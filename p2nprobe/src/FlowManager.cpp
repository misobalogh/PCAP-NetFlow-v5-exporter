#include <string>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <iostream>
#include <sys/time.h> 
#include <cstring>


#include "FlowManager.h"
#include "NetFlowV5Key.h"

FlowManager::FlowManager(ArgParser programArguments)
    : flow_count(0),
    flows_exported(0),
    exporter(programArguments.getHost(), programArguments.getPort()),
    reader(programArguments.getPCAPFilePath()),
    active_timeout(programArguments.getActiveTimeout()),
    inactive_timeout(programArguments.getInactiveTimeout()),
    time_start_set(false),
    time_start(0),
    time_end(0)
{
    if (!reader.open()) {
        dispose();
        ExitWith(ErrorCode::FILE_OPEN_ERROR);
    }
}

FlowManager::~FlowManager() {
    dispose();
}

void FlowManager::dispose() {
    flow_map.clear();
    cached_flows.clear();
    reader.close();
}

void FlowManager::add_or_update_flow(NetFlowV5record new_packet) {
    if (!time_start_set) {
        time_start_set = true;
        time_start = new_packet.Last;
    }

    time_end = new_packet.Last;

    NetFlowV5Key key(new_packet);
    std::string concat_key = key.concatToString();
    auto flow = flow_map.find(concat_key);

    if (flow != flow_map.end() && concat_key == flow->first) {
        // update existing one
        flow->second.update(new_packet.tcp_flags, new_packet.dOctets, new_packet.Last);
    }
    else {
        // create new
        flow_count++;
        new_packet.First = new_packet.Last;
        flow_map.emplace(concat_key, Flow(key, new_packet));
        flow = flow_map.find(concat_key);
    }
}


void FlowManager::export_remaining() {
    if (flow_map.empty()) {
        return;
    }

    for (const auto& entry : flow_map) {
        cached_flows.push_back(entry.second);
        if (cached_flows.size() == MAX_CACHED_FLOWS) {
            export_cached();
        }
    }

    export_cached();

    std::cout << "Total flows: " << flow_count << std::endl;
    std::cout << "Exported: " << flows_exported << std::endl;
}

int FlowManager::startProcessing() {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int result;

    while ((result = pcap_next_ex(reader.handle, &header, &packet)) > 0) {
        NetFlowV5record record;
        bool packetProcessed = reader.processPacket(header, packet, record);
        if (packetProcessed) {
            add_or_update_flow(record);
        }
        uint32_t packet_timestamp = header->ts.tv_sec;
        // uint32_t timestamp_ms = header->ts.tv_sec * 1000 + header->ts.tv_usec / 1000;

        cache_expired(packet_timestamp);
        if (cached_flows.size() == MAX_CACHED_FLOWS) {
            export_cached();
        }
    }

    return result;
}

// https://stackoverflow.com/a/1604632
void FlowManager::cache_expired(uint32_t current_time) {
    for (auto entry = flow_map.begin(); entry != flow_map.end(); ) {
        if (entry->second.active_expired(current_time, active_timeout) ||
            entry->second.inactive_expired(current_time, inactive_timeout)) {
            cached_flows.push_back(entry->second);
            entry = flow_map.erase(entry);    
            if (cached_flows.size() == MAX_CACHED_FLOWS) {
                break;
            }
        }
        else {
            entry++;
        }
    }
}

void FlowManager::export_cached() {
    if (cached_flows.size() <= 0) {
        return;
    }
    
    flows_exported += cached_flows.size();

    exporter.export_flows(cached_flows, time_start, time_end);
    cached_flows.clear();
}   