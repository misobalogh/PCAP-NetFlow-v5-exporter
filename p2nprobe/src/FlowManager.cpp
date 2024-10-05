#include <string>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <iostream>
#include <sys/time.h> 
#include <cstring>

#include "FlowManager.h"
#include "ErrorCodes.h"

FlowManager::FlowManager(ArgParser programArguments)
    : flow_count(0),
    flows_exported(0),
    exporter(programArguments.getHost(), programArguments.getPort()),
    reader(programArguments.getPCAPFilePath()),
    active_timeout_ms(programArguments.getActiveTimeout() * 1000),
    inactive_timeout_ms(programArguments.getInactiveTimeout() * 1000),
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

void FlowManager::add_or_update_flow(NetFlowV5record new_record) {
    if (!time_start_set) {
        time_start_set = true;
        time_start = new_record.Last;
    }
    time_end = new_record.Last;

    NetFlowV5Key key(new_record);
    std::string concat_key = key.concatToString();

    auto it = flow_map.find(concat_key);
    if (it != flow_map.end() && concat_key == it->first) {
        // Flow exists, update the existing flow in the list
        it->second->update(new_record.tcp_flags, new_record.dOctets, new_record.Last);
    } else {
        // New flow, add it to the list and map
        flow_count++;
        new_record.First = new_record.Last;
        flow_list.push_back(Flow(key, new_record));  
        FlowList::iterator list_it = --flow_list.end();  
        flow_map[concat_key] = list_it;  
    }
}

void FlowManager::export_remaining() {
    if (flow_list.empty()) {
        return;
    }

    for (const auto& flow : flow_list) {
        cached_flows.push_back(flow); 
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

        uint32_t timestamp_ms = header->ts.tv_sec * 1000 + header->ts.tv_usec / 1000;

        cache_expired(timestamp_ms);
        if (cached_flows.size() == MAX_CACHED_FLOWS) {
            export_cached();
        }
    }

    return result;
}

// https://stackoverflow.com/a/1604632
void FlowManager::cache_expired(uint32_t current_time) {
    for (auto it = flow_list.begin(); it != flow_list.end(); ) {
        if (it->active_expired(current_time, active_timeout_ms) ||
            it->inactive_expired(current_time, inactive_timeout_ms)) {
            
            cached_flows.push_back(*it);    

            flow_map.erase(it->key.concatToString());  
            it = flow_list.erase(it);       
            
            if (cached_flows.size() == MAX_CACHED_FLOWS) {
                break;  
            }
        }
        else {
            ++it;
        }
    }
}


void FlowManager::export_cached() {
    if (cached_flows.empty()) {
        return;
    }
    
    flows_exported += cached_flows.size();

    exporter.export_flows(cached_flows, time_start, time_end);
    cached_flows.clear();
}   