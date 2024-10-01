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
        : exporter(programArguments.getHost(), programArguments.getPort()),
    reader(programArguments.getPCAPFilePath()),
    active_timeout(programArguments.getActiveTimeout()),
    inactive_timeout(programArguments.getInactiveTimeout()) {
    if (!reader.open()) {
        ExitWith(ErrorCode::FILE_OPEN_ERROR);
    }

}

FlowManager::~FlowManager() {
    dispose();
}

void FlowManager::add_or_update_flow(NetFlowV5record new_packet) {
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

    // todo: check for expiration(if expired -> export_expired())
    // if (flow->second.is_expired()) {
    //     exporter.send_flow()
    // }
}

void FlowManager::dispose() {
    reader.close();
    flow_map.clear();
}


void FlowManager::export_remaining() {
    if (flow_map.empty()) {
        std::cerr << "No flows to export." << std::endl;
        return;
    }

    for (const auto& entry : flow_map) {
        exporter.send_flows(entry.second); 
        flows_exported++;
    }
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
    }

    return result;
}