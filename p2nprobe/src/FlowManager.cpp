#include <string>
#include <iostream>

#include "FlowManager.h"
#include "NetFlowV5Key.h"


FlowManager::~FlowManager() {
}

void FlowManager::add_or_update_flow(NetFlowV5record new_packet) {
    NetFlowV5Key key(new_packet);
    std::string concat_key = key.concatToString();
    auto flow = flow_map.find(concat_key);
    total_octets += new_packet.dOctets;

    if (flow != flow_map.end()) {
        // update existing one
        flow->second.update(new_packet.tcp_flags, new_packet.dOctets, new_packet.Last);
    }
    else {
        // create new
        new_packet.First = new_packet.Last;
        flow_map.emplace(concat_key, Flow(key, new_packet));
        auto flow = flow_map.find(concat_key);
    }
}

void FlowManager::dispose() {
    for (const auto& pair : flow_map) {
        exporter.send_flows(pair.second);
    }
    flow_map.clear();
}


void FlowManager::export_all() {
    if (flow_map.empty()) {
        std::cerr << "No flows to export." << std::endl;
        return;
    }
    int total_flows = 0;
    for (const auto& entry : flow_map) {
        exporter.send_flows(entry.second); 
        total_flows += 1;
    }
    std::cout << "Total flows: " << total_flows << std::endl;
}