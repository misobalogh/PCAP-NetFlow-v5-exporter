#include <string>
#include <iostream>

#include "FlowManager.h"
#include "NetFlowV5Key.h"

void FlowManager::add_or_update_flow(NetFlowV5record record) {
    NetFlowV5Key key(record);
    std::string concat_key = key.concatToString();
    auto flow = flow_map.find(concat_key);

    if (flow != flow_map.end()) {
        flow->second.update(32);
    }
    else {
        flow_map.emplace(concat_key, Flow(key, record));
        auto flow = flow_map.find(concat_key);
        std::cout << "creating new flow with key: " << "\n";
    }
}

void FlowManager::dispose() {
    for (const auto& pair : flow_map) {
        exporter.send_flows(pair.second);
    }
    flow_map.clear();
}
