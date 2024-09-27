#include <string>
#include <iostream>

#include "FlowManager.h"
#include "NetFlowV5Key.h"

void FlowManager::add_or_update_flow(const FlowKey& key, uint64_t bytes) {
    std::string concat_key = key.concatToString();
    auto flow = flow_map.find(concat_key);

    if (flow != flow_map.end()) {
        flow->second.update(bytes);
    }
    else {
        flow_map.emplace(concat_key, Flow(std::make_shared<NetFlowV5Key>(dynamic_cast<const NetFlowV5Key&>(key))));
        auto flow = flow_map.find(concat_key);
        std::cout << "creating new flow with key: " << flow->second.key << "\n";
    }
}

void FlowManager::dispose() {
    for (const auto& pair : flow_map) {
        exporter.send_flows(pair.second);
    }
    flow_map.clear();
}
