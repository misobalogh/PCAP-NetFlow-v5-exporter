#include "FlowManager.h"
#include <string>

void FlowManager::add_or_update_flow(const FlowKey& key, uint64_t bytes) {
    std::string concat_key = key.concatToString();
    auto flow = flow_map.find(concat_key);

    if (flow != flow_map.end()) {
        flow->second.update(bytes); 
    } else {
        flow_map[concat_key] = Flow(const_cast<FlowKey*>(&key));;
    }
}


void FlowManager::dispose() {
    for (const auto& pair : flow_map) {
        exporter.send_flows(pair.second);
    }
    flow_map.clear();
}
