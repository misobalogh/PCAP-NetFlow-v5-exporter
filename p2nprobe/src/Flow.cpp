#include <iostream>

#include "NetFlowV5Key.h"
#include "Flow.h"


Flow::Flow(std::shared_ptr<FlowKey> flow_key)
    : key(flow_key) {}

void Flow::update(uint64_t bytes) {
    if (auto netflow_key = std::dynamic_pointer_cast<NetFlowV5Key>(key)) {
        std::cout << "Updating flow with bytes" << bytes << " with key: " << netflow_key << "\n";
    }
}