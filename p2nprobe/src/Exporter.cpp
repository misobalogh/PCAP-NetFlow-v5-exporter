#include <vector>
#include "Flow.h"
#include <iostream>

void send_flows(const Flow& flow) {
    std::cout << "Sending single flow with details: " << std::endl;
}

void send_flows(const std::vector<Flow>& flows) {
    for (const auto& flow : flows) {
        send_flows(flow);
    }
    std::cout << "Sending multiple flows." << std::endl;
}