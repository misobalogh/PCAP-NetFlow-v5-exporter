#include <vector>
#include <iostream>

#include "Flow.h"
#include "Exporter.h"

void Exporter::send_flows(const Flow& flow) {
    std::cout << "Sending single flow with details: " << std::endl;
}

void Exporter::send_flows(const std::vector<Flow>& flows) {
    for (const auto& flow : flows) {
        send_flows(flow);
    }
    std::cout << "Sending multiple flows." << std::endl;
}