#ifndef FLOW_MANAGER_H
#define FLOW_MANAGER_H

#include <unordered_map>
#include <vector>
#include <chrono>
#include <string>
#include "FlowKey.h"
#include "Flow.h"
#include "Exporter.h"

class FlowManager {
public:
    FlowManager(const std::string& collector_ip, int collector_port)
        : exporter(collector_ip, collector_port) {} 
    ~FlowManager();

    void add_or_update_flow(NetFlowV5record record);
    void cleanup_expired_flows(std::chrono::duration<double> timeout);
    void export_all();
    void dispose();

private:
    uint32_t total_octets = 0;
    std::unordered_map<std::string, Flow> flow_map;
    Exporter exporter;
};

#endif // FLOW_MANAGER_H
