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
    FlowManager(const std::string& collector_ip, int collector_port, int activeTimeout, int inactiveTimeout)
        : exporter(collector_ip, collector_port), active_timeout(activeTimeout), inactive_timeout(inactiveTimeout) {} 
    ~FlowManager();

    void add_or_update_flow(NetFlowV5record record);
    void export_expired();
    void export_full();
    void export_remaining();
    void dispose();


private:
    uint32_t flow_count = 0;
    uint32_t flows_exported = 0;
    Exporter exporter;
    int active_timeout;
    int inactive_timeout;
    std::unordered_map<std::string, Flow> flow_map;
};

#endif // FLOW_MANAGER_H
