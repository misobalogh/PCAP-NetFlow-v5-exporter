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
    Exporter exporter;

    void add_or_update_flow(NetFlowV5record record);

    void cleanup_expired_flows(std::chrono::duration<double> timeout);

    void dispose();

private:
    std::unordered_map<std::string, Flow> flow_map;
};

#endif // FLOW_MANAGER_H
