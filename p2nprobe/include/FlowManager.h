#ifndef FLOW_MANAGER_H
#define FLOW_MANAGER_H

#include <unordered_map>
#include <vector>
#include <chrono>
#include <string>
#include "FlowKey.h"
#include "Flow.h"
#include "ArgParser.h"
#include "Exporter.h"
#include "PcapReader.h"
#include "ErrorCodes.h"
#include "NetFlowV5Key.h"
#include "NetFlowV5record.h"

class FlowManager {
public:
    FlowManager(ArgParser programArguments);
    ~FlowManager();

    void add_or_update_flow(NetFlowV5record record);
    void export_expired();
    void export_full();
    void export_remaining();
    void dispose();

    int startProcessing();

private:
    uint32_t flow_count = 0;
    uint32_t flows_exported = 0;
    Exporter exporter;
    PcapReader reader;

    int active_timeout;
    int inactive_timeout;
    std::unordered_map<std::string, Flow> flow_map;
};

#endif // FLOW_MANAGER_H
