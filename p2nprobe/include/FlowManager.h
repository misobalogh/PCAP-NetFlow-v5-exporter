#ifndef FLOW_MANAGER_H
#define FLOW_MANAGER_H

#include <list>
#include <unordered_map>
#include <vector>
#include <string>
#include "Flow.h"
#include "ArgParser.h"
#include "Exporter.h"
#include "PcapReader.h"
#include "NetFlowV5Key.h"
#include "NetFlowV5record.h"

constexpr unsigned int MAX_CACHED_FLOWS = 30;

class FlowManager {
public:
    using FlowList = std::list<Flow>;

    FlowManager(ArgParser programArguments);
    ~FlowManager();

    void add_or_update_flow(NetFlowV5record new_record);

    void cache_expired(uint32_t current_time);
    void export_cached();
    void export_remaining();
    void dispose();
    int startProcessing();

private:
    uint32_t flow_count = 0;
    uint32_t flows_exported = 0;
    Exporter exporter;
    PcapReader reader;

    int active_timeout_ms;
    int inactive_timeout_ms;

    bool time_start_set;
    uint32_t time_start;
    uint32_t time_end;

    // Vector to store flows waiting to be exported
    std::vector<Flow> cached_flows;

    // Double linked list to store flows in the order of arrival and fast addition or removal of flows
    FlowList flow_list;

    // Hash table for finding fast flows based on their key, pointing to the list entries in double linked list
    std::unordered_map<std::string, FlowList::iterator> flow_map;
};

#endif // FLOW_MANAGER_H
