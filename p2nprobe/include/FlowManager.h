////////////////////////////////////////////////////
// File: FlowManager.h
// Pcap Netflow v5 Exporter
// Author: Michal Balogh, xbalog06
// Date: 14.10.2024
////////////////////////////////////////////////////

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

// Maxed flows that can be cached is set to 30 by specification.
// https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html#wp1006108
constexpr unsigned int MAX_CACHED_FLOWS = 30;

/**
 * @brief Main class that gets packets from the PcapReader, processes the packets, and exports them using Exporter.
 */
class FlowManager {
public:
    // List of flows for buffering them in order they were read from the pcap file.
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
    uint32_t flow_count = 0; // current number of flows
    uint32_t flows_exported = 0; // total number of flows exported from device start
    Exporter exporter;  // Exporter object for exporting expired flows to collector
    PcapReader reader;  // PcapReader object for reading packets from pcap file. 

    int active_timeout_ms; // Active timeout expires, while there are still packets flowing to the flow, but the time exceeds the set timeout
    int inactive_timeout_ms; // Inactive timeout expires, when there is too much time between reciving next packet to the flow

    bool time_start_set; // Wheter the start time was already set
    uint32_t time_start; // Time of start of the device
    uint32_t time_end; // Last time of the divice

    // Vector to store flows waiting to be exported
    std::vector<Flow> cached_flows;

    // Double linked list to store flows in the order of arrival and fast addition or removal of flows
    FlowList flow_list;

    // Hash table for finding flows fast based on their key, pointing to the list entries in double linked list
    std::unordered_map<std::string, FlowList::iterator> flow_map;

    uint32_t getCurrentTime();
};

#endif // FLOW_MANAGER_H
