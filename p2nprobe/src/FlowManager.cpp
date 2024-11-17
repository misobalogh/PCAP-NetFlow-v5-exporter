////////////////////////////////////////////////////
// File: FlowManager.cpp
// Pcap Netflow v5 Exporter
// Author: Michal Balogh, xbalog06
// Date: 14.10.2024
////////////////////////////////////////////////////


#include <string>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <iostream>
#include <sys/time.h> 
#include <cstring>

#include "FlowManager.h"
#include "ErrorCodes.h"

/**
 * @brief Constructor for the class. Loads program arguments, initializes reader and tries to open the pcap file.
 *
 * @param programArguments Program arguments set by user.
 */
FlowManager::FlowManager(ArgParser programArguments)
    : flow_count(0),
    flows_exported(0),
    exporter(programArguments.getHost(), programArguments.getPort()),
    reader(programArguments.getPCAPFilePath()),
    active_timeout_ms(programArguments.getActiveTimeout() * 1000),
    inactive_timeout_ms(programArguments.getInactiveTimeout() * 1000),
    time_start_set(false),
    time_start(0),
    time_end(0)
{
    if (!reader.open()) {
        dispose();
        ExitWith(ErrorCode::FILE_OPEN_ERROR);
    }
}

/**
 * @brief Destructor of the class. Cleans up resources.
 */
FlowManager::~FlowManager() {
    dispose();
}

/**
 * @brief Cleans up resources and frees memmory.
 */
void FlowManager::dispose() {
    flow_map.clear();
    cached_flows.clear();
    reader.close();
}

/**
 * @brief Get current time in miliseconds.
 *
 * @return Current time in miliseconds.
 */
uint32_t FlowManager::getCurrentTime() {
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    uint32_t duration = tv.tv_sec * 1000LL + (tv.tv_usec / 1000);
    return duration;
}

/**
 * @brief Tries to find a flow by comparing their keys, if the flow is found, updates it.
 * If not, new flow is created.
 *
 * @param new_record Processed packet from pcap file into a NetFlowV5record struct.
 *
 * @return void
 */
void FlowManager::add_or_update_flow(NetFlowV5record new_record) {
    if (!time_start_set) { // Set the start time of the device
            time_start = getCurrentTime();
            time_start_set = true;
    }
    time_end = new_record.Last; // Update the end time with current timestamp

    // Key for comparing the flows.
    NetFlowV5Key key(new_record);
    std::string concat_key = key.concatToString();

    auto it = flow_map.find(concat_key); // Get the pointer to the flow by searching in hash map
    if (it != flow_map.end() && concat_key == it->first) {
        // Flow exists, update the existing flow in the list
        it->second->update(new_record.tcp_flags, new_record.dOctets, new_record.Last); // it->seconds points to the entry in the list
    }
    else {
        // New flow, add it to the list and map
        flow_count++;
        new_record.First = new_record.Last;
        flow_list.push_back(Flow(key, new_record));  
        FlowList::iterator list_it = --flow_list.end();  
        flow_map[concat_key] = list_it;  
    }
}

/**
 * @brief Exports flow that have not expired, but the pcap file ended, so they should be all sent to the collector
 */
void FlowManager::export_remaining() {
    if (flow_list.empty()) {
        return;
    }

    // Export all flows by aggregating them into buffers of size of maximum of 30 flows. 
    for (const auto& flow : flow_list) {
        cached_flows.push_back(flow); 
        if (cached_flows.size() == MAX_CACHED_FLOWS) {
            export_cached(); // Export 30 at once
        }
    }

    export_cached();  // Export remaining
}

/**
 * @brief Starts reading packets from pcap file, processes them and update flows if needed.
 *
 * @return -1 if error occurs while reading packets, -2 when the reader reaches end of the pcap file.
 */
int FlowManager::startProcessing() {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int result;

    // Result is -1 if error occured while reading packet, -2 when it reaches the end of pcap file.
    while ((result = pcap_next_ex(reader.handle, &header, &packet)) > 0) {
        NetFlowV5record record;
        bool packetProcessed = reader.processPacket(header, packet, record);
        if (packetProcessed) {
            add_or_update_flow(record);
        }

        uint32_t timestamp_ms = header->ts.tv_sec * 1000 + header->ts.tv_usec / 1000; // convert to miliseconds

        // Cache expired flows into buffer
        cache_expired(timestamp_ms);
        if (cached_flows.size() == MAX_CACHED_FLOWS) {
            export_cached(); // Buffer is full -> export it
        }
    }

    return result;
}

/**
 * @brief Iterates over current flows and check wheter the flows are expired. Expired flows are cached.
 * Iterating through list in cpp while removing some entries inspired from:
 * https://stackoverflow.com/a/1604632
 *
 * @param current_time Time that will be the packes compared to.
 */
void FlowManager::cache_expired(uint32_t current_time) {
    for (auto it = flow_list.begin(); it != flow_list.end(); ) {
        // If flow exceeds active or inactive timeout, cache it.
        if (it->active_expired(current_time, active_timeout_ms) ||
            it->inactive_expired(current_time, inactive_timeout_ms)) {
            printf("Flow expired: %s\n", it->key.concatToString().c_str());
            // Cache the flow
            cached_flows.push_back(*it);

            flow_map.erase(it->key.concatToString());
            it = flow_list.erase(it);       

            if (cached_flows.size() == MAX_CACHED_FLOWS) { // Buffer is full
                break;  
            }
        }
        else {
            ++it;
        }
    }
}

/**
 * @brief Export flows with the Exporter object and updates number of flows exported.
 */
void FlowManager::export_cached() {
    if (cached_flows.empty()) {
        return;
    }
    
    flows_exported += cached_flows.size();

    exporter.export_flows(cached_flows, time_start, time_end);
    cached_flows.clear();
}   