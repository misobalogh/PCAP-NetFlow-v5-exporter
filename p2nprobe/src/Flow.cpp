////////////////////////////////////////////////////
// File: Flow.cpp
// Pcap Netflow v5 Exporter
// Author: Michal Balogh, xbalog06
// Date: 14.10.2024
////////////////////////////////////////////////////

#include <iostream>

#include "NetFlowV5Key.h"
#include "Flow.h"

/**
 * @brief Constructor of the flow.
 *
 * @param key Unqiue key for identifying the flow
 * @param record Record for holding agregated data from packets
 */
Flow::Flow(NetFlowV5Key key, NetFlowV5record record)
    : key(key), record(record) {}

/**
 * @brief Updates the flow. Called on flow when new packet is aggregated to the flow.
 * Updates number of packets in the record, cumulutes tcp flags, updates number of octets and the "Last" timestamp.
 *
 * @param tcp_flags TCP flags from aggregated packet
 * @param num_layer_3_bytes Number of bytes in the packet
 * @param timestamp Timestamp of the packet
 *
 * @return void
 */
void Flow::update(uint8_t tcp_flags, uint32_t num_layer_3_bytes, uint32_t timestamp) {
    record.dPkts += 1;
    record.tcp_flags |= tcp_flags;
    record.dOctets += num_layer_3_bytes;
    record.Last = timestamp;

}

/**
 * @brief Checks wheter the flow has exceeded active timeout
 *
 * @return true if is expired, false otherwise
 */
bool Flow::active_expired(uint32_t current_time, uint32_t active_timeout) const {
        return (current_time - record.First) >= active_timeout;
    }

/**
 * @brief Checks wheter the flow has exceeded inactive timeout
 *
 * @return true if is expired, false otherwise
 */
bool Flow::inactive_expired(uint32_t current_time, uint32_t inactive_timeout) const {
        return (current_time - record.Last) >= inactive_timeout;
    }