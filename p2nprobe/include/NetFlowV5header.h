////////////////////////////////////////////////////
// File: NetFlowV5header.h
// Pcap Netflow v5 Exporter
// Author: Michal Balogh, xbalog06
// Date: 14.10.2024
////////////////////////////////////////////////////

#ifndef NETFLOW_V5_HEADER_H
#define NETFLOW_V5_HEADER_H

#include <cstdint>


/**
 * @brief The NetFlowV5header struct represents the header of NetFlow v5 packet.
 *
 * Format described at:
 * https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html#wp1006108
 */
struct NetFlowV5header {
    uint16_t version;           // NetFlow export format version number, 5 for NetFlow version 5
    uint16_t count;             // Number of flows exported in this packet (1-30)
    uint32_t SysUptime;         // Current time in milliseconds since the export device booted
    uint32_t unix_secs;         // Current count of seconds since 0000 UTC 1970
    uint32_t unix_nsecs;        // Residual nanoseconds since 0000 UTC 1970
    uint32_t flow_sequence;     // Counter of total seen flows
    uint8_t engine_type;        // -
    uint8_t engine_id;          // -
    uint16_t sampling_interval; // -

    NetFlowV5header() : version(0), count(0), SysUptime(0), unix_secs(0), unix_nsecs(0),
                        flow_sequence(0), engine_type(0), engine_id(0), sampling_interval(0) {}
};

#endif // NETFLOW_V5_HEADER_H
