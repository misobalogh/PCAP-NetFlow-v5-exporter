////////////////////////////////////////////////////
// File: NetFlowV5record.h
// Pcap Netflow v5 Exporter
// Author: Michal Balogh, xbalog06
// Date: 14.10.2024
////////////////////////////////////////////////////

#ifndef NETFLOW_V5_RECORD_H
#define NETFLOW_V5_RECORD_H

#include <cstdint>

/**
 * @brief The NetFlowV5record struct represents the record of NetFlow v5 packet.
 * Format described at:
 * https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html#wp1006186
 */
struct NetFlowV5record {
    uint32_t srcaddr; // Source IP address
    uint32_t dstaddr; // Destination IP address
    uint32_t nexthop; // IP address of next hop router
    uint16_t input;     // SNMP index of input interface
    uint16_t output;    // SNMP index of output interface
    uint32_t dPkts;     // Packets in the flow
    uint32_t dOctets;   // Total number of Layer 3 bytes in the packets of the flow 
    uint32_t First;     // SysUptime at start of flow 
    uint32_t Last;      // SysUptime at the time the last packet of the flow was received 
    uint16_t srcport;   // Source port
    uint16_t dstport;   // Destination port
    uint8_t pad1;       // -
    uint8_t tcp_flags;  // Tcp Flags
    uint8_t prot;       // 6 for TCP
    uint8_t tos;        // -
    uint16_t src_as;    // -
    uint16_t dst_as;    // -
    uint8_t src_mask;   // -
    uint8_t dst_mask;   // -
    uint16_t pad2;      // -

    NetFlowV5record() : srcaddr(0), dstaddr(0), nexthop(0), input(0), output(0), dPkts(0),
                        dOctets(0), First(0), Last(0), srcport(0), dstport(0), pad1(0),
                        tcp_flags(0), prot(0), tos(0), src_as(0), dst_as(0), src_mask(0),
                        dst_mask(0), pad2(0) {}
};

#endif // NETFLOW_V5_RECORD_H
