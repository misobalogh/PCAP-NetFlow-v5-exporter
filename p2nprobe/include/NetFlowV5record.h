#ifndef NETFLOW_V5_RECORD_H
#define NETFLOW_V5_RECORD_H

#include <cstdint>

// Format of NetFlow v5 record described at:
// https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html#wp1006186
struct NetFlowV5record {
    uint32_t srcaddr;
    uint32_t dstaddr;
    uint32_t nexthop;
    uint16_t input;
    uint16_t output;
    uint32_t dPkts;
    uint32_t dOctets;
    uint32_t First;
    uint32_t Last;
    uint16_t srcport;
    uint16_t dstport;
    uint8_t pad1;
    uint8_t tcp_flags;
    uint8_t prot;
    uint8_t tos;
    uint16_t src_as;
    uint16_t dst_as;
    uint8_t src_mask;
    uint8_t dst_mask;
    uint16_t pad2;

    NetFlowV5record() : srcaddr(0), dstaddr(0), nexthop(0), input(0), output(0), dPkts(0),
                        dOctets(0), First(0), Last(0), srcport(0), dstport(0), pad1(0),
                        tcp_flags(0), prot(0), tos(0), src_as(0), dst_as(0), src_mask(0),
                        dst_mask(0), pad2(0) {}
};

#endif // NETFLOW_V5_RECORD_H
