#ifndef NETFLOW_V5_FLOW_KEY_H
#define NETFLOW_V5_FLOW_KEY_H

#include <string>

#include "FlowKey.h"


// Unique key for a flow
// https://en.wikipedia.org/wiki/NetFlow#Network_flows
class NetFlowV5Key : public FlowKey {
    public:
        // ingress interface    // 1.
        std::string src_ip;     // 2.
        std::string dst_ip;     // 3.
        uint8_t protocol;       // 4. 
        uint16_t src_port;      // 5.
        uint16_t dst_port;      // 6.
        uint8_t type_of_service;// 7.

        NetFlowV5Key(const std::string& src, const std::string& dst, uint16_t sp, uint16_t dp, uint8_t proto, uint8_t tos);

        // Comparison operator for comparing keys in case of colision
        bool operator==(const FlowKey& other) const override;
        std::string concatToString() const override; // Concat key parts to one string so that it can be used as key in hash table
};

#endif // NETFLOW_V5_FLOW_KEY_H