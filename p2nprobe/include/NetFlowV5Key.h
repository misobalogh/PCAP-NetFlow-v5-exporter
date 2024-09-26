#ifndef NETFLOW_V5_FLOW_KEY_H
#define NETFLOW_V5_FLOW_KEY_H

#include <string>

#include "FlowKey.h"


// Unique key for a flow
// https://en.wikipedia.org/wiki/NetFlow#Network_flows
class NetFlowV5Key : public FlowKey {
    public:
        // ingress interface// 1.
        std::string src_ip; // 2.
        std::string dst_ip; // 3.
        uint8_t protocol;   // 4. 
        uint16_t src_port;  // 5.
        uint16_t dst_port;  // 6.
        // type of service  // 7.

        NetFlowV5Key(const std::string& src, const std::string& dst, uint16_t sp, uint16_t dp, uint8_t proto);

        // Comparison operator for comparing keys
        bool operator==(const FlowKey& other) const override;
        size_t hash() const override; // Hash function for hash tables
};

#endif // NETFLOW_V5_FLOW_KEY_H