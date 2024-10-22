////////////////////////////////////////////////////
// File: NetFlowV5Key.h
// Pcap Netflow v5 Exporter
// Author: Michal Balogh, xbalog06
// Date: 14.10.2024
////////////////////////////////////////////////////

#ifndef NETFLOW_V5_FLOW_KEY_H
#define NETFLOW_V5_FLOW_KEY_H

#include <string>

#include "FlowKey.h"
#include "NetFlowV5record.h"



/**
 * @brief Unique key for NetFlow v5 flow described at:
 * https://en.wikipedia.org/wiki/NetFlow#Network_flows
 *
 * Not all 7 parts of the key descriped are used.
 * Key is composed only from these 5:
 * 1. Source IP address
 * 2. Destination IP address
 * 3. Protocol
 * 4. Source port
 * 5. Destination port
 */
class NetFlowV5Key : public FlowKey {
    public:                         // coresponding parts on wiki
        std::string src_ip;         // 2. 
        std::string dst_ip;         // 3.
        uint8_t protocol;           // 4. 
        uint16_t src_port;          // 5.
        uint16_t dst_port;          // 6.

        NetFlowV5Key(NetFlowV5record record);

        // Comparison operator for comparing keys in case of colision
        bool operator==(const FlowKey& other) const override;
        std::string concatToString() const override; // Concat key parts to one string so that it can be used as key in hash table
};

#endif // NETFLOW_V5_FLOW_KEY_H