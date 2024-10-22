////////////////////////////////////////////////////
// File: NetFlowV5Key.cpp
// Pcap Netflow v5 Exporter
// Author: Michal Balogh, xbalog06
// Date: 14.10.2024
////////////////////////////////////////////////////

#include <functional>
#include <sstream>

#include "NetFlowV5Key.h"

/**
 * @brief Constructor for NetFlowV5Key. NetFlowV5Key is constructed from data in NetFlowV5record.
 * 
 */
NetFlowV5Key::NetFlowV5Key(NetFlowV5record record) {
    src_ip = record.srcaddr;
    dst_ip = record.dstaddr;     
    protocol = record.prot;    
    src_port = record.srcport;   
    dst_port = record.dstport;   
}

/**
 * @brief Concatenates key parts to one string so that it can be used as key in hash table.
 * 
 * @return std::string 
 */
std::string NetFlowV5Key::concatToString() const {
    std::ostringstream oss;
    oss << src_ip << ":"
        << dst_ip << ":"
        << src_port << ":"
        << dst_port << ":"
        << static_cast<int>(protocol);
    return oss.str();
}

/**
 * @brief Comparison operator for comparing keys in case of colision.
 * 
 * @param other 
 * @return true if keys are equal,
 * @return false otherwise
 */
bool NetFlowV5Key::operator==(const FlowKey& other) const {
    const NetFlowV5Key* otherKey = dynamic_cast<const NetFlowV5Key*>(&other);

    if (otherKey == nullptr) {
        return false;
    }

    return (src_ip == otherKey->src_ip &&
            dst_ip == otherKey->dst_ip &&
            src_port == otherKey->src_port &&
            dst_port == otherKey->dst_port &&
            protocol == otherKey->protocol);
}