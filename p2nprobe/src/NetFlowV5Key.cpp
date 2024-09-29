#include <functional>
#include <sstream>

#include "NetFlowV5Key.h"

NetFlowV5Key::NetFlowV5Key(NetFlowV5record record) {
    ingress_interface = record.input;
    src_ip = record.srcaddr;
    dst_ip = record.dstaddr;     
    protocol = record.prot;    
    src_port = record.srcport;   
    dst_port = record.dstport;   
    type_of_service = record.tos;
}

std::string NetFlowV5Key::concatToString() const {
    std::ostringstream oss;
    oss << src_ip << ":"
        << dst_ip << ":"
        << src_port << ":"
        << dst_port << ":"
        << static_cast<int>(protocol) << ":"
        << static_cast<int>(type_of_service);
    return oss.str();
}

bool NetFlowV5Key::operator==(const FlowKey& other) const {
    const NetFlowV5Key* otherKey = dynamic_cast<const NetFlowV5Key*>(&other);

    if (otherKey == nullptr) {
        return false;
    }

    return (src_ip == otherKey->src_ip &&
            dst_ip == otherKey->dst_ip &&
            src_port == otherKey->src_port &&
            dst_port == otherKey->dst_port &&
            protocol == otherKey->protocol &&
            type_of_service == otherKey->type_of_service);
}