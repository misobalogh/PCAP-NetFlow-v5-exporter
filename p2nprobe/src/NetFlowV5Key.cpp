#include <functional>
#include <sstream>

#include "NetFlowV5Key.h"

NetFlowV5Key::NetFlowV5Key(const std::string& src, const std::string& dst, uint16_t sp, uint16_t dp, uint8_t proto, uint8_t tos)
    : src_ip(src), dst_ip(dst), src_port(sp), dst_port(dp), protocol(proto), type_of_service(tos) {}

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