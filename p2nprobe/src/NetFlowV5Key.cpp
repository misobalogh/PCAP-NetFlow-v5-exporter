#include "NetFlowV5Key.h"

NetFlowV5Key::NetFlowV5Key(const std::string& src, const std::string& dst, uint16_t sp, uint16_t dp, uint8_t proto)
    : src_ip(src), dst_ip(dst), src_port(sp), dst_port(dp), protocol(proto) {}

size_t NetFlowV5Key::hash() const {
    return 0;
}

bool NetFlowV5Key::operator==(const FlowKey& other) const {
    return true;
}
