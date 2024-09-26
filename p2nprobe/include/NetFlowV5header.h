#ifndef NETFLOW_V5_HEADER_H
#define NETFLOW_V5_HEADER_H

#include <cstdint>


// Format of NetFlow v5 header described at:
// https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html#wp1006108
struct NetFlowV5header {
    uint16_t version;
    uint16_t count;
    uint32_t SysUptime;
    uint32_t unix_secs;
    uint32_t unix_nsecs;
    uint32_t flow_sequence;
    uint8_t engine_type;
    uint8_t engine_id;
    uint16_t sampling_interval;

    NetFlowV5header() : version(0), count(0), SysUptime(0), unix_secs(0), unix_nsecs(0),
                        flow_sequence(0), engine_type(0), engine_id(0), sampling_interval(0) {}
};

#endif // NETFLOW_V5_HEADER_H
