#include <iostream>

#include "NetFlowV5Key.h"
#include "Flow.h"


Flow::Flow(NetFlowV5Key key, NetFlowV5record record)
    : key(key), record(record) {}

void Flow::update(uint8_t tcp_flags, uint32_t num_layer_3_bytes, uint32_t timestamp)  {
    record.dPkts += 1;
    record.tcp_flags |= tcp_flags;
    record.dOctets += num_layer_3_bytes;
    record.Last = timestamp;

}