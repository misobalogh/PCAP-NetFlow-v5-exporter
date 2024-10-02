#ifndef FLOW_H
#define FLOW_H

#include <chrono>
#include <memory>

#include "NetFlowV5Key.h"
#include "NetFlowV5datagram.h"

class Flow {
public:
    NetFlowV5Key key;
    NetFlowV5record record;
    NetFlowV5header header;
    
    Flow(NetFlowV5Key key, NetFlowV5record record);
    ~Flow() = default;
    
    Flow(const Flow& other) = default;
    Flow& operator=(const Flow& other) = default;  

    void update(uint8_t tcp_flags, uint32_t num_layer_3_bytes, uint32_t timestamp);
    bool active_expired(uint32_t current_time, uint32_t active_timeout) const;
    bool inactive_expired(uint32_t current_time, uint32_t inactive_timeout) const;

};


#endif // FLOW_H