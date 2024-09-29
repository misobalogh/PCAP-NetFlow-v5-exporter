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

    void update(uint64_t bytes);
};


#endif // FLOW_H