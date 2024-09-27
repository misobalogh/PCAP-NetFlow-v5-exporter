#ifndef FLOW_H
#define FLOW_H

#include <chrono>
#include <memory>

#include "FlowKey.h"

class Flow {
public:
    std::shared_ptr<FlowKey> key;  
    
    Flow(std::shared_ptr<FlowKey> flow_key); 
    ~Flow() = default; 

    Flow(const Flow& other) = default; 
    Flow& operator=(const Flow& other) = default;  

    void update(uint64_t bytes);
};


#endif // FLOW_H