#include <iostream>

#include "NetFlowV5Key.h"
#include "Flow.h"


Flow::Flow(NetFlowV5Key key, NetFlowV5record record)
    : key(key), record(record) {}

void Flow::update(uint64_t bytes) {
    std::cout << "Updating flow with bytes" << bytes << " with key: " << "\n";
}