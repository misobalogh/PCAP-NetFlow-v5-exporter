#include <chrono>
#include "NetFlowV5Key.h"

class Flow {
    public:
        FlowKey* key;
        uint64_t packet_count;
        uint64_t byte_count;
        std::chrono::time_point<std::chrono::system_clock> start_time;
        std::chrono::time_point<std::chrono::system_clock> last_update_time;

        Flow(FlowKey* flow_key)
            : key(flow_key), packet_count(0), byte_count(0) {
            start_time = std::chrono::system_clock::now();
            last_update_time = start_time;
        }

        Flow(const Flow& other)
            : key(other.key), packet_count(other.packet_count),
            byte_count(other.byte_count), start_time(other.start_time),
            last_update_time(other.last_update_time) {}

        ~Flow() {
            delete key; 
        }

        void update(uint64_t bytes);
};
