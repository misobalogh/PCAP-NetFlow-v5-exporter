#include <unordered_map>
#include <vector>
#include <chrono>
#include <string>

#include "FlowKey.h"
#include "Flow.h"
#include "Exporter.h"

class FlowManager {
    public:
        Exporter exporter;
        
        void add_or_update_flow(const FlowKey& key, uint64_t bytes);
        void cleanup_expired_flows(std::chrono::duration<double> timeout);
        void dispose();
    private:
        std::unordered_map<std::string, Flow> flow_map;
};
