#include <vector>

#include "Flow.h"

class Exporter {
public:
    void send_flows(const std::vector<Flow>& flows);
    void send_flows(const Flow& flows);
private:
    void format(const Flow& flow);
};
