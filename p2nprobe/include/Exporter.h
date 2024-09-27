#ifndef EXPORTER_H
#define EXPORTER_H

#include <vector>

#include "Flow.h"

class Exporter {
public:
    void send_flows(const std::vector<Flow>& flows);
    void send_flows(const Flow& flow);
private:
    void format(const Flow& flow);
};

#endif // EXPORTER_H