#ifndef NETFLOW_V5_DATAGRAM_H
#define NETFLOW_V5_DATAGRAM_H

#include <array>

#include "NetFlowV5header.h"
#include "NetFlowV5record.h"

// https://www.cisco.com/en/US/docs/ios/12_3t/netflow/command/reference/nfl_a1gt_ps5207_TSD_Products_Command_Reference_Chapter.html#wp1185572
// "The number of records stored in the datagram is variable between 1 and 30 for Version 5."
#define MAX_RECORDS 30

class NetFlowV5datagram {
public:
    NetFlowV5header header;
    std::array<NetFlowV5record, MAX_RECORDS> records;
};

#endif // NETFLOW_V5_DATAGRAM_H