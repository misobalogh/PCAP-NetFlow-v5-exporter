#ifndef EXPORTER_H
#define EXPORTER_H

#include <vector>
#include <iostream>
#include <cstring> 
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h> 

#include "Flow.h"

constexpr size_t DATAGRAM_SIZE = sizeof(NetFlowV5header) + sizeof(NetFlowV5record);
constexpr uint16_t VERSION_5 = 5;

class Exporter {
public:
    Exporter(const std::string& collector_ip, int collector_port);
    ~Exporter();

    void send_flows(const std::vector<Flow>& flows, uint32_t time_start, uint32_t time_end);
    void send_flow(const Flow& flow);

private:
    int create_socket();
    void close_socket();

    void format_header(uint8_t* buffer, uint16_t flow_count, uint32_t time_start, uint32_t time_end);
    void format_record(NetFlowV5record record, uint8_t* buffer, size_t& length, size_t offset);

    uint32_t flow_sequence;
    int sock;
    struct sockaddr_in server_addr;
};

#endif // EXPORTER_H
