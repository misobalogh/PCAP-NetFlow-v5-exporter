#ifndef EXPORTER_H
#define EXPORTER_H

#include <vector>
#include <iostream>
#include <cstring> 
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h> 

#include "Flow.h"

constexpr uint16_t VERSION_5 = 5;

class Exporter {
public:
    Exporter(const std::string& collector_ip, int collector_port);
    ~Exporter();

    void export_flows(const std::vector<Flow>& flows, uint32_t time_start, uint32_t time_end);

private:
    int create_socket();
    void close_socket();

    void send(uint8_t* buffer, size_t buffer_size);
    void format_header(uint8_t* buffer, uint16_t flow_count, uint32_t time_start, uint32_t time_end);
    void format_record(NetFlowV5record record, uint8_t* buffer, size_t &offset, uint32_t time_start);

    uint32_t flow_sequence;
    int sock;
    struct sockaddr_in server_addr;
};

#endif // EXPORTER_H
