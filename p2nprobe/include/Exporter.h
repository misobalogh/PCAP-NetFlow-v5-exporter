#ifndef EXPORTER_H
#define EXPORTER_H

#include <vector>
#include <iostream>
#include <cstring> 
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h> 

#include "Flow.h"

const size_t DATAGRAM_SIZE = sizeof(NetFlowV5header) + sizeof(NetFlowV5record);

class Exporter {
public:
    Exporter(const std::string& collector_ip, int collector_port);
    ~Exporter();

    void send_flows(const std::vector<Flow>& flows);
    void send_flows(const Flow& flow);

private:
    void format(const Flow& flow, uint8_t* buffer, size_t& length);
    int create_socket();
    void close_socket();

    int sock;
    struct sockaddr_in server_addr;
};

#endif // EXPORTER_H
