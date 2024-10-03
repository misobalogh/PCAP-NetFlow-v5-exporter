#include "Exporter.h"

Exporter::Exporter(const std::string& collector_ip, int collector_port) {
    sock = create_socket();

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_port = htons(collector_port);
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(collector_ip.c_str());

    flow_sequence = 0;
}

Exporter::~Exporter() {
    close_socket();
}

int Exporter::create_socket() {
    int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0) {
        std::cerr << "Error creating socket." << std::endl;
        exit(EXIT_FAILURE);
    }
    return sock_fd;
}

void Exporter::close_socket() {
    if (sock >= 0) {
        close(sock);
    }
}

void Exporter::send_flows(const std::vector<Flow>& flows, uint32_t time_start, uint32_t time_end) {

    uint8_t buffer[DATAGRAM_SIZE];
    format_header(buffer, flows.size(), time_start, time_end);

    size_t length = 0;
    size_t offset = sizeof(NetFlowV5header);
    for (const auto& flow : flows) {
        format_record(flow.record, buffer, length, offset);
    }
    // send_flow(flows);
    // send_flows(flow);
}

void Exporter::send_flow(const Flow& flow) {
    flow_sequence += 1;
    uint8_t buffer[DATAGRAM_SIZE];
    size_t length = 0;

    if (length == 0) {
        return;
    }

    ssize_t sent = sendto(sock, buffer, length, 0, (struct sockaddr*)&server_addr, sizeof(server_addr));
    if (sent < 0) {
        std::cerr << "Error occurred when sending flow. Program continues. Flow seq: " << flow_sequence << std::endl;
    }
}

void Exporter::format_header(uint8_t* buffer, uint16_t flow_count, uint32_t time_start, uint32_t time_end) {
    NetFlowV5header header;
    header.version = htons(VERSION_5);
    header.count = htons(flow_count); 
    header.SysUptime = htonl(time_end-time_start);
    header.unix_secs = htonl(time(nullptr));
    header.unix_nsecs = htonl(0); 
    header.flow_sequence = htonl(flow_sequence);
    header.engine_type = 0;
    header.engine_id = 0; 
    header.sampling_interval = 0; 

    memcpy(buffer, &header, sizeof(NetFlowV5header));

    size_t offset = sizeof(NetFlowV5header);
}

void Exporter::format_record(NetFlowV5record record, uint8_t* buffer, size_t& length, size_t offset) {

    record.srcaddr = htonl(record.srcaddr); 
    record.dstaddr = htonl(record.dstaddr);
    record.nexthop = htonl(record.nexthop);
    record.input = htons(record.input);
    record.output = htons(record.output);
    record.dPkts = htonl(record.dPkts);
    record.dOctets = htonl(record.dOctets);
    record.First = htonl(record.First);
    record.Last = htonl(record.Last);
    record.srcport = htons(record.srcport);
    record.dstport = htons(record.dstport);
    record.tcp_flags = record.tcp_flags;
    record.prot = record.prot;
    record.tos = record.tos;
    record.src_as = htons(record.src_as);
    record.dst_as = htons(record.dst_as);
    record.src_mask = record.src_mask;
    record.dst_mask = record.dst_mask;

    memcpy(buffer + offset, &record, sizeof(NetFlowV5record));
    offset += sizeof(NetFlowV5record); 

    length = offset;
}


