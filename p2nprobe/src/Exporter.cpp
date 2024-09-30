#include "Exporter.h"

Exporter::Exporter(const std::string& collector_ip, int collector_port) {
    sock = create_socket();

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_port = htons(collector_port);
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(collector_ip.c_str());
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

void Exporter::send_flows(const std::vector<Flow>& flows) {
    for (const auto& flow : flows) {
        send_flows(flow);
    }
}

void Exporter::send_flows(const Flow& flow) {
    uint8_t buffer[DATAGRAM_SIZE];
    size_t length = 0;

    format(flow, buffer, length);

    if (length == 0) {
        return;
    }

    ssize_t sent = sendto(sock, buffer, length, 0, (struct sockaddr*)&server_addr, sizeof(server_addr));
    if (sent < 0) {
        std::cerr << "Error sending flow." << std::endl;
    }
}

void Exporter::format(const Flow& flow, uint8_t* buffer, size_t& length) {
    NetFlowV5header header;
    header.version = htons(5); // NetFlow v5 version
    header.count = htons(1);
    header.SysUptime = htonl(0);
    header.unix_secs = htonl(time(nullptr));
    header.unix_nsecs = htonl(0); 
    header.flow_sequence = htonl(0);
    header.engine_type = 0;
    header.engine_id = 0; 
    header.sampling_interval = 0; 

    memcpy(buffer, &header, sizeof(NetFlowV5header));

    size_t offset = sizeof(NetFlowV5header);

    NetFlowV5record record;
    record.srcaddr = htonl(flow.record.srcaddr); 
    record.dstaddr = htonl(flow.record.dstaddr);
    record.nexthop = htonl(flow.record.nexthop);
    record.input = htons(flow.record.input);
    record.output = htons(flow.record.output);
    record.dPkts = htonl(flow.record.dPkts);
    record.dOctets = htonl(flow.record.dOctets);
    record.First = htonl(flow.record.First);
    record.Last = htonl(flow.record.Last);
    record.srcport = htons(flow.record.srcport);
    record.dstport = htons(flow.record.dstport);
    record.tcp_flags = flow.record.tcp_flags;
    record.prot = flow.record.prot;
    record.tos = flow.record.tos;
    record.src_as = htons(flow.record.src_as);
    record.dst_as = htons(flow.record.dst_as);
    record.src_mask = flow.record.src_mask;
    record.dst_mask = flow.record.dst_mask;

    memcpy(buffer + offset, &record, sizeof(NetFlowV5record));
    offset += sizeof(NetFlowV5record); 

    length = offset;
}

    