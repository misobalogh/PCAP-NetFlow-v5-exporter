////////////////////////////////////////////////////
// File: Exporter.cpp
// Pcap Netflow v5 Exporter
// Author: Michal Balogh, xbalog06
// Date: 14.10.2024
////////////////////////////////////////////////////

#include <netdb.h> 
#include <arpa/inet.h>

#include "Exporter.h"


/**
 * @brief Constructor of the class. Initialize socket for connection with collector.
 *
 * @param collector_ip IP address of the collector
 * @param collector_port Port of the collector
 */
Exporter::Exporter(const std::string& collector_ip, int collector_port) {
    sock = create_socket();

    // Try to resolve the host address
    struct addrinfo hints;
    struct addrinfo *result;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; // for IPv4
    hints.ai_socktype = SOCK_DGRAM; // UPD for Netflow

    int status = getaddrinfo(collector_ip.c_str(), std::to_string(collector_port).c_str(), &hints, &result);
    if (status != 0) {
        std::cerr << "Error resolving host address: " << gai_strerror(status) << std::endl;
        return;
    }

    // Set the resolved address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr = *(reinterpret_cast<struct sockaddr_in*>(result->ai_addr));

    flow_sequence = 0;
    
    freeaddrinfo(result); // Clean up
}

/**
 * @brief Destrucotr. Closes socket.
 */
Exporter::~Exporter() {
    close_socket();
}

/**
 * @brief Method for initializing socket for connection with collector.
 *
 * @return Socket if was succesfully created.
 */
int Exporter::create_socket() {
    int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0) {
        std::cerr << "Error creating socket." << std::endl;
        exit(EXIT_FAILURE);
    }
    return sock_fd;
}

/**
 * @brief Method fo closing the connection.
 */
void Exporter::close_socket() {
    if (sock >= 0) {
        close(sock);
    }
}

/**
 * @brief Exports all cached flows in the flows vector.
 *
 * @param flows Vector of flows to be exported
 * @param time_start Start time of the flow
 * @param time_end End time of the flow
 *
 * @return void
 */
void Exporter::export_flows(const std::vector<Flow>& flows, uint32_t time_start, uint32_t time_end) {

    uint16_t flow_count = flows.size();

    // Datagram has one header and can have 1-30 flows
    size_t datagram_size = sizeof(NetFlowV5header) + sizeof(NetFlowV5record) * flow_count;
    uint8_t buffer[datagram_size];
    
    format_header(buffer, flow_count, time_start, time_end);

    // Update the number of exported flows
    flow_sequence += flow_count;

    size_t offset = sizeof(NetFlowV5header);
    for (const auto& flow : flows) {
        format_record(flow.record, buffer, offset, time_start);
    }
    
    send(buffer, datagram_size);
}

/**
 * @brief Sends the UDP datagram stored in buffer to the collector.
 *
 * @param buffer Data to export
 * @param buffer_size Size of the data
 */
void Exporter::send(uint8_t* buffer, size_t buffer_size) {
    if (buffer_size == 0) {
        return;
    }

    ssize_t sent = sendto(sock, buffer, buffer_size, 0, (struct sockaddr*)&server_addr, sizeof(server_addr));
    if (sent < 0) {
        std::cerr << "Error occurred when sending flow. Program continues." << std::endl;
    }
}

/**
 * @brief Sets header in the buffer for Netflow v5 protocol.
 *
 * @param buffer Buffer for setting the data
 * @param flow_count Number of flows exported
 * @param time_start Start time of the flow needed for calculating uptime of the device
 * @param time_end End time of the flow needed for calculating uptime of the device
*/
void Exporter::format_header(uint8_t* buffer, uint16_t flow_count, uint32_t time_start, uint32_t time_end) {
    NetFlowV5header header;
    header.version = htons(VERSION_5);
    header.count = htons(flow_count); 
    header.SysUptime = htonl(time_end - time_start);  // Calculate the uptime of the device
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) == 0) { // Get current time 
        header.unix_secs = htonl(ts.tv_sec);
        header.unix_nsecs = htonl(ts.tv_nsec);
    }
    else { // Defaults to 0 in case of error
        header.unix_secs = htonl(0); 
        header.unix_nsecs = htonl(0);
    }
    header.flow_sequence = htonl(flow_sequence);
    header.engine_type = 0;
    header.engine_id = 0; 
    header.sampling_interval = 0; 

    // set the data to buffer
    memcpy(buffer, &header, sizeof(NetFlowV5header));
}

/**
 * @brief Sets record in the buffer for Netflow v5 protocol.
 *
 * @param record Record to set the buffer with
 * @param buffer Buffer for setting the data
 * @param offset for calculating where should be the data placed and not overwrting previous records
 * @param time_start Start time of the flow needed for calculating uptime of the device
*/
void Exporter::format_record(NetFlowV5record record, uint8_t* buffer, size_t& offset, uint32_t time_start) {

    record.srcaddr = htonl(record.srcaddr);
    record.dstaddr = htonl(record.dstaddr);
    record.nexthop = htonl(record.nexthop);
    record.input = 0;
    record.output = 0;
    record.dPkts = htonl(record.dPkts);
    record.dOctets = htonl(record.dOctets);
    record.First = htonl(record.First - time_start);
    record.Last = htonl(record.Last - time_start);
    record.srcport = htons(record.srcport);
    record.dstport = htons(record.dstport);
    record.tcp_flags = record.tcp_flags;
    record.prot = record.prot;
    record.tos = 0;
    record.src_as = htons(record.src_as);
    record.dst_as = htons(record.dst_as);
    record.src_mask = 0;
    record.dst_mask = 0;

    memcpy(buffer + offset, &record, sizeof(NetFlowV5record));
    // update the offset in the buffer after adding the record
    offset += sizeof(NetFlowV5record);
}


