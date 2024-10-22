////////////////////////////////////////////////////
// File: PcapReader.cpp
// Pcap Netflow v5 Exporter
// Author: Michal Balogh, xbalog06
// Date: 14.10.2024
////////////////////////////////////////////////////

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <iostream>
#include <sys/time.h> 
#include <cstring>

#include "PcapReader.h"
#include "ErrorCodes.h"
#include "NetFlowV5Key.h"
#include "NetFlowV5record.h"

const unsigned int ETHERNET_HEADER_SIZE = 14;

/**
 * @brief Constructor for the PcapReader class. Initializes the err buffer and pcap file name.
 */
PcapReader::PcapReader(std::string pcapFile)
    : _pcapFile(pcapFile) {
    _errbuf[0] = '\0';
}

/**
 * @brief Destructor of the class. Closes the handle.
 */
PcapReader::~PcapReader() {
    close();
}

/**
 * @brief Initializes handle for processing packets by opening the pcap file.
 *
 * @return false if error occured while opening the file, true otherwise.
 */
bool PcapReader::open() {
    handle = pcap_open_offline(_pcapFile.c_str(), _errbuf);
    if (handle == NULL) {
        std::cerr << "Error: Cannot open file: " << _errbuf << std::endl;
        return false;
    }
    return true;
}

/**
 * @brief Closes the handle and sets the handle to nullptr.
 *
 * @return void
 */
void PcapReader::close() {
    if (handle) {
        pcap_close(handle);
        handle = nullptr;
    }
}


/**
 * @brief Checks wheter the packet processed is TCP packet.
 *
 * @return true if packet is TCP packet, false otherwise.
 */
bool PcapReader::isTcpPacket(const u_char* packet) {
    // Extract ip header by removing ethernet header part.
    const struct ip* ipHeader = reinterpret_cast<const struct ip*>(packet + ETHERNET_HEADER_SIZE);
    return (ipHeader->ip_p == IPPROTO_TCP);
}

/**
 * @brief Extracts data from packet and sets the data to NetflowV5record record structure.
 *
 * @param header Header of the packet.
 * @param packet Packet to be processed.
 * @param record Struct, where will be the data from packet stored.
 *
 * @return true if packet was processed without issues, false otherwise.
 */
bool PcapReader::processPacket(const struct pcap_pkthdr* header, const u_char* packet, NetFlowV5record& record) {
    if (!isTcpPacket(packet)) { // Process only TCP packets
        return false;
    }

    // Extract the header from packet by skipping ethernet header
    const u_char* ipOffset = packet + ETHERNET_HEADER_SIZE;
    const struct ip* ipHeader = reinterpret_cast<const struct ip*>(ipOffset);
    if (ipHeader == nullptr) {
        std::cerr << "Error: IP header is null." << std::endl;
        close();
        ExitWith(ErrorCode::INVALID_PACKET);
    }

    unsigned int ipHeaderLength = ipHeader->ip_hl * 4; // Length of IP header
    if (ipHeaderLength < 20) { // IPv4 packet headers have to be at least 20 bytes long
        std::cerr << "Error: Invalid IP header length: " << ipHeaderLength << " bytes." << std::endl;
        return false;
    }

    const struct tcphdr* tcpHeader = reinterpret_cast<const struct tcphdr*>(ipOffset + ipHeaderLength);
    if (tcpHeader == nullptr) {
        std::cerr << "Error: TCP header is null." << std::endl;
        close();
        ExitWith(ErrorCode::INVALID_PACKET);
    }

    uint32_t totalPacketLength = header->len - ETHERNET_HEADER_SIZE;
    uint32_t timestamp_ms = header->ts.tv_sec * 1000 + header->ts.tv_usec / 1000; // convert timestamp to miliseconds


    record.prot = IPPROTO_TCP;                          // Protocol
    record.srcaddr = ntohl(ipHeader->ip_src.s_addr);    // Source address
    record.dstaddr = ntohl(ipHeader->ip_dst.s_addr);    // Destination address
    record.srcport = ntohs(tcpHeader->source);          // Source port
    record.dstport = ntohs(tcpHeader->dest);            // Destination port
    record.tos = 0;                                     // -
    record.tcp_flags = tcpHeader->th_flags;             // TCP flags
    record.input = 0;                                   // -
    record.dOctets = totalPacketLength;                 // Number of layer 3 bytes
    record.dPkts = 1; // If new flow is created, number of packets will be 1, otherwise, the number of packets is managed by flow itself.
    record.Last = timestamp_ms;                         // Timestamp in miliseconds

    return true;
}




