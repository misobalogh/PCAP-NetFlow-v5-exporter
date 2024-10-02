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

PcapReader::PcapReader(std::string pcapFile)
    : _pcapFile(pcapFile) {
    _errbuf[0] = '\0';
}

PcapReader::~PcapReader() {
    close();
}

bool PcapReader::open() {
    handle = pcap_open_offline(_pcapFile.c_str(), _errbuf);
    if (handle == NULL) {
        std::cerr << "Error: Cannot open file: " << _errbuf << std::endl;
        return false;
    }
    return true;
}

void PcapReader::close() {
    if (handle) {
        pcap_close(handle);
        handle = nullptr;
    }
}

bool PcapReader::isTcpPacket(const u_char* packet) {
    const struct ip* ipHeader = reinterpret_cast<const struct ip*>(packet + ETHERNET_HEADER_SIZE);
    return (ipHeader->ip_p == IPPROTO_TCP);
}


bool PcapReader::processPacket(const struct pcap_pkthdr* header, const u_char* packet, NetFlowV5record& record) {
    if (!isTcpPacket(packet)) {
        return false;
    }

    // Skip Ethernet header
    const u_char* ipOffset = packet + ETHERNET_HEADER_SIZE;
    const struct ip* ipHeader = reinterpret_cast<const struct ip*>(ipOffset);
    if (ipHeader == nullptr) {
        std::cerr << "Error: IP header is null." << std::endl;
        ExitWith(ErrorCode::INVALID_PACKET);
    }

    unsigned int ipHeaderLength = ipHeader->ip_hl * 4; // Length of IP header
    if (ipHeaderLength < 20) {
        std::cerr << "Error: Invalid IP header length: " << ipHeaderLength << " bytes." << std::endl;
        return false;
    }

    const struct tcphdr* tcpHeader = reinterpret_cast<const struct tcphdr*>(ipOffset + ipHeaderLength);
    if (tcpHeader == nullptr) {
        std::cerr << "Error: TCP header is null." << std::endl;
        ExitWith(ErrorCode::INVALID_PACKET);
    }

    uint32_t totalPacketLength = header->len - ETHERNET_HEADER_SIZE;
    struct timeval packet_timestamp = header->ts;
    uint32_t timestamp_ms = packet_timestamp.tv_sec * 1000 + packet_timestamp.tv_usec / 1000;


    record.prot = IPPROTO_TCP;
    record.srcaddr = ntohl(ipHeader->ip_src.s_addr);
    record.dstaddr = ntohl(ipHeader->ip_dst.s_addr);
    record.srcport = ntohs(tcpHeader->source);
    record.dstport = ntohs(tcpHeader->dest);
    record.tos = ipHeader->ip_tos;
    record.tcp_flags = tcpHeader->th_flags;
    record.input = 0;
    record.dOctets = totalPacketLength;
    record.dPkts = 1; // if new flow is created, number of packets will be 1
    record.Last = header->ts.tv_sec;

    return true;
}




