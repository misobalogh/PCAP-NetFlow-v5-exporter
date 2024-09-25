#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <iostream>

#include "PcapReader.h"
#include "ErrorCodes.h"

const unsigned int ETHERNET_HEADER_SIZE = 14;

PcapReader::PcapReader(const std::string& pcapFilePath) {
    pcapFile = pcapFilePath;
    errbuf[0] = '\0';
}

PcapReader::~PcapReader() {
    if (handle) {
        pcap_close(handle);
    }
}

bool PcapReader::open() {
    handle = pcap_open_offline(pcapFile.c_str(), errbuf);
    if (handle == NULL) {
        std::cerr << "Error: Cannot open file: " << errbuf << std::endl;
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

void PcapReader::readAllPackets() {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int result;

    while ((result = pcap_next_ex(handle, &header, &packet)) > 0) {
        processPacket(header, packet);
    }

    if (result == -1) {
        std::cerr << "Error reading the packet: " << pcap_geterr(handle) << std::endl;
        close();
        ExitWith(ErrorCode::READING_PACKET_ERROR);
    }
    // if result -2 -> end of pcap file
}

void PcapReader::processPacket(const struct pcap_pkthdr* header, const u_char* packet) {
    if (!isTcpPacket(packet)) {
        return; 
    }

    // skip ethernt header
    const u_char* ipOffset = packet + ETHERNET_HEADER_SIZE;
    const struct ip* ipHeader = reinterpret_cast<const struct ip*>(ipOffset);
    if (ipHeader == nullptr) {
        std::cerr << "Error: IP header is null." << std::endl;
        ExitWith(ErrorCode::INVALID_PACKET);
    }

    char srcIp[INET_ADDRSTRLEN];
    char dstIp[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ipHeader->ip_src), srcIp, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->ip_dst), dstIp, INET_ADDRSTRLEN);

    // calculation of the offset inspired from: https://www.tcpdump.org/pcap.html
    unsigned int ipHeaderLength = ipHeader->ip_hl * 4; // multiply by 4 to get size in bytes
    if (ipHeaderLength < 20) {
        std::cerr << "Error: Invalid IP header length: " << ipHeaderLength << " bytes." << std::endl;
        return;
    }

    const struct tcphdr* tcpHeader = reinterpret_cast<const struct tcphdr*>(ipOffset + ipHeaderLength);
    if (tcpHeader == nullptr) {
        std::cerr << "Error: TCP header is null." << std::endl;
        ExitWith(ErrorCode::INVALID_PACKET);
    }

    uint16_t srcPort = ntohs(tcpHeader->source);
    uint16_t dstPort = ntohs(tcpHeader->dest);


    std::cout << "TCP Packet - Src IP: " << srcIp << ", Src Port: " << srcPort
              << ", Dst IP: " << dstIp << ", Dst Port: " << dstPort << std::endl;
}




