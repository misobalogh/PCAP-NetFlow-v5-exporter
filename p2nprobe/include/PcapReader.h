////////////////////////////////////////////////////
// File: PcapReader.h
// Pcap Netflow v5 Exporter
// Author: Michal Balogh, xbalog06
// Date: 14.10.2024
////////////////////////////////////////////////////

#ifndef PCAP_READER_H
#define PCAP_READER_H

#include <pcap.h>
#include <string>
#include "NetFlowV5record.h"

/**
 * @brief Class for reading and processing packets from pcap file.
 */
class PcapReader {
public:
    PcapReader(std::string pcapFile);
    ~PcapReader();

    bool open();
    void close();

    bool processPacket(const struct pcap_pkthdr* header, const u_char* packet, NetFlowV5record& record);
    pcap_t* handle = nullptr;

private:
    std::string _pcapFile; // Name of the processed pcap file
    char _errbuf[PCAP_ERRBUF_SIZE]; // Error buffer in case error occurs while processing packets

    bool isTcpPacket(const u_char* packet);
};

#endif // PCAP_READER_H
