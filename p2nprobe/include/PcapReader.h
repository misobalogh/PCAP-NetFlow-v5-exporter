#ifndef PCAP_READER_H
#define PCAP_READER_H

#include <pcap.h>
#include <string>
#include "NetFlowV5record.h"

class PcapReader {
public:
    PcapReader(std::string pcapFile);
    ~PcapReader();

    bool open();
    void close();

    bool processPacket(const struct pcap_pkthdr* header, const u_char* packet, NetFlowV5record& record);
    pcap_t* handle = nullptr;

private:
    std::string _pcapFile;
    char _errbuf[PCAP_ERRBUF_SIZE];
    bool isTcpPacket(const u_char* packet);
};

#endif // PCAP_READER_H
