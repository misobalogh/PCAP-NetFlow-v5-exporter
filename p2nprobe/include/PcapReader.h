#ifndef PCAP_READER_H
#define PCAP_READER_H

#include <pcap.h>
#include <string>
#include "FlowManager.h"

class PcapReader {
    public:
        PcapReader(const std::string& pcapFilePath);
        ~PcapReader();

        bool open(); 
        void close();
        
        void readAllPackets();

    private:
        std::string _pcapFile;
        char _errbuf[PCAP_ERRBUF_SIZE];
        FlowManager _flowManager;
        pcap_t* _handle = nullptr;

        bool isTcpPacket(const u_char* packet);
        void processPacket(const struct pcap_pkthdr* header, const u_char* packet);
};

#endif // PCAP_READER_H
