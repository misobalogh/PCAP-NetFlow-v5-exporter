#ifndef PCAP_READER_H
#define PCAP_READER_H

#include <pcap.h>
#include <string>
#include "FlowManager.h"

class PcapReader {
    public:
        PcapReader(const std::string& pcapFilePath, const std::string& collector_ip, int collector_port);
        ~PcapReader();

        bool open(); 
        void close();
        
        void readAllPackets();

    private:
        std::string _pcapFile;
        pcap_t* _handle = nullptr;
        char _errbuf[PCAP_ERRBUF_SIZE];
        FlowManager _flowManager;

        bool isTcpPacket(const u_char* packet);
        void processPacket(const struct pcap_pkthdr* header, const u_char* packet);
};

#endif // PCAP_READER_H
