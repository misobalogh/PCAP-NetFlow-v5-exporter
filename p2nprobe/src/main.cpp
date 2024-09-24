#include <iostream>
#include "ArgParser.h"

int main(int argc, char* argv[]) {
    ArgParser parser(argc, argv);

    std::cout << "Host: " << parser.getHost() << "\n";
    std::cout << "Port: " << parser.getPort() << "\n";
    std::cout << "PCAP File Path: " << parser.getPCAPFilePath() << "\n";
    std::cout << "Active Timeout: " << parser.getActiveTimeout() << " seconds\n";
    std::cout << "Inactive Timeout: " << parser.getInactiveTimeout() << " seconds\n";

    return 0; 
}
