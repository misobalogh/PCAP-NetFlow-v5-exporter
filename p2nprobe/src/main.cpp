#include <iostream>

#include "ErrorCodes.h"
#include "ArgParser.h"
#include "FlowManager.h"

int main(int argc, char* argv[]) {
    ArgParser programArguments(argc, argv);

    std::cout << "Host: " << programArguments.getHost() << "\n";
    std::cout << "Port: " << programArguments.getPort() << "\n";
    std::cout << "PCAP File Path: " << programArguments.getPCAPFilePath() << "\n";
    std::cout << "Active Timeout: " << programArguments.getActiveTimeout() << " seconds\n";
    std::cout << "Inactive Timeout: " << programArguments.getInactiveTimeout() << " seconds\n\n";

    int result;
    FlowManager manager(programArguments);

    result = manager.startProcessing();

    manager.export_remaining();
    manager.dispose();

    if (result == -1) {
        std::cerr << "Error reading a packet." << std::endl;
        return result;
    }
    // result -2 means end of pcap file -> no error
    // reulst 0 also means no error
    return 0;
}
