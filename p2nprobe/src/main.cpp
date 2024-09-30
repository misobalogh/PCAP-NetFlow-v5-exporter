#include <iostream>

#include "ErrorCodes.h"
#include "ArgParser.h"
#include "PcapReader.h"

int main(int argc, char* argv[]) {
    ArgParser programArguments(argc, argv);

    std::cout << "Host: " << programArguments.getHost() << "\n";
    std::cout << "Port: " << programArguments.getPort() << "\n";
    std::cout << "PCAP File Path: " << programArguments.getPCAPFilePath() << "\n";
    std::cout << "Active Timeout: " << programArguments.getActiveTimeout() << " seconds\n";
    std::cout << "Inactive Timeout: " << programArguments.getInactiveTimeout() << " seconds\n\n";

    auto pcapFilePath = programArguments.getPCAPFilePath();

    PcapReader reader(pcapFilePath, programArguments.getHost(), programArguments.getPort());
    if (!reader.open()) {
        ExitWith(ErrorCode::FILE_OPEN_ERROR);
    }

    reader.readAllPackets();
    reader.close();

    return 0;
}
