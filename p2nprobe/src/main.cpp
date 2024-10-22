////////////////////////////////////////////////////
// File: main.cpp 
// Pcap Netflow v5 Exporter
// Author: Michal Balogh, xbalog06
// Date: 14.10.2024
////////////////////////////////////////////////////

#include <iostream>

#include "ErrorCodes.h"
#include "ArgParser.h"
#include "FlowManager.h"

/**
 * @brief Main entry point of the program
 *
 * @return 0 if the program was successful, -1 if there was an error reading a packet
 */
int main(int argc, char* argv[]) {
    ArgParser programArguments(argc, argv);

    int result;

    // Create the flow manager and start processing the packets
    FlowManager manager(programArguments);

    // Error while reading packet results in -1 and program termination
    result = manager.startProcessing();

    // After all packets are processed and aggregated, export the remaining flows
    manager.export_remaining();

    // Cleanup
    manager.dispose();

    if (result == -1) {
        std::cerr << "Error reading a packet." << std::endl;
        return result;
    }
    // result -2 means end of pcap file -> no error
    // reulst 0 also means no error
    return 0;
}
