////////////////////////////////////////////////////
// File: main.cpp
// Pcap Netflow v5 Exporter
// Author: Michal Balogh, xbalog06
// Date: 14.10.2024
////////////////////////////////////////////////////

#include <iostream>
#include <iomanip>
#include <chrono>

#include "ErrorCodes.h"
#include "ArgParser.h"
#include "FlowManager.h"

/**
 * @brief Print program banner with version info
 */
void printBanner() {
    std::cout << "====================================\n";
    std::cout << "  NetFlow v5 PCAP Exporter (p2nprobe)\n";
    std::cout << "  Author: Michal Balogh (xbalog06)\n";
    std::cout << "  Version: 1.0.0\n";
    std::cout << "====================================\n\n";
}

/**
 * @brief Print processing statistics
 */
void printStats(int result, const std::chrono::high_resolution_clock::time_point& start_time) {
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

    std::cout << "\n====================================\n";
    std::cout << "Processing completed in " << duration.count() << " ms\n";

    if (result == -1) {
        std::cout << "Status: ERROR - Packet reading failed\n";
    } else if (result == -2) {
        std::cout << "Status: SUCCESS - End of PCAP file reached\n";
    } else {
        std::cout << "Status: SUCCESS - All packets processed\n";
    }
    std::cout << "====================================\n";
}

/**
 * @brief Main entry point of the program
 *
 * @param argc Number of command line arguments
 * @param argv Array of command line arguments
 * @return 0 if the program was successful, -1 if there was an error reading a packet
 */
int main(int argc, char* argv[]) {
    printBanner();

    auto start_time = std::chrono::high_resolution_clock::now();

    try {
        // Parse command line arguments
        ArgParser programArguments(argc, argv);

        std::cout << "Configuration:\n";
        std::cout << "  Collector: " << programArguments.getHost() << ":" << programArguments.getPort() << "\n";
        std::cout << "  PCAP file: " << programArguments.getPCAPFilePath() << "\n";
        std::cout << "  Active timeout: " << programArguments.getActiveTimeout() << "s\n";
        std::cout << "  Inactive timeout: " << programArguments.getInactiveTimeout() << "s\n\n";

        std::cout << "Starting packet processing...\n";

        // Create the flow manager and start processing the packets
        FlowManager manager(programArguments);

        // Error while reading packet results in -1 and program termination
        int result = manager.startProcessing();

        std::cout << "Exporting remaining flows...\n";
        // After all packets are processed and aggregated, export the remaining flows
        manager.export_remaining();

        // Cleanup
        manager.dispose();

        printStats(result, start_time);

        if (result == -1) {
            std::cerr << "Error: Failed to read packet from PCAP file.\n";
            return 1; // Use standard exit codes
        }

        return 0; // Success

    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Fatal error: Unknown exception occurred" << std::endl;
        return 1;
    }
}
