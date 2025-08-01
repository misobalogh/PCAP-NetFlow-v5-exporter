////////////////////////////////////////////////////
// File: Config.h
// Pcap Netflow v5 Exporter
// Author: Michal Balogh, xbalog06
// Date: 14.10.2024
////////////////////////////////////////////////////

#ifndef CONFIG_H
#define CONFIG_H

#include <cstdint>

namespace Config {
    // Version information
    constexpr const char* VERSION = "1.0.0";
    constexpr const char* AUTHOR = "Michal Balogh (xbalog06)";

    // Default values
    constexpr int DEFAULT_ACTIVE_TIMEOUT = 60;   // seconds
    constexpr int DEFAULT_INACTIVE_TIMEOUT = 60; // seconds
    constexpr uint16_t DEFAULT_NETFLOW_VERSION = 5;

    // Network constraints
    constexpr uint32_t MIN_PORT = 1;
    constexpr uint32_t MAX_PORT = 65535;

    // NetFlow constraints (according to RFC)
    constexpr uint8_t MAX_FLOWS_PER_PACKET = 30;
    constexpr size_t NETFLOW_HEADER_SIZE = 24;
    constexpr size_t NETFLOW_RECORD_SIZE = 48;

    // Processing constraints
    constexpr size_t MAX_CACHED_FLOWS = MAX_FLOWS_PER_PACKET;
    constexpr size_t ETHERNET_HEADER_SIZE = 14;

    // Timeout constraints
    constexpr int MIN_TIMEOUT = 1;      // 1 second minimum
    constexpr int MAX_TIMEOUT = 86400;  // 24 hours maximum

    // Buffer sizes
    constexpr size_t PCAP_ERRBUF_SIZE = 256;
    constexpr size_t MAX_HOSTNAME_LENGTH = 256;

    // Debug and logging
    #ifdef DEBUG
        constexpr bool ENABLE_DEBUG_LOGGING = true;
    #else
        constexpr bool ENABLE_DEBUG_LOGGING = false;
    #endif
}

#endif // CONFIG_H
