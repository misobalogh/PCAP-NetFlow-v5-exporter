////////////////////////////////////////////////////
// File: ErrorCodes.h
// Pcap Netflow v5 Exporter
// Author: Michal Balogh, xbalog06
// Date: 14.10.2024
////////////////////////////////////////////////////


#ifndef ERROR_CODES_H
#define ERROR_CODES_H

#include <cstdlib>
#include <iostream>

/**
 * @brief Error codes that can be returned by the program.
 */
enum class ErrorCode {
    SUCCESS = 0,                // No error
    INTERNAL_ERROR = 1,         // Internal error
    INVALID_ARGS = 2,           // Invalid arguments
    FILE_OPEN_ERROR = 3,        // Error while opening file
    READING_PACKET_ERROR = 4,   // Error while reading packet
    INVALID_PACKET = 5,         // Invalid packet
};

/**
 * @brief Exit the program with the given error code.
 * @param code Error code
 */
inline void ExitWith(ErrorCode code) {
    if (code != ErrorCode::SUCCESS) {
        std::cerr << "Program terminated with: " << static_cast<int>(code) << "\n";
    }
    exit(static_cast<int>(code));
}

#endif // ERROR_CODES_H
