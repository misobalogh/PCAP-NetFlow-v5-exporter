#include <iostream>
#include <sstream>
#include <cstdlib>

#include "ArgParser.h"
#include "ErrorCodes.h" 

const unsigned int PORT_MIN = 1;
const unsigned int PORT_MAX = 65535; 

ArgParser::ArgParser(int argc, char* argv[]) {
    activeTimeout = DEFAULT_ACTIVE_TIMEOUT;
    inactiveTimeout = DEFAULT_INACTIVE_TIMEOUT;
    parseArgs(argc, argv);
}

void ArgParser::parseHostAndPort(const std::string& collectorAdress, size_t colonIndex) {
    
    // Split into host and port part
    std::string host = collectorAdress.substr(0, colonIndex);
    std::string port_str = collectorAdress.substr(colonIndex + 1);

    int port;

    try {
        port = std::stoi(port_str);
    }
    catch (const std::invalid_argument& e) {
        std::cerr << "Error: Could not parse number of port: Port is not a number.\n";
        ExitWith(ErrorCode::INVALID_ARGS); 
    } catch (const std::out_of_range& e) {
        std::cerr << "Error: Could not parse number of port: out of range.\n";
        ExitWith(ErrorCode::INTERNAL_ERROR); 
    }

    collectorHost = host;
    collectorPort = port;
}

void ArgParser::parseArgs(int argc, char* argv[]) {
    const int NUM_MANDATORY_ARGS = 2;
    if (argc < NUM_MANDATORY_ARGS + 1) {
        std::cerr << "Usage: ./p2nprobe <host>:<port> <pcap_file_path> [-a <active_timeout> -i <inactive_timeout>]\n";
        ExitWith(ErrorCode::INVALID_ARGS); 
    }

    bool pcapSetFlag = false;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        size_t colonPos = arg.find(':');
        // Collector adress
        if (colonPos != std::string::npos) {
            parseHostAndPort(arg, colonPos);
        } 
        // Active timeout
        else if (arg == "-a" && i + 1 < argc) {
            try {
                activeTimeout = std::stoi(argv[++i]);
            }
            catch (const std::out_of_range& e) {
                std::cerr << "Error: Could not parse active timeout: out of range.\n";
                ExitWith(ErrorCode::INTERNAL_ERROR);
            }
        }
        // Inactive timeour
        else if (arg == "-i" && i + 1 < argc) {
            try {
                inactiveTimeout = std::stoi(argv[++i]);
            }
            catch (const std::out_of_range& e) {
                std::cerr << "Error: Could not parse active timeout: out of range.\n";
                ExitWith(ErrorCode::INTERNAL_ERROR);
            }
        }
        // Path to PCAP file
        else if (!pcapSetFlag) {
            pcapFilePath = arg;
            pcapSetFlag = true;
        }
        else {
            std::cerr << "Error: Invalid argument provided: " << arg << "\n";
            std::cerr << "Usage: ./p2nprobe <host>:<port> <pcap_file_path> [-a <active_timeout> -i <inactive_timeout>]\n";
            ExitWith(ErrorCode::INVALID_ARGS); 
        }
    }

    if (collectorHost.empty() || pcapFilePath.empty()) {
        std::cerr << "Error: host:port and PCAP file path are mandatory.\n";
        ExitWith(ErrorCode::INVALID_ARGS); 
    }

    if (collectorPort < PORT_MIN || collectorPort > PORT_MAX) {
        std::cerr << "Error: Port number out of range ("<< PORT_MIN <<"-"<< PORT_MAX <<").\n";
        ExitWith(ErrorCode::INVALID_ARGS); 
    }
}

std::string ArgParser::getHost() const {
    return collectorHost;
}

int ArgParser::getPort() const {
    return collectorPort;
}

std::string ArgParser::getPCAPFilePath() const {
    return pcapFilePath;
}

int ArgParser::getActiveTimeout() const {
    return activeTimeout;
}

int ArgParser::getInactiveTimeout() const {
    return inactiveTimeout;
}
