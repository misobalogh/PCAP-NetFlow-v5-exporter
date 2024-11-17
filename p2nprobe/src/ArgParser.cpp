////////////////////////////////////////////////////
// File: ArgParser.cpp
// Pcap Netflow v5 Exporter
// Author: Michal Balogh, xbalog06
// Date: 14.10.2024
////////////////////////////////////////////////////


#include <iostream>
#include <sstream>
#include <cstdlib>

#include "ArgParser.h"
#include "ErrorCodes.h" 

// Maximum and minimum possible port number
const unsigned int PORT_MIN = 1;
const unsigned int PORT_MAX = 65535;

const std::string HELP_MESSAGE = R"(
Arguments:
    -h                       Display this help message and exit
  Mandatory:
    <host>:<port>            Address of the collector in format host:port
    <pcap_file_path>         Path to PCAP file
  Optional:
    -a <active_timeout>      Active timeout in seconds (default: 60)
    -i <inactive_timeout>    Inactive timeout in seconds (default: 60)
)";


/**
 * @brief Constructor for the ArgParser class.
 * Constructs the ArgParser object and parses the command line arguments.
 * They are then stored in the object and can be accessed using the getter methods.
 *
 * @param argc Number of command line arguments
 * @param argv Array of command line arguments
 *
 * @return void
 */
ArgParser::ArgParser(int argc, char* argv[])
    : collectorHost(""),
    collectorPort(0),
    pcapFilePath(""),
    activeTimeout(DEFAULT_ACTIVE_TIMEOUT),
    inactiveTimeout(DEFAULT_INACTIVE_TIMEOUT) {
    parseArgs(argc, argv);
}

/**
 * @brief Parses the host and port part of the collector address.
 * Format of the collector address is host:port
 *
 * @param collectorAdress Collector address in the format host:port
 * @param colonIndex Index of the colon character in the collector address
 *
 * @return void
 *
 * @exception std::invalid_argument If the port part is not a number
 * @exception std::out_of_range If the port number is out of possible range (1-65535)
 */
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
        printUsage();
        ExitWith(ErrorCode::INVALID_ARGS);
    }
    catch (const std::out_of_range& e) {
        std::cerr << "Error: Could not parse number of port: out of range.\n";
        printUsage();
        ExitWith(ErrorCode::INTERNAL_ERROR);
    }

    collectorHost = host;
    collectorPort = port;
}


/**
 * @brief Parses the command line arguments by iterating through them and trying to parse them.
 * If the argument is not valid, the program exits with an error message.
 *
 * @param argc Number of command line arguments
 * @param argv Array of command line arguments
 *
 * @return void
 *
 * @exception std::out_of_range if the active or inactive timeout is out of range
 */
void ArgParser::parseArgs(int argc, char* argv[]) {

    // Flag for checking if the PCAP file path was already set
    bool pcapSetFlag = false;

    // Iterate through the arguments and parse them
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "-h") {
            printHelp(); 
            ExitWith(ErrorCode::SUCCESS);  // Exit with success
        }

        size_t colonPos = arg.find(':');
        // Collector adress
        if (colonPos != std::string::npos) {
            parseHostAndPort(arg, colonPos);
        }
        // Active timeout
        else if (arg == "-a" && i + 1 < argc) {
            try {
                activeTimeout = std::stoi(argv[++i]);
                if (activeTimeout <= 0) {
                    std::cerr << "Error: Active timeout must be a positive number.\n";
                    ExitWith(ErrorCode::INVALID_ARGS);
                }
            }
            catch (const std::exception& e) {
                std::cerr << "Error: Invalid active timeout value.\n";
                ExitWith(ErrorCode::INVALID_ARGS);
            }
        }
        // Inactive timeour
        else if (arg == "-i" && i + 1 < argc) {
            try {
                inactiveTimeout = std::stoi(argv[++i]);
                if (inactiveTimeout <= 0) {
                    std::cerr << "Error: Inactive timeout must be a positive number.\n";
                    ExitWith(ErrorCode::INVALID_ARGS);
                }
            }
            catch (const std::exception& e) {
                std::cerr << "Error: Invalid inactive timeout value.\n";
                ExitWith(ErrorCode::INVALID_ARGS);
            }
        }
        // Path to PCAP file
        else if (!pcapSetFlag) {
            pcapFilePath = arg;
            pcapSetFlag = true;
        }
        else {
            std::cerr << "Error: Invalid argument provided: " << arg << "\n";
            printUsage();
            ExitWith(ErrorCode::INVALID_ARGS);
        }
    }

    // Check if the mandatory arguments were set
    if (collectorHost.empty() || pcapFilePath.empty()) {
        std::cerr << "Error: host:port and PCAP file path are mandatory.\n";
        printUsage();
        ExitWith(ErrorCode::INVALID_ARGS);
    }

    // Check valid range of port number
    if (collectorPort < PORT_MIN || collectorPort > PORT_MAX) {
        std::cerr << "Error: Port number out of range (" << PORT_MIN << "-" << PORT_MAX << ").\n";
        printUsage();
        ExitWith(ErrorCode::INVALID_ARGS);
    }

    const int NUM_MANDATORY_ARGS = 2;
    if (argc < NUM_MANDATORY_ARGS + 1) {
        printUsage();
        ExitWith(ErrorCode::INVALID_ARGS);
    }
}


/**
 * @brief Prints help message to the standard output.
 *
 * @return void
 */
void ArgParser::printHelp() const {
    std::cout << "Pcap Netflow v5 Exporter" << std::endl;
    printUsage();
    std::cout << HELP_MESSAGE;
}

/**
 * @brief Prints program usage to the standard error output.
 *
 * @return void
 */
void ArgParser::printUsage() const {
    std::cerr << "Usage: ./p2nprobe <host>:<port> <pcap_file_path> [-a <active_timeout> -i <inactive_timeout>]\n";
}

/**
 * @brief Getter method for the collector host. Mandatory argument.
 *
 * @return std::string Collector host
 */
std::string ArgParser::getHost() const {
    return collectorHost;
}

/**
 * @brief Getter method for the collector port. Mandatory argument.
 *
 * @return int Collector port
 */
int ArgParser::getPort() const {
    return collectorPort;
}

/**
 * @brief Getter method for the PCAP file path. Mandatory argument.
 *
 * @return std::string PCAP file path
 */
std::string ArgParser::getPCAPFilePath() const {
    return pcapFilePath;
}

/**
 * @brief Getter method for the active timeout if set, otherwise the default value.
 *
 * @return int Active timeout
 */
int ArgParser::getActiveTimeout() const {
    return activeTimeout;
}

/**
 * @brief Getter method for the inactive timeout if set, otherwise the default value.
 *
 * @return int Inactive timeout
 */
int ArgParser::getInactiveTimeout() const {
    return inactiveTimeout;
}
