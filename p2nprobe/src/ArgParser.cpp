////////////////////////////////////////////////////
// File: ArgParser.cpp
// Pcap Netflow v5 Exporter
// Author: Michal Balogh, xbalog06
// Date: 14.10.2024
////////////////////////////////////////////////////


#include <iostream>
#include <sstream>
#include <cstdlib>
#include <filesystem>
#include <fstream>

#include "ArgParser.h"
#include "ErrorCodes.h"
#include "Config.h"
#include "Logger.h"

// Maximum and minimum possible port number
const unsigned int PORT_MIN = Config::MIN_PORT;
const unsigned int PORT_MAX = Config::MAX_PORT;

const std::string HELP_MESSAGE = R"(
NetFlow v5 PCAP Exporter (p2nprobe) v)" + std::string(Config::VERSION) + R"(
Author: )" + std::string(Config::AUTHOR) + R"(

DESCRIPTION:
    Reads packets from PCAP files, aggregates them into network flows,
    and exports them to a NetFlow v5 collector via UDP protocol.
    Designed specifically for TCP traffic analysis and monitoring.

USAGE:
    ./p2nprobe <host>:<port> <pcap_file_path> [OPTIONS]

ARGUMENTS:
    <host>:<port>            Address of the NetFlow collector in format host:port
                            Examples: localhost:9995, 192.168.1.100:2055,
                                     netflow.example.com:9995
    <pcap_file_path>         Path to PCAP file to process

OPTIONS:
    -a <active_timeout>      Active timeout in seconds (default: )" + std::to_string(Config::DEFAULT_ACTIVE_TIMEOUT) + R"()
                            Range: )" + std::to_string(Config::MIN_TIMEOUT) + R"(-)" + std::to_string(Config::MAX_TIMEOUT) + R"( seconds
    -i <inactive_timeout>    Inactive timeout in seconds (default: )" + std::to_string(Config::DEFAULT_INACTIVE_TIMEOUT) + R"()
                            Range: )" + std::to_string(Config::MIN_TIMEOUT) + R"(-)" + std::to_string(Config::MAX_TIMEOUT) + R"( seconds
    -h                       Display this help message and exit

EXAMPLES:
    ./p2nprobe localhost:9995 capture.pcap
    ./p2nprobe 192.168.1.100:2055 traffic.pcap -a 30 -i 15
    ./p2nprobe netflow-collector.example.com:9995 network_dump.pcap -a 120 -i 60
)";


/**
 * @brief Constructor for the ArgParser class.
 * Constructs the ArgParser object and parses the command line arguments.
 * They are then stored in the object and can be accessed using the getter methods.
 *
 * @param argc Number of command line arguments
 * @param argv Array of command line arguments
 */
ArgParser::ArgParser(int argc, char* argv[])
    : collectorHost(""),
    collectorPort(0),
    pcapFilePath(""),
    activeTimeout(Config::DEFAULT_ACTIVE_TIMEOUT),
    inactiveTimeout(Config::DEFAULT_INACTIVE_TIMEOUT) {

    LOG_DEBUG("Parsing command line arguments");
    parseArgs(argc, argv);
    LOG_DEBUG("Command line arguments parsed successfully");
}

/**
 * @brief Parses the host and port part of the collector address.
 * Format of the collector address is host:port
 *
 * @param collectorAddress Collector address in the format host:port
 * @param colonIndex Index of the colon character in the collector address
 *
 * @exception std::invalid_argument If the port part is not a number
 * @exception std::out_of_range If the port number is out of possible range (1-65535)
 */
void ArgParser::parseHostAndPort(const std::string& collectorAddress, size_t colonIndex) {
    LOG_DEBUG("Parsing collector address: ", collectorAddress);

    // Split into host and port part
    std::string host = collectorAddress.substr(0, colonIndex);
    std::string port_str = collectorAddress.substr(colonIndex + 1);

    // Validate host is not empty
    if (host.empty()) {
        LOG_ERROR("Host part cannot be empty");
        std::cerr << "Error: Host part cannot be empty in collector address.\n";
        printUsage();
        ExitWith(ErrorCode::INVALID_ARGS);
    }

    // Validate port string is not empty
    if (port_str.empty()) {
        LOG_ERROR("Port part cannot be empty");
        std::cerr << "Error: Port part cannot be empty in collector address.\n";
        printUsage();
        ExitWith(ErrorCode::INVALID_ARGS);
    }

    int port;
    try {
        port = std::stoi(port_str);
    }
    catch (const std::invalid_argument& e) {
        LOG_ERROR("Invalid port number: ", port_str);
        std::cerr << "Error: Could not parse port number '" << port_str << "': Not a valid number.\n";
        printUsage();
        ExitWith(ErrorCode::INVALID_ARGS);
    }
    catch (const std::out_of_range& e) {
        LOG_ERROR("Port number out of range: ", port_str);
        std::cerr << "Error: Port number '" << port_str << "' is out of range.\n";
        printUsage();
        ExitWith(ErrorCode::INVALID_ARGS);
    }

    // Validate port range
    if (port < PORT_MIN || port > PORT_MAX) {
        LOG_ERROR("Port number out of valid range: ", port);
        std::cerr << "Error: Port number must be between " << PORT_MIN
                  << " and " << PORT_MAX << ". Got: " << port << "\n";
        printUsage();
        ExitWith(ErrorCode::INVALID_ARGS);
    }

    collectorHost = host;
    collectorPort = static_cast<unsigned int>(port);

    LOG_DEBUG("Parsed collector - Host: ", collectorHost, ", Port: ", collectorPort);
}


/**
 * @brief Validates timeout value
 *
 * @param timeout Timeout value to validate
 * @param timeoutName Name of the timeout for error messages
 */
void ArgParser::validateTimeout(int timeout, const std::string& timeoutName) {
    if (timeout < Config::MIN_TIMEOUT || timeout > Config::MAX_TIMEOUT) {
        LOG_ERROR("Invalid ", timeoutName, " timeout: ", timeout);
        std::cerr << "Error: " << timeoutName << " timeout must be between "
                  << Config::MIN_TIMEOUT << " and " << Config::MAX_TIMEOUT
                  << " seconds. Got: " << timeout << "\n";
        printUsage();
        ExitWith(ErrorCode::INVALID_ARGS);
    }
}

/**
 * @brief Validates PCAP file path and accessibility
 *
 * @param filePath Path to the PCAP file
 */
void ArgParser::validatePcapFile(const std::string& filePath) {
    // Check if file exists and is readable
    if (!std::filesystem::exists(filePath)) {
        LOG_ERROR("PCAP file does not exist: ", filePath);
        std::cerr << "Error: PCAP file '" << filePath << "' does not exist.\n";
        ExitWith(ErrorCode::FILE_OPEN_ERROR);
    }

    if (!std::filesystem::is_regular_file(filePath)) {
        LOG_ERROR("PCAP path is not a regular file: ", filePath);
        std::cerr << "Error: '" << filePath << "' is not a regular file.\n";
        ExitWith(ErrorCode::FILE_OPEN_ERROR);
    }

    // Try to open the file to check permissions
    std::ifstream file(filePath);
    if (!file.good()) {
        LOG_ERROR("Cannot read PCAP file: ", filePath);
        std::cerr << "Error: Cannot read PCAP file '" << filePath << "'. Check permissions.\n";
        ExitWith(ErrorCode::FILE_OPEN_ERROR);
    }
    file.close();

    LOG_DEBUG("PCAP file validated: ", filePath);
}

/**
 * @brief Parses the command line arguments by iterating through them and trying to parse them.
 * If the argument is not valid, the program exits with an error message.
 *
 * @param argc Number of command line arguments
 * @param argv Array of command line arguments
 */
void ArgParser::parseArgs(int argc, char* argv[]) {
    LOG_DEBUG("Parsing ", argc, " command line arguments");

    // Check minimum arguments (program name + collector + pcap file)
    if (argc < 3) {
        std::cerr << "Error: Insufficient arguments. Minimum required: <host>:<port> <pcap_file_path>\n";
        printUsage();
        ExitWith(ErrorCode::INVALID_ARGS);
    }

    // Flag for checking if the PCAP file path was already set
    bool pcapSetFlag = false;
    bool collectorSetFlag = false;

    // Iterate through the arguments and parse them
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        LOG_DEBUG("Processing argument[", i, "]: ", arg);

        if (arg == "-h" || arg == "--help") {
            printHelp();
            ExitWith(ErrorCode::SUCCESS);  // Exit with success
        }

        size_t colonPos = arg.find(':');
        // Collector address
        if (colonPos != std::string::npos && !collectorSetFlag) {
            parseHostAndPort(arg, colonPos);
            collectorSetFlag = true;
        }
        // Active timeout
        else if (arg == "-a" && i + 1 < argc) {
            if (++i >= argc) {
                std::cerr << "Error: -a option requires a timeout value.\n";
                printUsage();
                ExitWith(ErrorCode::INVALID_ARGS);
            }
            try {
                activeTimeout = std::stoi(argv[i]);
                validateTimeout(activeTimeout, "Active");
                LOG_DEBUG("Active timeout set to: ", activeTimeout);
            }
            catch (const std::exception& e) {
                LOG_ERROR("Invalid active timeout value: ", argv[i]);
                std::cerr << "Error: Invalid active timeout value '" << argv[i] << "'.\n";
                printUsage();
                ExitWith(ErrorCode::INVALID_ARGS);
            }
        }
        // Inactive timeout
        else if (arg == "-i" && i + 1 < argc) {
            if (++i >= argc) {
                std::cerr << "Error: -i option requires a timeout value.\n";
                printUsage();
                ExitWith(ErrorCode::INVALID_ARGS);
            }
            try {
                inactiveTimeout = std::stoi(argv[i]);
                validateTimeout(inactiveTimeout, "Inactive");
                LOG_DEBUG("Inactive timeout set to: ", inactiveTimeout);
            }
            catch (const std::exception& e) {
                LOG_ERROR("Invalid inactive timeout value: ", argv[i]);
                std::cerr << "Error: Invalid inactive timeout value '" << argv[i] << "'.\n";
                printUsage();
                ExitWith(ErrorCode::INVALID_ARGS);
            }
        }
        // Path to PCAP file
        else if (!pcapSetFlag && !arg.empty() && arg[0] != '-') {
            pcapFilePath = arg;
            validatePcapFile(pcapFilePath);
            pcapSetFlag = true;
            LOG_DEBUG("PCAP file path set to: ", pcapFilePath);
        }
        else {
            LOG_ERROR("Invalid or unexpected argument: ", arg);
            std::cerr << "Error: Invalid or unexpected argument '" << arg << "'.\n";
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
 * @return const std::string& Collector host
 */
const std::string& ArgParser::getHost() const {
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
 * @return const std::string& PCAP file path
 */
const std::string& ArgParser::getPCAPFilePath() const {
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
