////////////////////////////////////////////////////
// File: ArgParser.h
// Pcap Netflow v5 Exporter
// Author: Michal Balogh, xbalog06
// Date: 14.10.2024
////////////////////////////////////////////////////


#ifndef ARG_PARSER_H
#define ARG_PARSER_H

#include <string>
#include "Config.h"


/**
 * @brief Class for parsing command line arguments
 *
 * @param argc Number of command line arguments
 * @param argv Array of command line arguments
 *
 * Create the class by passing the argc and argv arguments from the main function.
 * After creating the class, you can access the parsed arguments using the getter methods for each argument.
 */
class ArgParser {
public:
    ArgParser(int argc, char* argv[]);

    // Getters for parsed arguments
    const std::string& getHost() const;
    int getPort() const;
    const std::string& getPCAPFilePath() const;
    int getActiveTimeout() const;
    int getInactiveTimeout() const;

private:
    void parseArgs(int argc, char* argv[]);
    void parseHostAndPort(const std::string& collectorAddress, size_t colonIndex);
    void validateTimeout(int timeout, const std::string& timeoutName);
    void validatePcapFile(const std::string& filePath);
    void printUsage() const;
    void printHelp() const;

    // Mandatory args
    std::string collectorHost;
    unsigned int collectorPort;
    std::string pcapFilePath;

    // Optional args with default values
    int activeTimeout;
    int inactiveTimeout;
};

#endif // ARG_PARSER_H
