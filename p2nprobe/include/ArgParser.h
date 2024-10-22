////////////////////////////////////////////////////
// File: ArgParser.h
// Pcap Netflow v5 Exporter
// Author: Michal Balogh, xbalog06
// Date: 14.10.2024
////////////////////////////////////////////////////


#ifndef ARG_PARSER_H
#define ARG_PARSER_H

#include <string>


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

    std::string getHost() const;
    int getPort() const;
    std::string getPCAPFilePath() const;
    int getActiveTimeout() const;
    int getInactiveTimeout() const;

private:
    void parseArgs(int argc, char* argv[]);
    void parseHostAndPort(const std::string& collectorAdress, size_t colonIndex);
    void printUsage() const;

    // Mandatory args
    std::string collectorHost;
    unsigned int collectorPort;
    std::string pcapFilePath;

    // Default values for optional args
    static const int DEFAULT_ACTIVE_TIMEOUT = 60;
    static const int DEFAULT_INACTIVE_TIMEOUT = 60;

    // Optional args
    int activeTimeout = DEFAULT_ACTIVE_TIMEOUT;
    int inactiveTimeout = DEFAULT_INACTIVE_TIMEOUT;
};

#endif // ARG_PARSER_H
