#ifndef ARG_PARSER_H
#define ARG_PARSER_H

#include <string>

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
    
    void parseHostAndPort(const std::string& collectorAdress, size_t colonPos);

    // Mandatory args
    std::string collectorHost;
    unsigned int collectorPort;
    std::string pcapFilePath;

    static const int DEFAULT_ACTIVE_TIMEOUT = 60;   
    static const int DEFAULT_INACTIVE_TIMEOUT = 60; 
    // Optional args
    int activeTimeout = DEFAULT_ACTIVE_TIMEOUT;  
    int inactiveTimeout = DEFAULT_INACTIVE_TIMEOUT;
};

#endif // ARG_PARSER_H
