////////////////////////////////////////////////////
// File: FlowKey.h
// Pcap Netflow v5 Exporter
// Author: Michal Balogh, xbalog06
// Date: 14.10.2024
////////////////////////////////////////////////////

#ifndef FLOW_KEY_H
#define FLOW_KEY_H

#include <cstddef> // For size_t
#include <string>

/**
 * @brief Interface for flow key classes.
 * Defines 2 methods that must be implemented by all flow key classes:
 *  - concatToString: For hashing 
 *  - operator==: For comparing flow keys
 */
class FlowKey {
public:
    virtual ~FlowKey() = default; 
    virtual std::string concatToString() const = 0; 
    virtual bool operator==(const FlowKey& other) const = 0; 
};

#endif // FLOW_KEY_H
