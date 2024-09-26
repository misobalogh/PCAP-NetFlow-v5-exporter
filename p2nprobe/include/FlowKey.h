#ifndef FLOW_KEY_H
#define FLOW_KEY_H

#include <cstddef> // For size_t
#include <string>

class FlowKey {
public:
    virtual ~FlowKey() = default; 
    virtual std::string concatToString() const = 0; 
    virtual bool operator==(const FlowKey& other) const = 0; 
};

#endif // FLOW_KEY_H
