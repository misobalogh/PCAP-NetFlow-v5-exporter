#ifndef ERROR_CODES_H
#define ERROR_CODES_H

#include <cstdlib>
#include <iostream>

enum class ErrorCode {
    SUCCESS = 0,
    INTERNAL_ERROR = 1,
    INVALID_ARGS = 2,
};

inline void ExitWith(ErrorCode code) {
    std::cerr << "Program terminated with: " << static_cast<int>(code) << "\n";
    exit(static_cast<int>(code));
}

#endif // ERROR_CODES_H
