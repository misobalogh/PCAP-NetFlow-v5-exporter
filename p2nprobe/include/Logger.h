////////////////////////////////////////////////////
// File: Logger.h
// Pcap Netflow v5 Exporter
// Author: Michal Balogh, xbalog06
// Date: 14.10.2024
////////////////////////////////////////////////////

#ifndef LOGGER_H
#define LOGGER_H

#include <iostream>
#include <iomanip>
#include <chrono>
#include <sstream>
#include "Config.h"

/**
 * @brief Simple logging utility for debugging and monitoring
 */
class Logger {
public:
    enum class Level {
        DEBUG_LEVEL = 0,
        INFO = 1,
        WARNING = 2,
        ERROR = 3
    };

    /**
     * @brief Log a debug message (only in debug builds)
     */
    template<typename... Args>
    static void debug(Args&&... args) {
        if constexpr (Config::ENABLE_DEBUG_LOGGING) {
            log(Level::DEBUG_LEVEL, std::forward<Args>(args)...);
        }
    }

    /**
     * @brief Log an info message
     */
    template<typename... Args>
    static void info(Args&&... args) {
        log(Level::INFO, std::forward<Args>(args)...);
    }

    /**
     * @brief Log a warning message
     */
    template<typename... Args>
    static void warning(Args&&... args) {
        log(Level::WARNING, std::forward<Args>(args)...);
    }

    /**
     * @brief Log an error message
     */
    template<typename... Args>
    static void error(Args&&... args) {
        log(Level::ERROR, std::forward<Args>(args)...);
    }

private:
    /**
     * @brief Internal logging function
     */
    template<typename... Args>
    static void log(Level level, Args&&... args) {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        auto tm = *std::localtime(&time_t);

        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) % 1000;

        std::ostream& stream = (level >= Level::WARNING) ? std::cerr : std::cout;

        stream << "[" << std::put_time(&tm, "%Y-%m-%d %H:%M:%S")
               << "." << std::setfill('0') << std::setw(3) << ms.count()
               << "] [" << levelToString(level) << "] ";

        ((stream << std::forward<Args>(args)), ...);
        stream << std::endl;
    }

    /**
     * @brief Convert log level to string
     */
    static const char* levelToString(Level level) {
        switch (level) {
            case Level::DEBUG_LEVEL: return "DEBUG";
            case Level::INFO:        return "INFO ";
            case Level::WARNING:     return "WARN ";
            case Level::ERROR:       return "ERROR";
            default:                return "UNKNOWN";
        }
    }
};

// Convenience macros for cleaner code
#define LOG_DEBUG(...) Logger::debug(__VA_ARGS__)
#define LOG_INFO(...) Logger::info(__VA_ARGS__)
#define LOG_WARNING(...) Logger::warning(__VA_ARGS__)
#define LOG_ERROR(...) Logger::error(__VA_ARGS__)

#endif // LOGGER_H
