# NetFlow v5 PCAP Exporter (p2nprobe)

A high-performance C++17 application that reads packets from PCAP files, aggregates them into network flows, and exports them to a NetFlow v5 collector via UDP protocol. This tool is specifically designed for TCP traffic analysis and monitoring.

## Features

- **PCAP Processing**: Reads and processes packets from PCAP files using libpcap
- **Flow Aggregation**: Aggregates TCP packets into flows based on 5-tuple identification
- **NetFlow v5 Export**: Exports flows in standard NetFlow v5 format
- **Timeout Management**: Supports both active and inactive flow timeouts
- **Real-time Processing**: Processes packets and exports flows in real-time
- **Performance Optimized**: Uses efficient data structures (hash maps + linked lists) for flow management
- **Error Handling**: Comprehensive error handling and logging

## Requirements

- **Operating System**: Linux (tested on modern distributions)
- **Compiler**: GCC with C++17 support
- **Dependencies**:
  - libpcap-dev
  - Standard C++ libraries

### Installing Dependencies

On Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install build-essential libpcap-dev
```

On CentOS/RHEL/Fedora:
```bash
sudo yum install gcc-c++ libpcap-devel
# or for newer versions:
sudo dnf install gcc-c++ libpcap-devel
```

## 🔧 Building

### Checking Dependencies

Before building, you can check if all required dependencies are installed:

```bash
./check_dependencies.sh
```

This script will verify that you have:
- GCC with C++17 support
- make build system
- libpcap development headers
- pkg-config (for CMake builds)

### Build Options

The project supports both Make and CMake build systems.

#### Using Make (Recommended)

Navigate to the project directory and compile:

```bash
cd p2nprobe
make
```

Available Make targets:
- `make` or `make release` - Release build with optimizations
- `make debug` - Debug build with debug symbols and logging
- `make clean` - Clean build artifacts
- `make install` - Install to /usr/local/bin (requires sudo)
- `make run` - Build and run with test parameters
- `make help` - Show available targets

#### Using CMake

For more advanced build configuration:

```bash
cd p2nprobe
mkdir build && cd build
cmake ..
make
```

CMake build types:
- `cmake -DCMAKE_BUILD_TYPE=Release ..` - Optimized release build
- `cmake -DCMAKE_BUILD_TYPE=Debug ..` - Debug build
- `cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo ..` - Release with debug info
make clean
```

## Usage

### Basic Syntax

```bash
./p2nprobe <host>:<port> <pcap_file_path> [-a <active_timeout>] [-i <inactive_timeout>]
```

### Parameters

- **`<host>:<port>`** - NetFlow collector address (IP or hostname with port)
- **`<pcap_file_path>`** - Path to the PCAP file to process
- **`-a <active_timeout>`** - Active timeout in seconds (default: 60)
- **`-i <inactive_timeout>`** - Inactive timeout in seconds (default: 60)
- **`-h`** - Display help message

### Examples

**Basic usage with localhost collector:**
```bash
./p2nprobe localhost:9995 capture.pcap
```

**With custom timeouts:**
```bash
./p2nprobe 192.168.1.100:2055 traffic.pcap -a 30 -i 15
```

**Using domain name:**
```bash
./p2nprobe netflow-collector.example.com:9995 network_dump.pcap -a 120 -i 60
```

## Architecture

### Core Components

1. **ArgParser** - Command-line argument parsing and validation
2. **PcapReader** - PCAP file reading and packet processing
3. **FlowManager** - Flow aggregation, timeout management, and coordination
4. **Flow** - Individual flow representation with update capabilities
5. **NetFlowV5Key** - Unique flow identification using 5-tuple
6. **Exporter** - NetFlow v5 formatting and UDP transmission

### Flow Processing Pipeline

```
PCAP File → PcapReader → FlowManager → Flow Aggregation → Exporter → NetFlow Collector
```

### Flow Identification

Flows are uniquely identified using a 5-tuple:
- Source IP address
- Destination IP address
- Source port
- Destination port
- Protocol (TCP only)

### Timeout Management

- **Active Timeout**: Flow expires after specified time regardless of activity
- **Inactive Timeout**: Flow expires after period of inactivity
- **End of File**: Remaining flows are exported when PCAP processing completes

## Testing

The project includes Python-based testing tools:

### NetFlow Collector Test

Start the test collector:
```bash
cd tests
python3 netflowcollector.py
```

Run p2nprobe against the test collector:
```bash
./p2nprobe localhost:9995 test_data.pcap
```

### Argument Testing

```bash
cd tests
python3 test_args.py
```

## Project Structure

```
p2nprobe/
├── Makefile                 # Build configuration
├── README                   # Original documentation (Slovak)
├── manual.pdf              # Detailed technical manual
├── docs/                   # Documentation assets
│   ├── class_diagram.png   # UML class diagram
│   └── argument_tests.png  # Test results visualization
├── include/                # Header files
│   ├── ArgParser.h
│   ├── ErrorCodes.h
│   ├── Exporter.h
│   ├── Flow.h
│   ├── FlowKey.h
│   ├── FlowManager.h
│   ├── NetFlowV5header.h
│   ├── NetFlowV5Key.h
│   ├── NetFlowV5record.h
│   └── PcapReader.h
├── src/                    # Source files
│   ├── ArgParser.cpp
│   ├── Exporter.cpp
│   ├── Flow.cpp
│   ├── FlowManager.cpp
│   ├── main.cpp
│   ├── NetFlowV5Key.cpp
│   └── PcapReader.cpp
└── tests/                  # Testing tools
    ├── netflowcollector.py # NetFlow collector for testing
    ├── netflowV5format.py  # NetFlow format definitions
    ├── test_args.py        # Argument validation tests
    └── test_probe.py       # Integration tests
```

## Technical Details

### NetFlow v5 Format

The application generates NetFlow v5 packets according to [Cisco's NetFlow v5 specification](https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html).

Each NetFlow packet contains:
- **Header**: Version, count, timestamps, sequence numbers
- **Records**: Up to 30 flow records per packet

### Performance Considerations

- **Memory Efficient**: Uses iterators and smart memory management
- **Fast Lookups**: Hash map for O(1) flow finding
- **Ordered Processing**: Linked list maintains flow order
- **Batch Export**: Exports up to 30 flows per UDP packet

### Error Handling

The application includes comprehensive error handling for:
- Invalid command-line arguments
- PCAP file access issues
- Network connectivity problems
- Malformed packets
- Memory allocation failures

## Troubleshooting

### Common Issues

**"Error opening PCAP file"**
- Check file path and permissions
- Ensure PCAP file is valid and not corrupted

**"Error connecting to collector"**
- Verify collector IP address and port
- Check network connectivity
- Ensure collector is listening on specified port

**"No packets processed"**
- Verify PCAP contains TCP traffic
- Check if PCAP file is empty

### Debug Mode

For verbose output, you can modify the source code to enable debug logging or use system tools:

```bash
# Monitor network traffic
sudo tcpdump -i lo port 9995

# Check system logs
journalctl -f
```

## References

- [NetFlow v5 Format Specification](https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html)
- [libpcap Documentation](https://www.tcpdump.org/pcap.html)
- [NetFlow Overview](https://en.wikipedia.org/wiki/NetFlow)

## Author

**Michal Balogh** (xbalog06)
Created: October 2024
