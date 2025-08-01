# Author: Michal Balogh, xbalog06
# Project: PcapNetflowV5exporter
# Date: 14-10-2024

CXX = g++
CXXFLAGS = -Wall -Wextra -Wpedantic -std=c++17 -Iinclude -MMD -MP
CXXFLAGS_DEBUG = $(CXXFLAGS) -g -O0 -DDEBUG
CXXFLAGS_RELEASE = $(CXXFLAGS) -O2 -DNDEBUG
LDFLAGS = -lpcap
SRC_DIR = src
BUILD_DIR = build
SRC = $(wildcard $(SRC_DIR)/*.cpp)
OBJS = $(patsubst $(SRC_DIR)/%.cpp,$(BUILD_DIR)/%.o,$(SRC))
DEPS = $(OBJS:.o=.d)

TARGET = p2nprobe

# Default build type
BUILD_TYPE ?= release

.PHONY: all clean run debug release install help

all: $(TARGET)

# Debug build
debug: BUILD_TYPE = debug
debug: CXXFLAGS_USED = $(CXXFLAGS_DEBUG)
debug: $(TARGET)

# Release build (default)
release: BUILD_TYPE = release
release: CXXFLAGS_USED = $(CXXFLAGS_RELEASE)
release: $(TARGET)

# Default uses release flags
CXXFLAGS_USED ?= $(CXXFLAGS_RELEASE)

$(TARGET): $(OBJS)
	@echo "Linking $(TARGET) ($(BUILD_TYPE) mode)..."
	$(CXX) $(CXXFLAGS_USED) -o $@ $^ $(LDFLAGS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(BUILD_DIR)
	@echo "Compiling $< ($(BUILD_TYPE) mode)..."
	$(CXX) $(CXXFLAGS_USED) -c $< -o $@

-include $(DEPS)

clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR) $(TARGET)

# Install to system (requires sudo)
install: $(TARGET)
	@echo "Installing $(TARGET) to /usr/local/bin..."
	sudo cp $(TARGET) /usr/local/bin/
	sudo chmod +x /usr/local/bin/$(TARGET)

# Run with default parameters (for testing)
run: $(TARGET)
	./$(TARGET) localhost:2055 ../my_pcap.pcap

# Display help
help:
	@echo "Available targets:"
	@echo "  all      - Build the project (default: release mode)"
	@echo "  debug    - Build with debug flags (-g -O0)"
	@echo "  release  - Build with optimization (-O2)"
	@echo "  clean    - Remove build artifacts"
	@echo "  install  - Install to /usr/local/bin (requires sudo)"
	@echo "  run      - Build and run with test parameters"
	@echo "  help     - Show this help message"
	@echo ""
	@echo "Build types can be controlled with BUILD_TYPE variable:"
	@echo "  make BUILD_TYPE=debug"
	@echo "  make BUILD_TYPE=release"
