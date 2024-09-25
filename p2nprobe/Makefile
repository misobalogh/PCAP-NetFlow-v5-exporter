CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++11 -Iinclude
LDFLAGS = -lpcap
SRC = src/main.cpp src/ArgParser.cpp src/PcapReader.cpp

TARGET = p2nprobe

.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(SRC:.cpp=.o)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

src/%.o: src/%.cpp include/ArgParser.h include/ErrorCodes.h include/PcapReader.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) src/*.o

run: $(TARGET)
	./$(TARGET) localhost:2055 ../my_pcap.pcap

