CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++11 -Iinclude
SRC = src/main.cpp src/ArgParser.cpp

TARGET = p2nprobe

all: $(TARGET)

$(TARGET): $(SRC:.cpp=.o)
	$(CXX) $(CXXFLAGS) -o $@ $^

src/%.o: src/%.cpp include/ArgParser.h include/ErrorCodes.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) src/*.o

run: $(TARGET)
	./$(TARGET) localhost:2055 my_pcap_file.pcap

.PHONY: all clean run
