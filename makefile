CXX = g++
CXXFLAGS = -std=c++11 -Wall -O2
LIBS = -lpcap -pthread

TARGET = beacon-flood
SRCS = beacon_flood.cpp utils.cpp

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRCS) $(LIBS)

clean:
	rm -f $(TARGET)
