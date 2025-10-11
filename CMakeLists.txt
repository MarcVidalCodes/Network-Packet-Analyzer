cmake_minimum_required(VERSION 3.14)
project(NetGuard VERSION 1.0 LANGUAGES CXX)

# C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include directories
include_directories(include)

# Find libpcap
find_library(PCAP_LIBRARY pcap REQUIRED)

# Source files
set(SOURCES
    src/main.cpp
)

# Executable
add_executable(netguard ${SOURCES})

# Link libpcap
target_link_libraries(netguard ${PCAP_LIBRARY})

# Enable testing
enable_testing()