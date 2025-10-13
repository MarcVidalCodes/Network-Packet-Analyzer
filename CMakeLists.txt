cmake_minimum_required(VERSION 3.14)
project(NetGuard VERSION 0.1.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler flags
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Find libpcap
find_path(PCAP_INCLUDE_DIR pcap.h)
find_library(PCAP_LIBRARY pcap)

if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
    message(FATAL_ERROR "libpcap not found. Please install it (brew install libpcap on macOS)")
endif()

# Include directories
include_directories(${PCAP_INCLUDE_DIR})

# Source files
set(SOURCES
    src/main.cpp
)

# Create executable
add_executable(netguard ${SOURCES})

# Link libraries
target_link_libraries(netguard ${PCAP_LIBRARY})

# Install target
install(TARGETS netguard DESTINATION bin)