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

# Main executable
add_executable(netguard 
    src/main.cpp
    src/cli.cpp
)
target_link_libraries(netguard ${PCAP_LIBRARY})

# Install target
install(TARGETS netguard DESTINATION bin)

# Testing
enable_testing()

# Fetch Google Test
include(FetchContent)
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG v1.14.0
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# Test executable
add_executable(netguard_tests
    src/tests/test_cli.cpp
    src/cli.cpp
)

target_link_libraries(netguard_tests
    GTest::gtest_main
    ${PCAP_LIBRARY}
)

include(GoogleTest)
gtest_discover_tests(netguard_tests)