cmake_minimum_required(VERSION 3.10)

project(ptchat VERSION 1.0)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED True)

include_directories(cbinc)

add_executable(ptchat main.c)
if (CMAKE_BUILD_TYPE MATCHES Debug)
    add_definitions(-DDEBUG)
endif()

# output directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Compiler warnings
if (CMAKE_C_COMPILER_ID MATCHES GNU|Clang)
    add_definitions(-Wall -Wextra )
endif()

install(TARGETS ptchat DESTINATION bin)
