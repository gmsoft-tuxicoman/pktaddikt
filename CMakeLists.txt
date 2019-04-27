
cmake_minimum_required(VERSION 3.9)
project(pktaddikt)
set(PKTADDIKT_VERSION 0.0.0)

configure_file(src/config.h.in src/config.h)

set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -std=c++17")

add_subdirectory(src)
