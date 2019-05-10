
cmake_minimum_required(VERSION 3.13)
project(pktaddikt)
set(PKTADDIKT_VERSION 0.0.0)

configure_file(src/config.h.in src/config.h)

set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -std=c++17 -pipe")
set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -DRAPIDJSON_HAS_STDSTRING=1")

set(CMAKE_CXX_FLAGS_DEBUG "-O0 -ggdb3 -D__DEBUG__")

add_subdirectory(src)
