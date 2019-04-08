
include_directories(httpd)
add_subdirectory(httpd)

add_executable(pktaddikt main.cpp core.cpp core.h)

target_link_libraries(pktaddikt httpd)
