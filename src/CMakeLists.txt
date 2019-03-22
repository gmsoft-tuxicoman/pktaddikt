
include_directories(httpd)
add_subdirectory(httpd)

add_executable(pktaddikt main.cpp)

target_link_libraries(pktaddikt httpd)
