
add_executable(pktaddikt main.cpp application.cpp application.h)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})


add_subdirectory(common)
target_link_libraries(pktaddikt common)

add_subdirectory(httpd)
target_link_libraries(pktaddikt httpd)

add_subdirectory(input)
target_link_libraries(pktaddikt input)

add_subdirectory(pkt)
target_link_libraries(pktaddikt pkt)

add_subdirectory(proto)
target_link_libraries(pktaddikt proto)

add_subdirectory(ptype)
target_link_libraries(pktaddikt ptype)

add_subdirectory(tasks)
target_link_libraries(pktaddikt tasks)

find_package(Threads REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_check_modules(YAMLCPP REQUIRED yaml-cpp)

target_include_directories(pktaddikt PUBLIC ${YAMLCPP_INCLUDE_DIRS})
target_link_libraries(pktaddikt ${CMAKE_THREAD_LIBS_INIT} ${YAMLCPP_LIBRARIES})
