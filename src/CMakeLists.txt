
add_executable(pktaddikt main.cpp application.cpp application.h logger.cpp
	logger.h logger_def.h)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})


add_subdirectory(common)
add_subdirectory(httpd)
add_subdirectory(input)
add_subdirectory(pkt)
add_subdirectory(proto)
add_subdirectory(ptype)
add_subdirectory(tasks)

find_package(Threads REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_check_modules(YAMLCPP REQUIRED yaml-cpp)

target_include_directories(pktaddikt PUBLIC ${YAMLCPP_INCLUDE_DIRS})
target_link_libraries(pktaddikt ${CMAKE_THREAD_LIBS_INIT} ${YAMLCPP_LIBRARIES})
