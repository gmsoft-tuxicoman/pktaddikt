
add_executable(pktaddikt main.cpp application.cpp application.h)


include_directories(httpd)
add_subdirectory(httpd)
target_link_libraries(pktaddikt httpd)

include_directories(registry)
add_subdirectory(registry)
target_link_libraries(pktaddikt registry)

find_package(PkgConfig REQUIRED)
pkg_check_modules(YAMLCPP REQUIRED yaml-cpp)


target_include_directories(pktaddikt PUBLIC ${YAMLCPP_INCLUDE_DIRS})
target_link_libraries(pktaddikt ${YAMLCPP_LIBRARIES})
