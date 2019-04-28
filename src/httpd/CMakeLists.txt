
find_package(PkgConfig REQUIRED)
pkg_check_modules(MICROHTTPD REQUIRED libmicrohttpd)

add_library(httpd
		httpd.cpp httpd.h
		http_exception.h
		)

target_link_libraries(httpd ${MICROHTTPD_LIBRARIES})
