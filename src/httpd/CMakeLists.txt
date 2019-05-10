
find_package(PkgConfig REQUIRED)
pkg_check_modules(MICROHTTPD REQUIRED libmicrohttpd)

target_sources(pktaddikt PRIVATE
		httpd.cpp httpd.h
		http_exception.h
		)

target_link_libraries(pktaddikt ${MICROHTTPD_LIBRARIES})
