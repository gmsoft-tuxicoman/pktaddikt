
add_library(input
	input.cpp input.h
	input_pcap.cpp input_pcap.h
	)

target_link_libraries(input pcap)
