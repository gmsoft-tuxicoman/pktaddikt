
target_sources(pktaddikt PRIVATE
	input.cpp input.h
	input_pcap.cpp input_pcap.h
	)

target_link_libraries(pktaddikt pcap)
