
#include <pcap.h>

#include "logger.h"
#include "pkt_ethernet.h"

void pkt_ethernet::register_number() {

	pkt_factory::register_number(pkt_factory::type::dlt, DLT_EN10MB, factory);

}

pkt::parse_result pkt_ethernet::parse() {
	

	// Byte 0-5 : daddr
	field_dst_.set_value(*buf_, 0);

	// Byte 6-11: saddr
	field_src_.set_value(*buf_, 6);

	// Byte 12-13 : ether type
	field_type_.set_value(*buf_, 12);



	LOG_DEBUG << "ethernet : " << field_src_.print() << " -> " << field_dst_.print() << " | type: " << field_type_.print();


	pkt_buffer_ptr buf(new pkt_buffer_part(buf_, ETHERNET_HEADER_LEN));

	pkt *p = pkt_factory::factory(pkt_factory::type::ethernet, field_type_.get_value(), buf, self_, executor_);

	if (p) {
		p->process();
	}

	return ok;
}
