
#include <pcap.h>

#include "pkt_ipv4.h"
#include "logger.h"

void pkt_ipv4::register_number() {

	pkt_factory::register_number(pkt_factory::type::dlt, DLT_RAW, factory);
	pkt_factory::register_number(pkt_factory::type::dlt, DLT_IPV4, factory);
	pkt_factory::register_number(pkt_factory::type::ethernet, 0x800, factory);
	pkt_factory::register_number(pkt_factory::type::ip, IPPROTO_IPIP, factory);
	pkt_factory::register_number(pkt_factory::type::ppp, 0x21, factory);
}


pkt::parse_result pkt_ipv4::parse() {

	uint8_t version = buf_->read_bits8(0, 4);
	uint8_t ihl = buf_->read_bits8(4, 4) * 4;

	if (ihl < 5) { // Minimum header length is 5 bytes
		return invalid;
	}

	// Byte 1: TOS
	field_tos_.set_value(*buf_, 1);

	// Byte 2-3 : tot_len
	uint16_t tot_len = buf_->read_ntoh16(2);

	if (tot_len < ihl) { // total length smaller than header length
		return invalid;
	}

	// Byte 4-5 : id
	
	// Byte 6-7: frag_off
	
	// Byte 8: ttl
	field_ttl_.set_value(*buf_, 8);

	// Byte 9 : protocol
	field_proto_.set_value(*buf_, 9);

	// Byte 10-11 : checksum
	
	// Byte 12-15 : saddr
	field_dst_.set_value(*buf_, 12);

	// Byte 16-19 : daddr
	field_src_.set_value(*buf_, 16);

	// FIXME take care of IP options
	
	LOG_DEBUG << "ipv4 : " << field_src_.print() << " -> " << field_dst_.print() << " | proto: " << field_proto_.print();

	pkt_buffer_ptr buf(new pkt_buffer_part(buf_, ihl, tot_len - ihl));


	pkt *p = pkt_factory::factory(pkt_factory::type::ip, field_proto_.get_value(), buf, self_, executor_);

	if (p) {
		p->process();
	}

	return ok;
}
