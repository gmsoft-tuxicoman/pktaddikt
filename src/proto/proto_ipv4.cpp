
#include <pcap.h>

#include <arpa/inet.h>
#include "proto_ipv4.h"

#include "pkt/pkt.h"
#include "logger.h"

proto_ipv4::proto_ipv4(): proto("ipv4") { 

	register_number(dlt, DLT_RAW, this);
	register_number(dlt, DLT_IPV4, this);
	register_number(ethernet, 0x800, this);
	register_number(ip, IPPROTO_IPIP, this);
	register_number(ppp, 0x21, this);
}

void proto_ipv4::parse_pre_session() {

	pkt_buffer *buf = pkt_->get_buffer();

	// Byte 0 : version | ihl
	uint8_t version = buf->read_bits8(0, 4);
	uint8_t ihl = buf->read_bits8(4, 4) * 4;

	if (ihl < 5) { // Minimum header length is 5 bytes
		parse_status_ = invalid;
		return;
	}

	// Byte 1: TOS
	field_tos_.set_value(buf, 1);

	// Byte 2-3 : tot_len
	uint16_t tot_len = buf->read_ntoh16(2);
	if (tot_len < buf->remaining()) { // packet lenght larger than remaining bytes
		parse_status_ = invalid;
		return;
	}

	if (tot_len < ihl) { // total length smaller than header length
		parse_status_ = invalid;
		return;
	}

	// Crop the packet to provided total length
	buf->set_remaining(tot_len);
	
	// Byte 4-5 : id
	
	// Byte 6-7: frag_off
	
	// Byte 8: ttl
	field_ttl_.set_value(buf, 8);

	// Byte 9 : protocol
	uint8_t ip_proto = buf->read_8(9);
	field_proto_.set_value(ip_proto);

	// Byte 10-11 : checksum

	// Byte 12-15 : saddr
	field_dst_.set_value(buf, 12);

	// Byte 16-19 : daddr
	field_src_.set_value(buf, 16);

	pkt_->add_proto(proto::number_type::ip, ip_proto);

	LOG_DEBUG << "ipv4 : " << field_src_.print() << " -> " << field_dst_.print() << " | proto: " << field_proto_.print();
}

void proto_ipv4::parse_fetch_session() {


}

void proto_ipv4::parse_in_session() {


}
