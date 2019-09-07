

#include "proto_udp.h"
#include "pkt/pkt.h"
#include "logger.h"

#include <arpa/inet.h>


void proto_udp::register_number() {

	proto_number().register_number(proto_number::type::ip, IPPROTO_UDP, proto_udp::factory);

}

void proto_udp::parse_pre_session() {

	pkt_buffer *buf = pkt_->get_buffer();

	// Byte 0-1 : source
	field_sport_.set_value(buf, 0);

	// Byte 2-3 : destination
	field_dport_.set_value(buf, 2);

	// Byte 4-5 : length
	uint16_t len = buf->read_ntoh16(4);

	// Crop the packet to provided total length
	buf->set_remaining(len);

	// Bytes 6-7 : checksum
	
	// Rremove header from buffer
	buf->consume(8);

	pkt_->add_proto(proto_number::type::udp, field_dport_.get_value());

}



void proto_udp::parse_fetch_session(pa_task fetch_session_done) {

	if (parent_.get() == nullptr) {
		parent_.reset(new conntrack_udp_entry(executor_));
		LOG_DEBUG << "New conntrack table initiated for udp";
	}

	// This is ugly, please help me !
	conntrack_udp_entry *table = static_cast<conntrack_udp_entry*>(parent_.get());

	conntrack_ = table->get_child(std::make_pair(field_sport_, field_dport_));

	fetch_session_done();

}
