
#include <pcap.h>

#include <arpa/inet.h>
#include "proto_ethernet.h"

#include "pkt/pkt.h"
#include "logger.h"

proto_ethernet::proto_ethernet(): proto("ethernet") { 

	register_number(dlt, DLT_EN10MB, this);
}

void proto_ethernet::parse_pre_session() {

	pkt_buffer *buf = pkt_->get_buffer();

	// Byte 0-5 : daddr
	field_dst_.set_value(buf, 0);

	// Byte 6-11: saddr
	field_src_.set_value(buf, 6);

	// Byte 12-13 : ether type
	uint16_t ether_type = buf->read_ntoh16(12);
	field_type_.set_value(ether_type);

	buf->consume(14);

	pkt_->add_proto(proto::number_type::ethernet, ether_type);

	LOG_DEBUG << "ethernet : " << field_src_.print() << " -> " << field_dst_.print() << " | type: " << field_type_.print();

	this->parse_status_ = ok;

}
