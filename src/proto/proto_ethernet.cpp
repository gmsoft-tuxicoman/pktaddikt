
#include <pcap.h>

#include <arpa/inet.h>
#include "proto_ethernet.h"

#include "proto_numbers.h"

#include "pkt/pkt.h"

#include <iostream>

proto_ethernet::proto_ethernet(): proto("ethernet") { 

	proto_numbers proto_numbers_dlt;
	proto_numbers_dlt.register_number(proto_numbers::number_type::dlt, DLT_EN10MB, this);


}

void proto_ethernet::parse() {

	pkt_buffer *buf = pkt_->get_buffer();

	fields_[fields_id::dst].second->set_value(buf);
	fields_[fields_id::src].second->set_value(buf);
	fields_[fields_id::type].second->set_value(buf);


	std::cout << "ethernet : " << fields_[fields_id::src].second->print() << " -> " << fields_[fields_id::dst].second->print() << " | type: " << fields_[fields_id::type].second->print() << std::endl;
}
