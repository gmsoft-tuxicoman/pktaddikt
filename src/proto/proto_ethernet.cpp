
#include <pcap.h>

#include "proto_ethernet.h"

#include "proto_numbers.h"

#include <iostream>

proto_ethernet::proto_ethernet(): proto("ethernet") { 

	proto_numbers proto_numbers_dlt;
	proto_numbers_dlt.register_number(proto_numbers::number_type::dlt, DLT_EN10MB, this);


}

proto_ethernet::proto_ethernet(pkt* pkt): proto(pkt) {

	fields_[fields_id::src].second = new ptype_mac();
	fields_[fields_id::dst].second = new ptype_mac();
	fields_[fields_id::type].second = new ptype_uint16();
}


void proto_ethernet::parse() {

	std::cout << "PARSING ETHERNET PACKET !!!" << std::endl;
}
