
#include <iostream>
#include <iomanip>
#include <sstream>

#include <arpa/inet.h>

#include "ptype_ipv4.h"

ptype_ipv4::ptype_ipv4() : ptype("ipv4") {};

ptype_ipv4::ptype_ipv4(const std::string& val) : ptype("ipv4") {
	if (!this->parse(val))
		std::cout << "Error while parsing ptype ipv4 default value" << std::endl;

};

bool ptype_ipv4::parse(const std::string& val) {

	if (inet_pton(AF_INET, val.c_str(), &ip_) == 1) {
		return true;
	}
	return false;
}


const std::string ptype_ipv4::print() {
	
	std::string res(inet_ntoa(ip_));
	return res;
}

void ptype_ipv4::set_value(pkt_buffer *buf) {

	const unsigned char *value = buf->read(sizeof(in_addr));

	memcpy(&ip_, value, sizeof(in_addr));
}
