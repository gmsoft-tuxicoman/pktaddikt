
#include <arpa/inet.h>

#include "ptype_ipv4.h"
#include "logger.h"

ptype_ipv4::ptype_ipv4() : ptype("ipv4") {};

ptype_ipv4::ptype_ipv4(const std::string& val) : ptype("ipv4") {
	if (!this->parse(val))
		LOG_WARN << "Error while parsing ptype ipv4 default value";

};

bool ptype_ipv4::parse(const std::string& val) {

	if (inet_pton(AF_INET, val.c_str(), &ip_) == 1) {
		return true;
	}
	return false;
}


const std::string ptype_ipv4::print() const {
	
	std::string res(inet_ntoa(ip_));
	return res;
}

void ptype_ipv4::set_value(pkt_buffer &buf, std::size_t offset) {

	 buf.read(&ip_, offset, sizeof(in_addr));
}
