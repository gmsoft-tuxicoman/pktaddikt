
#include <algorithm>
#include <cctype>

#include "ptype_uint16.h"
#include "logger.h"

ptype_uint16::ptype_uint16() : ptype("uint16") {};
ptype_uint16::ptype_uint16(const std::string& val) : ptype("uint16") {
	if (!this->parse(val))
		LOG_WARN << "Error while parsing ptype uint16 default value";

};

bool ptype_uint16::parse(const std::string& val) {

	int res = 0;
	try {
		res = std::stoi(val);
	} catch (...) {
		return false;
	}

	if (res > UINT16_MAX) {
		return false;
	}

	value_ = res;

	return true;
}


const std::string ptype_uint16::print() const {

	return std::to_string(value_);
}

void ptype_uint16::set_value(pkt_buffer *buf, std::size_t offset) {
	buf->read_ntoh16(offset);
}
