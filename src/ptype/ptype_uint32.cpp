
#include <algorithm>
#include <cctype>

#include "ptype_uint32.h"
#include "logger.h"

ptype_uint32::ptype_uint32() : ptype("uint32") {};
ptype_uint32::ptype_uint32(const std::string& val) : ptype("uint32") {
	if (!this->parse(val))
		LOG_WARN << "Error while parsing ptype uint32 default value";

};

bool ptype_uint32::parse(const std::string& val) {

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


const std::string ptype_uint32::print() const {

	return std::to_string(value_);
}

void ptype_uint32::set_value(pkt_buffer &buf, std::size_t offset) {
	value_ = buf.read_ntoh16(offset);
}
