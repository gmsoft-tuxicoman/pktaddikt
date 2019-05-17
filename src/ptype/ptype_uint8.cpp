
#include <algorithm>
#include <cctype>
#include <iostream>

#include "ptype_uint8.h"

ptype_uint8::ptype_uint8() : ptype("uint8") {};
ptype_uint8::ptype_uint8(const std::string& val) : ptype("uint8") {
	if (!this->parse(val))
		std::cout << "Error while parsing ptype uint8 default value" << std::endl;

};

bool ptype_uint8::parse(const std::string& val) {

	int res = 0;
	try {
		res = std::stoi(val);
	} catch (...) {
		return false;
	}

	if (res > UINT8_MAX) {
		return false;
	}

	value_ = res;

	return true;
}


const std::string ptype_uint8::print() {

	return std::to_string(value_);
}

void ptype_uint8::set_value(pkt_buffer *buf, std::size_t offset) {

	value_ = buf->read_8(offset);

}
