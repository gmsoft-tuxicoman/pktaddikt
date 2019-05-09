
#include <algorithm>
#include <cctype>
#include <iostream>

#include "ptype_uint16.h"

ptype_uint16::ptype_uint16() : ptype("uint16") {};
ptype_uint16::ptype_uint16(const std::string& val) : ptype("uint16") {
	if (!this->parse(val))
		std::cout << "Error while parsing ptype uint16 default value" << std::endl;

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


const std::string ptype_uint16::print() {

	return std::to_string(value_);
}

