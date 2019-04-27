
#include <iostream>

#include "ptype_string.h"

ptype_string::ptype_string() : ptype("string") {};
ptype_string::ptype_string(const ptype_string &p) : ptype("string") { value_ = p.value_; };
ptype_string::ptype_string(const std::string& val) : ptype("string") {
	if (!this->parse(val))
		std::cout << "Error while parsing ptype default value" << std::endl;

}

bool ptype_string::parse(const std::string& val) {

	value_ = val;
	return true;
}


const std::string ptype_string::print() {
	return value_;
}

