
#include <iostream>

#include "ptype_string.h"

ptype_string::ptype_string() : type_name_("string") {};
ptype_string::ptype_string(const ptype_string &p) { value_ = p.value_; };
ptype_string::ptype_string(const std::string& val) : type_name_("string") {
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

