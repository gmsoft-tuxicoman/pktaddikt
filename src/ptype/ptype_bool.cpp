
#include <algorithm>
#include <cctype>
#include <iostream>

#include "ptype_bool.h"

ptype_bool::ptype_bool() : type_name_("bool") {};
ptype_bool::ptype_bool(const ptype_bool &p) { value_ = p.value_; };
ptype_bool::ptype_bool(const std::string& val) : type_name_("bool") {
	if (!this->parse(val))
		std::cout << "Error while parsing ptype default value" << std::endl;

};

bool ptype_bool::parse(const std::string& val) {

	std::string s = val;
	std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return std::tolower(c); });

	if (s == "yes" || s == "true" || s == "on" || s == "1") {
		value_ = true;
	} else if (s == "no" || s == "false" || s == "off" || s == "0") {
		value_ = false;
	} else {
		return false;
	}

	return true;
}


const std::string ptype_bool::print() {
	if (value_)
		return "yes";

	return "no";
}

