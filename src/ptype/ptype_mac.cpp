
#include <iostream>
#include <sstream>

#include "ptype_mac.h"

ptype_mac::ptype_mac() : ptype("mac") {};

ptype_mac::ptype_mac(const std::string& val) : ptype("mac") {
	if (!this->parse(val))
		std::cout << "Error while parsing ptype mac default value" << std::endl;

};

bool ptype_mac::parse(const std::string& val) {


	if (sscanf(val.c_str(), "%hhX:%hhX:%hhX:%hhX:%hhX:%hhX", value_, value_ + 1, value_ + 2, value_ + 3, value_ + 4, value_ + 5) == 6) {
		return true;
	}

	return true;
}


const std::string ptype_mac::print() {

	std::ostringstream stream;
	stream << std::hex << value_[0] << ":" << value_[1] << ":" << value_[2] << ":" << value_[3] << ":" << value_[4] << ":" << value_[5];
	return stream.str();
}

