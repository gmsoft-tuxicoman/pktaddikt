
#include <iomanip>
#include <sstream>

#include "ptype_mac.h"
#include "logger.h"

ptype_mac::ptype_mac() : ptype("mac") {};

ptype_mac::ptype_mac(const std::string& val) : ptype("mac") {
	if (!this->parse(val))
		LOG_WARN << "Error while parsing ptype mac default value";

};

bool ptype_mac::parse(const std::string& val) {


	if (sscanf(val.c_str(), "%hhX:%hhX:%hhX:%hhX:%hhX:%hhX", value_, value_ + 1, value_ + 2, value_ + 3, value_ + 4, value_ + 5) == 6) {
		return true;
	}

	return true;
}


const std::string ptype_mac::print() const {

	std::ostringstream stream;
	stream << std::setfill('0') << std::right << std::setw(2) << std::hex << (int)value_[0] << ":" << (int)value_[1] << ":" << (int)value_[2] << ":" << (int)value_[3] << ":" << (int)value_[4] << ":" << (int)value_[5];
	return stream.str();
}

void ptype_mac::set_value(pkt_buffer *buf, std::size_t offset) {

	buf->read(value_, offset, 6);
}
