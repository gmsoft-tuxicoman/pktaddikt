
#include "ptype_string.h"
#include "logger.h"

ptype_string::ptype_string() : ptype("string") {};
ptype_string::ptype_string(const std::string& val) : ptype("string") {
	if (!this->parse(val))
		LOG_WARN << "Error while parsing ptype default value";
}

bool ptype_string::parse(const std::string& val) {

	value_ = val;
	return true;
}


const std::string ptype_string::print() const {
	return value_;
}

