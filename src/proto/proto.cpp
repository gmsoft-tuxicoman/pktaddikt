
#include <cassert>

#include "proto.h"


proto_numbers_vector proto::numbers_[PROTO_NUMBER_TYPE_COUNT];

void proto::register_number(number_type type, unsigned int id, proto *proto) {
	assert(type <= PROTO_NUMBER_TYPE_COUNT);
	numbers_[type].push_back({id, proto});
}

proto* proto::get_proto(number_type type, unsigned int id) {

	for (auto const& num : numbers_[type]) {
		if (num.first == id) {
			return num.second;
		}
	}

	return nullptr;
}

void proto::parse() {

	if (parse_flags_ & parse_flag_pre) {
		try {
			parse_pre_session();
		} catch (const std::out_of_range& e) {
			parse_status_ = invalid;
		}

		if (parse_status_ > ok) {
			return;
		}
	}

}
