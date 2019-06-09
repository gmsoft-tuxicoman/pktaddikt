
#include <cassert>

#include "proto.h"


proto_numbers_vector proto_number::numbers_[PROTO_NUMBER_TYPE_COUNT];

void proto_number::register_number(type type, unsigned int id, proto_factory f) {
	assert(type <= PROTO_NUMBER_TYPE_COUNT);
	numbers_[type].push_back({id, f});
}

proto* proto_number::get_proto(type type, unsigned int id, pkt *pkt) {

	for (auto const& num : numbers_[type]) {
		if (num.first == id) {
			return num.second(pkt);
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
