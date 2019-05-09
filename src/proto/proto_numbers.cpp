
#include "proto_numbers.h"

proto_numbers_vector proto_numbers::numbers_[PROTO_NUMBER_TYPE_COUNT];

void proto_numbers::register_number(number_type type, unsigned int id, proto *proto) {
	assert(type <= PROTO_NUMBER_TYPE_COUNT);
	numbers_[type].push_back({id, proto});
}

proto* proto_numbers::get_proto(number_type type, unsigned int id) {

	for (auto const& num : numbers_[type]) {
		if (num.first == id) {
			return num.second;
		}
	}

	return nullptr;
}
