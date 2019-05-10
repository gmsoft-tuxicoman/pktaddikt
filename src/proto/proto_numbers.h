#ifndef __PROTO_NUMBERS_H__
#define __PROTO_NUMBERS_H__

#include <vector>
#include <cassert>


class proto;

using proto_numbers_vector = std::vector<std::pair<unsigned int, proto*>>;

class proto_numbers {

	public:
		enum number_type { dlt, ip, PROTO_NUMBER_TYPE_COUNT};

		void register_number(number_type type, unsigned int id, proto *proto);
		proto* get_proto(number_type type, unsigned int id);


	protected:
		static proto_numbers_vector numbers_[PROTO_NUMBER_TYPE_COUNT];
};

#endif
