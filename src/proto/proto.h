#ifndef __PROTO_H__
#define __PROTO_H__

#include <vector>
#include <map>
#include "ptype/ptype.h"

class proto;

using proto_fields = std::vector<std::pair<std::string, ptype*>>;
using proto_numbers_vector = std::vector<std::pair<unsigned int, proto*>>;

class pkt;
class proto {

	public:
		virtual ~proto() {};

		virtual proto* factory(pkt *pkt) = 0;
		virtual void parse() = 0;

		enum number_type { dlt, ethernet, ip, ppp, PROTO_NUMBER_TYPE_COUNT};
		void register_number(number_type type, unsigned int id, proto *proto);
		static proto* get_proto(number_type type, unsigned int id);

	protected:
		proto(pkt* pkt): pkt_(pkt) {};
		proto(std::string name): name_(name) {};

		std::string name_;
		pkt *pkt_;

		proto_fields fields_;


		static proto_numbers_vector numbers_[PROTO_NUMBER_TYPE_COUNT];

};

#endif
