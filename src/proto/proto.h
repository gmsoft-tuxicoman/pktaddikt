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

		enum parse_status { todo, ok, stop, invalid, error};
		parse_status get_parse_status() { return parse_status_; };

		void parse();

		virtual void parse_pre_session() {};
		virtual void parse_fetch_session() {};
		virtual void parse_in_session() {};

		enum number_type { dlt, ethernet, ip, ppp, PROTO_NUMBER_TYPE_COUNT};
		void register_number(number_type type, unsigned int id, proto *proto);
		static proto* get_proto(number_type type, unsigned int id);

	protected:
		proto(pkt* pkt, unsigned int parse_flags): pkt_(pkt), parse_flags_(parse_flags) {};
		proto(std::string name): name_(name) {};

		std::string name_;
		pkt *pkt_;

		proto_fields fields_;

		static const unsigned int parse_flag_pre = 1;
		static const unsigned int parse_flag_fetch = 2;
		static const unsigned int parse_flag_in = 4;
		static const unsigned int parse_flag_post = 8;

		unsigned int parse_flags_ = 0;


		parse_status parse_status_ = todo;


		static proto_numbers_vector numbers_[PROTO_NUMBER_TYPE_COUNT];

};

#endif
