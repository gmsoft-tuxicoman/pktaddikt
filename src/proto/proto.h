#ifndef __PROTO_H__
#define __PROTO_H__

#include <vector>
#include <functional>
#include <map>
#include "ptype/ptype.h"

class pkt;
class proto;
using proto_fields = std::vector<std::pair<std::string, ptype*>>;
using proto_factory = std::function<proto*(pkt*)>;

class proto {

	public:
		proto(pkt* pkt, unsigned int parse_flags): pkt_(pkt), parse_flags_(parse_flags) {};

		enum parse_status { todo, ok, stop, invalid, error};
		parse_status get_parse_status() { return parse_status_; };

		void parse();

		virtual void parse_pre_session() {};
		virtual void parse_fetch_session() {};
		virtual void parse_in_session() {};


	protected:

		pkt *pkt_;

		proto_fields fields_;

		static const unsigned int parse_flag_pre = 1;
		static const unsigned int parse_flag_fetch = 2;
		static const unsigned int parse_flag_in = 4;
		static const unsigned int parse_flag_post = 8;

		unsigned int parse_flags_ = 0;


		parse_status parse_status_ = todo;



};

using proto_numbers_vector = std::vector<std::pair<unsigned int, proto_factory>>;

class proto_number {

	public:
		enum type { dlt, ethernet, ip, ppp, PROTO_NUMBER_TYPE_COUNT};

		void register_number(type type, unsigned int id, proto_factory f);
		static proto* get_proto(type type, unsigned int id, pkt *pkt);

	protected:
		static proto_numbers_vector numbers_[PROTO_NUMBER_TYPE_COUNT];

};

#endif
