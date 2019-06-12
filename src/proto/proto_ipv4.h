#ifndef __PROTO_IPV4_H__
#define __PROTO_IPV4_H__

#include "proto.h"
#include "proto_session.h"

#include "ptype/ptype_ipv4.h"
#include "ptype/ptype_uint8.h"


class proto_ipv4_session {

	public:
		int some_value;
};

using proto_ipv4_session_both = proto_session_both<ptype_ipv4, proto_ipv4_session>;

class proto_ipv4 : public proto, public proto_ipv4_session_both {

	public:
		static void register_number();

		proto_ipv4(pkt *pkt, task_executor_ptr executor): proto(pkt, parse_flag_pre | parse_flag_fetch, executor), proto_session_both(field_src_, field_dst_, sessions_, executor) {};

		static proto* factory(pkt *pkt, task_executor_ptr executor) { return new proto_ipv4(pkt, executor); };

		void parse_pre_session();
		void parse_fetch_session(pa_task fetch_session_done) { this->fetch_session(fetch_session_done); };
		void parse_in_session();
		
		enum fields_id { src, dst, protocol, tos, ttl };

		static proto_ipv4_session_both::proto_session_list sessions_;

	protected:

		ptype_ipv4 field_src_;
		ptype_ipv4 field_dst_;
		ptype_uint8 field_proto_;
		ptype_uint8 field_tos_;
		ptype_uint8 field_ttl_;

		proto_fields fields_ = {
			{ "src", &field_src_ },
			{ "dst", &field_dst_ },
			{ "proto", &field_proto_ },
			{ "tos", &field_tos_ },
			{ "ttl", &field_ttl_ } };


};


#endif
