#ifndef __PKT_IPV4_H__
#define __PKT_IPV4_H__

#include "pkt/pkt.h"
#include "pkt/pkt_factory.h"

#include "ptype/ptype_ipv4.h"
#include "ptype/ptype_uint8.h"

class pkt_ipv4 : public pkt {

	public:
		pkt_ipv4(pkt_buffer_ptr buf, pkt_ptr parent, task_executor_ptr executor) : pkt(buf, parent, executor) {};

		static pkt* factory(pkt_buffer_ptr buf, pkt_ptr parent, task_executor_ptr executor) { return new pkt_ipv4(buf, parent, executor); };

		static void register_number();


	protected:
		
		parse_result parse();

		ptype_ipv4 field_src_;
		ptype_ipv4 field_dst_;
		ptype_uint8 field_proto_;
		ptype_uint8 field_tos_;
		ptype_uint8 field_ttl_;

		pkt_fields fields_ = {
			{ "src", &field_src_ },
			{ "dst", &field_dst_ },
			{ "proto", &field_proto_ },
			{ "tos", &field_tos_ },
			{ "ttl", &field_ttl_ } };

};

#endif
