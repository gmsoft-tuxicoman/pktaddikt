#ifndef __PKT_ETHERNET__
#define __PKT_ETHERNET__

#include "pkt/pkt.h"
#include "pkt/pkt_factory.h"
#include "ptype/ptype_uint16.h"
#include "ptype/ptype_mac.h"

#define ETHERNET_HEADER_LEN 14

class pkt_ethernet : public pkt {
	
	public:
		pkt_ethernet(pkt_buffer_ptr buf, pkt_ptr parent, task_executor_ptr executor) : pkt(buf, parent, executor) {};

		static pkt* factory(pkt_buffer_ptr buf, pkt_ptr parent, task_executor_ptr executor) { return new pkt_ethernet(buf, parent, executor); };

		static void register_number();


	protected:

		parse_result parse();

		ptype_mac field_src_;
		ptype_mac field_dst_;
		ptype_uint16 field_type_;

		pkt_fields fields_ = {
			{ "src", &field_src_ },
			{ "dst", &field_dst_ },
			{ "type", &field_type_ } };
};

#endif
