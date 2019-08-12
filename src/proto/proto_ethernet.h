#ifndef __PROTO_ETHERNET_H__
#define __PROTO_ETHERNET_H__

#include "proto.h"

#include "ptype/ptype_uint16.h"
#include "ptype/ptype_mac.h"

class proto_ethernet : public proto {

	public:

		static void register_number();

		proto_ethernet(pkt *pkt, task_executor_ptr executor): proto(pkt, parse_flag_pre, nullptr, executor) {};

		static proto* factory(pkt *pkt, conntrack_entry_ptr parent, task_executor_ptr executor) { return new proto_ethernet(pkt, executor); };

		void parse_pre_session();
		
		enum fields_id { src, dst, type };

	protected:

		ptype_mac field_src_;
		ptype_mac field_dst_;
		ptype_uint16 field_type_;

		proto_fields fields_ = {
			{ "src", &field_src_ },
			{ "dst", &field_dst_ },
			{"type", &field_type_ } };


};


#endif
