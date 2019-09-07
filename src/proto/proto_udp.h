#ifndef __PROTO_UDP_H__
#define __PROTO_UDP_H__

#include "proto.h"

#include "ptype/ptype_uint16.h"

class proto_udp : public proto {

	public:
		static void register_number();
		static proto* factory(pkt *pkt, conntrack_entry_ptr parent, task_executor_ptr executor) { return new proto_udp(pkt, parent, executor); };

		proto_udp(pkt *pkt, conntrack_entry_ptr parent, task_executor_ptr executor): proto(pkt, parse_flag_pre | parse_flag_fetch, parent, executor) {};

		void parse_pre_session();
		void parse_fetch_session(pa_task fetch_session_done);
		void parse_in_session() {};

		enum fields_id { sport, dport };


	protected:
		
		ptype_uint16 field_sport_;
		ptype_uint16 field_dport_;

		proto_fields fields_ {
			{ "sport", &field_sport_ },
			{ "dport", &field_dport_ }};

};

using conntrack_udp_key = std::pair<ptype_uint16, ptype_uint16>;
using conntrack_udp_entry = conntrack_entry_children<conntrack_udp_key>;

#endif
