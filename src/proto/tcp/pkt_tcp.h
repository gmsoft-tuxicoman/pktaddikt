#ifndef __PKT_TCP_H__
#define __PKT_TCP_H__

#include "pkt/pkt.h"
#include "pkt/pkt_factory.h"

#include "ptype/ptype_uint8.h"
#include "ptype/ptype_uint16.h"
#include "ptype/ptype_uint32.h"

#define TH_FIN	0x1
#define TH_SYN	0x2
#define TH_RST	0x4
#define TH_ACK	0x10


class pkt_tcp: public pkt {

	public:
		pkt_tcp(pkt_buffer_ptr buf, pkt_ptr parent, task_executor_ptr executor) : pkt(buf, parent, executor) {};

		static pkt* factory(pkt_buffer_ptr buf, pkt_ptr parent, task_executor_ptr executor) { return new pkt_tcp(buf, parent, executor); };

		static void register_number();

	protected:

		parse_result parse();

		ptype_uint16 field_sport_;
		ptype_uint16 field_dport_;
		ptype_uint8 field_flags_;
		ptype_uint32 field_seq_;
		ptype_uint32 field_ack_;
		ptype_uint16 field_win_;

		pkt_fields fields_ = {
			{ "sport", &field_sport_ },
			{ "dport", &field_dport_ },
			{ "flags", &field_flags_ },
			{ "seq", &field_seq_ },
			{ "ack", &field_ack_ },
			{ "win", &field_win_ } };

};

#endif
