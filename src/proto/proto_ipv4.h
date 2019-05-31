#ifndef __PROTO_IPV4_H__
#define __PROTO_IPV4_H__

#include "proto.h"

#include "ptype/ptype_ipv4.h"
#include "ptype/ptype_uint8.h"

class proto_ipv4 : public proto {

	public:

		proto_ipv4();
		proto_ipv4(pkt *pkt): proto(pkt) {};

		proto* factory(pkt *pkt) { return new proto_ipv4(pkt); };

		void parse();
		
		enum fields_id { src, dst, protocol, tos, ttl };

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
