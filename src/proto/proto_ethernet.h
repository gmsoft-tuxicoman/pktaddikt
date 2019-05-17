#ifndef __PROTO_ETHERNET_H__
#define __PROTO_ETHERNET_H__

#include "proto.h"

#include "ptype/ptype_uint16.h"
#include "ptype/ptype_mac.h"

class proto_ethernet : public proto {

	public:

		proto_ethernet();
		proto_ethernet(pkt *pkt): proto(pkt) {};

		proto* factory(pkt *pkt) { return new proto_ethernet(pkt); };

		void parse();
		
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
