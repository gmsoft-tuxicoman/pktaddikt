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

		ptype_mac field_src;
		ptype_mac field_dst;
		ptype_uint16 field_type;

		proto_fields fields_ = {
			{ "src", &field_src },
			{ "dst", &field_dst },
			{"type", &field_type } };


};


#endif
