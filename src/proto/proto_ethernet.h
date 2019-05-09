#ifndef __PROTO_ETHERNET_H__
#define __PROTO_ETHERNET_H__

#include "proto.h"

#include "ptype/ptype_uint16.h"
#include "ptype/ptype_mac.h"

class proto_ethernet : public proto {

	public:

		proto_ethernet();
		proto_ethernet(pkt *pkt);

		proto* factory(pkt *pkt) { return new proto_ethernet(pkt); };

		void parse();
		
		enum fields_id { src, dst, type };

	protected:
		proto_fields fields_ = { 
			{ "src", nullptr },
			{ "dst", nullptr },
			{"type", nullptr } };


	private:
		// Registration stuff
		static proto_ethernet proto_ethernet_;

};


#endif
