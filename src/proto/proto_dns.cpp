
#include "proto_dns.h"

void proto_dns::register_number() {

	proto_number().register_number(proto_number::type::udp, 53, proto_udp::factory);
	proto_number().register_number(proto_number::type::tcp, 53, proto_udp::factory);
}

void proto_dns::parse_pre_session() {
	// Need to fetch a conntrack if TCP
	// FIXME make this actually
	parse_flags |= parse_flag_fetch;
}
