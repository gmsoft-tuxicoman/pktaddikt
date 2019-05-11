
#ifndef __PTYPE_IPV4_H__
#define __PTYPE_IPV4_H__

#include <cstring>

#include <netinet/in.h>

#include "ptype.h"

class ptype_ipv4 : public ptype {

	public:
		ptype_ipv4();
		ptype_ipv4(const std::string& val);

		bool parse(const std::string& val) override;
		const std::string print() override;

		in_addr get_ip() const { return ip_; };
		void set_ip(in_addr ip) { ip_ = ip; };
		void set_value(pkt_buffer *buf);

	private:
		in_addr ip_ = { 0 };

};

#endif
