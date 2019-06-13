
#ifndef __PTYPE_IPV4_H__
#define __PTYPE_IPV4_H__

#include <netinet/in.h>
#include <byteswap.h>
#include <cassert>


#include "ptype.h"

class ptype_ipv4 : public ptype {

	public:
		ptype_ipv4();
		ptype_ipv4(const std::string& val);

		bool parse(const std::string& val) override;
		const std::string print() const override;

		in_addr get_ip() const { return ip_; };
		void set_ip(in_addr ip) { ip_ = ip; };
		void set_value(pkt_buffer *buf, std::size_t offset);

		bool operator==(ptype_ipv4 const& p) const { return this->ip_.s_addr == p.ip_.s_addr; };

	private:
		in_addr ip_ = { 0 };

};

using ptype_ipv4_pair = std::pair<ptype_ipv4, ptype_ipv4>;

namespace std {
	template <> struct hash<ptype_ipv4> {
		std::size_t operator()(ptype_ipv4 const &p) const noexcept {
			return std::hash<uint32_t>{}(p.get_ip().s_addr);
		}
	};

	template <> struct hash<ptype_ipv4_pair> {
		std::size_t operator() (ptype_ipv4_pair const &p) const noexcept {
			uint32_t first = p.first.get_ip().s_addr;
			uint32_t second = p.second.get_ip().s_addr;
			if (second < first) {
				uint32_t tmp = first;
				first = second;
				second = tmp;
			}
			if (sizeof(std::size_t) >= 8) {
				return (std::size_t) (first << (8 * sizeof(uint32_t)) + second);
			} else {
				assert(sizeof(std::size_t) >= 4);
				return first ^ bswap_32(second);
			}
		}
	};

	template <> struct equal_to<ptype_ipv4_pair> {
		bool operator() (const ptype_ipv4_pair &lhs, const ptype_ipv4_pair &rhs) const {
			return (((lhs.first.get_ip().s_addr == rhs.first.get_ip().s_addr) && (lhs.second.get_ip().s_addr == rhs.second.get_ip().s_addr))
				|| ((lhs.first.get_ip().s_addr == rhs.second.get_ip().s_addr) && (lhs.second.get_ip().s_addr == rhs.first.get_ip().s_addr)));
		}
	};
}

#endif
