#ifndef __PTYPE_UINT32_H__
#define __PTYPE_UINT32_H__


#include <cassert>
#include <byteswap.h>

#include "ptype.h"


class ptype_uint32 : public ptype {

	public:
		ptype_uint32();
		ptype_uint32(const std::string& val);

		bool parse(const std::string& val) override;
		const std::string print() const override;

		uint32_t get_value() const { return value_; };
		void set_value(uint32_t val) { value_ = val; };
		void set_value(pkt_buffer &buf, std::size_t offset);

	private:
		uint32_t value_ = false;

};

using ptype_uint32_pair = std::pair<ptype_uint32, ptype_uint32>;

namespace std {
	template <> struct hash<ptype_uint32> {
		std::size_t operator() (ptype_uint32 const &p) const noexcept {
			return std::hash<uint32_t>{} (p.get_value());
		}
	};

	template <> struct hash<ptype_uint32_pair> {
		std::size_t operator() (ptype_uint32_pair const &p) const noexcept {
			uint32_t first = p.first.get_value();
			uint32_t second = p.second.get_value();
			if (second < first) {
				uint32_t tmp = first;
				first = second;
				second = tmp;
			}
			if (sizeof(std::size_t) >= 8) {
				// 64 bit platform
				return (std::size_t) (first << (8 * sizeof(uint32_t)) + second);
			}
			// 32bit platform
			assert(sizeof(std::size_t) >= 4);
			return first ^ bswap_32(second);
		}
	};

	template <> struct equal_to<ptype_uint32_pair> {
		bool operator() (const ptype_uint32_pair &lhs, const ptype_uint32_pair &rhs) const {
			return (((lhs.first.get_value() == rhs.first.get_value()) && (lhs.second.get_value() == rhs.second.get_value()))
				|| (((lhs.first.get_value() == rhs.second.get_value()) && (lhs.second.get_value() == rhs.first.get_value()))));
		}
	};
}

#endif