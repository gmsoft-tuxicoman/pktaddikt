
#ifndef __PTYPE_UINT16_H__
#define __PTYPE_UINT16_H__


#include "ptype.h"


class ptype_uint16 : public ptype {

	public:
		ptype_uint16();
		ptype_uint16(const std::string& val);

		bool parse(const std::string& val) override;
		const std::string print() const override;

		uint16_t get_value() const { return value_; };
		void set_value(uint16_t val) { value_ = val; };
		void set_value(pkt_buffer &buf, std::size_t offset);

	private:
		uint16_t value_ = false;

};

using ptype_uint16_pair = std::pair<ptype_uint16, ptype_uint16>;

namespace std {
	template <> struct hash<ptype_uint16> {
		std::size_t operator() (ptype_uint16 const &p) const noexcept {
			return std::hash<uint16_t>{} (p.get_value());
		}
	};

	template <> struct hash<ptype_uint16_pair> {
		std::size_t operator() (ptype_uint16_pair const &p) const noexcept {
			uint16_t first = p.first.get_value();
			uint16_t second = p.second.get_value();
			if (first < second) {
				return (first << (8 * sizeof(uint16_t))) + second;
			}
			return (second << (8 * sizeof(uint16_t))) + first;
		}
	};

	template <> struct equal_to<ptype_uint16_pair> {
		bool operator() (const ptype_uint16_pair &lhs, const ptype_uint16_pair &rhs) const {
			return (((lhs.first.get_value() == rhs.first.get_value()) && (lhs.second.get_value() == rhs.second.get_value()))
				|| (((lhs.first.get_value() == rhs.second.get_value()) && (lhs.second.get_value() == rhs.first.get_value()))));
		}
	};
}

#endif
