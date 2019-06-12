
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
		void set_value(pkt_buffer *buf, std::size_t offset);

	private:
		uint16_t value_ = false;

};

namespace std {
	template <> struct hash<ptype_uint16> {
		std::size_t operator() (ptype_uint16 const &p) const noexcept {
			return std::hash<uint16_t>{} (p.get_value());
		}
	};
}

#endif
