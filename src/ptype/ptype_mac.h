
#ifndef __PTYPE_MAC_H__
#define __PTYPE_MAC_H__

#include <cstring>

#include "ptype.h"

class ptype_mac : public ptype {

	public:
		ptype_mac();
		ptype_mac(const std::string& val);

		bool parse(const std::string& val) override;
		const std::string print() const override;

		const unsigned char* get_value() const { return value_; };
		void set_value(const unsigned char* val) { memcpy(value_, val, 6); };
		void set_value(pkt_buffer *buf, std::size_t offset);

	private:
		unsigned char value_[6] = { 0 };

};

namespace std {
	template <> struct hash<ptype_mac> {
		std::size_t operator()(ptype_mac const &p) const noexcept {
			std::size_t ret = 0;
			if (sizeof(std::size_t) > 6) {
				memcpy(&ret, p.get_value(), 6);
			} else {
				const unsigned char *val = p.get_value();
				for (int i = 0; i < 6; i++) {
					ret ^= (std::size_t)val[i] << ( 8 * (i % sizeof(std::size_t)));
				}
			}
			return ret;
		}
	};
}

#endif
