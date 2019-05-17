
#ifndef __PTYPE_MAC_H__
#define __PTYPE_MAC_H__

#include <cstring>

#include "ptype.h"

class ptype_mac : public ptype {

	public:
		ptype_mac();
		ptype_mac(const std::string& val);

		bool parse(const std::string& val) override;
		const std::string print() override;

		const unsigned char* get_value() const { return value_; };
		void set_value(const unsigned char* val) { memcpy(value_, val, 6); };
		void set_value(pkt_buffer *buf, std::size_t offset);

	private:
		unsigned char value_[6] = { 0 };

};

#endif
