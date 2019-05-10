
#ifndef __PTYPE_UINT8_H__
#define __PTYPE_UINT8_H__


#include "ptype.h"


class ptype_uint8 : public ptype {

	public:
		ptype_uint8();
		ptype_uint8(const std::string& val);

		bool parse(const std::string& val) override;
		const std::string print() override;

		uint8_t get_value() const { return value_; };
		void set_value(uint8_t val) { value_ = val; };
		void set_value(pkt_buffer *buf);

	private:
		uint8_t value_ = 0;

};

#endif
