
#ifndef __PTYPE_UINT16_H__
#define __PTYPE_UINT16_H__


#include "ptype.h"


class ptype_uint16 : public ptype {

	public:
		ptype_uint16();
		ptype_uint16(const std::string& val);

		bool parse(const std::string& val) override;
		const std::string print() override;

		uint16_t get_value() const { return value_; };
		void set_value(uint16_t val) { value_ = val; };

	private:
		uint16_t value_ = false;
		std::string type_name_ = "uint16";

};

#endif
