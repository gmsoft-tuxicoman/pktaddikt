
#ifndef __PTYPE_STRING_H__
#define __PTYPE_STRING_H__


#include "ptype.h"


class ptype_string : public ptype {

	public:
		ptype_string();
		ptype_string(const std::string& val);

		bool parse(const std::string& val) override;
		const std::string print() override;

		const std::string& get_value() const { return value_; };

	private:
		std::string value_ = "";

};

#endif
