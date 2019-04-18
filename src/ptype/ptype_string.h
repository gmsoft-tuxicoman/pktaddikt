
#ifndef __PTYPE_PTYPE_STRING_H__
#define __PTYPE_PTYPE_STRING_H__


#include "ptype.h"


class ptype_string : public ptype {

	public:
		ptype_string();
		ptype_string(const ptype_string& p);
		ptype_string(const std::string& val);

		bool parse(const std::string& val) override;
		const std::string print() override;

	private:
		std::string value_ = "";
		std::string type_name_ = "string";

};

#endif
