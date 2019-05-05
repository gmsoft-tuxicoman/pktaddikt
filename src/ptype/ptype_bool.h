
#ifndef __PTYPE_PTYPE_BOOL_H__
#define __PTYPE_PTYPE_BOOL_H__


#include "ptype.h"


class ptype_bool : public ptype {

	public:
		ptype_bool();
		ptype_bool(const ptype_bool &p);
		ptype_bool(const std::string& val);

		bool parse(const std::string& val) override;
		const std::string print() override;

		bool get_value() const { return value_; };

	private:
		bool value_ = false;
		std::string type_name_ = "bool";

};

#endif
