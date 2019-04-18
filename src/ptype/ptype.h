#ifndef __PTYPE_PTYPE_H__
#define __PTYPE_PTYPE_H__

#include <string>

class ptype {

	public:
		
		virtual bool parse(const std::string& val) = 0;
		virtual const std::string print() = 0;

		const std::string& get_type() { return type_name_; };

	protected:
		std::string type_name_;

};

#endif
