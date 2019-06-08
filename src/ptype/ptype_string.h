
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

namespace std {
	template <> struct hash<ptype_string> {
		std::size_t operator() (ptype_string const &p) const noexcept {
			return std::hash<std::string>{} (p.get_value());
		}
	};
}

#endif
