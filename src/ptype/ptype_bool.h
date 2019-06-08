
#ifndef __PTYPE_BOOL_H__
#define __PTYPE_BOOL_H__


#include "ptype.h"


class ptype_bool : public ptype {

	public:
		ptype_bool();
		ptype_bool(const std::string& val);

		bool parse(const std::string& val) override;
		const std::string print() override;

		bool get_value() const { return value_; };

	private:
		bool value_ = false;

};

namespace std {
	template <> struct hash<ptype_bool> {
		std::size_t operator()(ptype_bool const &p) const noexcept {
			return std::hash<bool>{}(p.get_value());
		}
	};
}
#endif
