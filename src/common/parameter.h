#ifndef __PARAMETER_H__
#define __PARAMETER_H__

#include <memory>

#include "ptype/ptype.h"

class parameter_base {

	public:
		
		virtual const std::string print_default_value() = 0;
		virtual const std::string print_value() = 0;
		virtual const std::string get_type() = 0;
		virtual bool set_value(const std::string& val) = 0;

};

template <class P>
class parameter : public parameter_base {

	public:
		parameter(const std::string& val) {
			value_ = std::make_unique<P>(val);
			default_value_ = std::make_unique<P>(val);
		}

		const std::string print_default_value() { return default_value_->print(); };
		const std::string print_value() { return value_->print(); };

		const std::string get_type() { return value_->get_type(); };

		bool set_value(const std::string& val) { return value_->parse(val); };

		bool has_default_value() { return value_ == default_value_; };


	protected:

		std::unique_ptr<P> value_;
		std::unique_ptr<P> default_value_;

};

#endif
