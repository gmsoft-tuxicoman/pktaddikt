#ifndef __PARAMETER_H__
#define __PARAMETER_H__

#include <memory>
#include <mutex>

#include "ptype/ptype.h"

class parameter_base {

	public:
		
		virtual const std::string print_default_value() const = 0;
		virtual const std::string print_value() const = 0;

		virtual const std::string& get_type() const = 0;
		virtual const std::string& get_description() const = 0;

		virtual bool parse_value(const std::string& val) = 0;

};

template <class P>
class parameter : public parameter_base {

	public:
		parameter(const std::string& val, const std::string& description) : description_(std::move(description)), value_(val), default_value_(val) {};

		const std::string print_default_value() const {
			std::lock_guard<std::mutex> lock(mutex_);
			return default_value_.print();
		}

		const std::string print_value() const {
			std::lock_guard<std::mutex> lock(mutex_);
			return value_.print();
		}

		const std::string& get_type() const { return value_.get_type(); };
		const std::string& get_description() const { return description_; };

		bool parse_value(const std::string& val) {
			std::lock_guard<std::mutex> lock(mutex_);
			return value_.parse(val);
		}

		bool has_default_value() const { return value_ == default_value_; };

		const P& ptype() const { return value_; };


	protected:

		mutable P value_;
		mutable P default_value_;

		std::string description_;

		mutable std::mutex mutex_;

};

#endif
