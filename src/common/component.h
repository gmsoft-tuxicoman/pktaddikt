#ifndef __COMPONENT_H__
#define __COMPONENT_H__

#include <map>

#include "common/parameter.h"

using component_parameters = std::map<std::string, parameter_base*>;

class component {

	public:
		component(const std::string& name) : name_(name) {};

		const component_parameters& get_parameters() const { return parameters_; };
		const std::string& get_name() const { return name_; };

		virtual component* clone(const std::string &name) const = 0;

	protected:
		std::string name_;
		component_parameters parameters_;

};

#endif
