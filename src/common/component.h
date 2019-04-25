#ifndef __COMPONENT_H__
#define __COMPONENT_H__

#include "common/parameter.h"

using component_parameters = std::map<std::string, std::unique_ptr<parameter_base>>;

class component {

	public:
		component(const std::string& name) : name_(name) {};

		const component_parameters& get_parameters() { return parameters_; };

	protected:
		std::string name_;
		component_parameters parameters_;

};

#endif
