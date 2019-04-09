#include <iostream>

#include "registry.h"


void registry::add_class(const std::string &name) {

	std::cout << "Registry class " << name << " added" << std::endl;
	classes_[name] = std::make_unique<registry_class> (name);
	
}

registry_class::registry_class(const std::string &name) {

	name_ = name;

	std::cout << "Registry class " << name << " created" << std::endl;
}
