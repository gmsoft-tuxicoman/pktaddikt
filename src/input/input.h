#ifndef __INPUT_H__
#define __INPUT_H__

#include "common/component.h"

class input : public component {
	public:
		input(const std::string& name): component(name) {};

		virtual input* clone(const std::string &name) const { throw std::runtime_error("Cannot create input directly"); };
};

#endif
