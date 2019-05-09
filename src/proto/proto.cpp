
#include <cassert>
#include <iostream>

#include "proto.h"


proto::~proto() {

	for (auto const &field: fields_) {
		delete field.second;
	}


}
