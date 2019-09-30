#include <memory>

#include "pkt.h"

void pkt::process() {


	result_ = parse();

	// Let's commit suicide
	self_.reset();
}


