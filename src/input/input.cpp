

#include "input.h"

void input::start() {

	try {
		running_status_ = starting;
		open();
	} catch (...) {
		close();
		running_status_ = idle;
		throw;
	}

	running_status_ = running;
	processing_thread_ = std::thread(&input::read_packets, this);

}


void input::stop() {

	if (running_status_ != running) {
		throw std::runtime_error("Input is not in running state");
	}

	running_status_ = stopping;

	close();

}
