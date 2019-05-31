#include "input.h"
#include "logger.h"

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

void input::read_packets() {

	while (running_status_ == running) {

		pkt *p = read_packet();

		if (!p) {
			break;
		}

		auto process_packet_done = [this, p] { this->process_packet_done(p); };

		executor_->enqueue([this, p, process_packet_done] { this->process_packet(p, std::move(process_packet_done)); });

	}

	if (running_status_ == running) {
		stop();
	}

}

void input::process_packet(pkt *p, pa_task processing_done) {

	pkts_count_++;
	p->process(processing_done);
}

void input::process_packet_done(pkt *p) {

	pkts_count_--;
	if (!pkts_count_) {
		LOG_DEBUG << "Queue empty";
	}
	delete p;
}


void input::stop() {

	if (running_status_ != running) {
		throw std::runtime_error("Input is not in running state");
	}

	running_status_ = stopping;

	// Break the main loop first
	break_loop();

	// Wait for the main loop to stop
	if (processing_thread_.joinable()) {
		if (processing_thread_.get_id() != std::this_thread::get_id()) {
			processing_thread_.join();
		} else {
			processing_thread_.detach();
		}
	}

	// Finally close the input
	close();

	running_status_ = idle;
}
