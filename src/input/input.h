#ifndef __INPUT_H__
#define __INPUT_H__

#include <atomic>
#include <thread>

#include "common/component.h"

class input : public component {
	public:
		input(const std::string& name): component(name) {};
		virtual ~input() {};

		virtual input* clone(const std::string &name) const { throw std::runtime_error("Cannot create input directly"); };

		void start();
		virtual void break_loop() {};
		void stop();

		enum running_status { idle, starting, running, stopping };
		const running_status get_running_status() const { return running_status_; };

	protected:
		std::atomic<running_status> running_status_ = idle;
		std::thread processing_thread_;

		virtual void open() = 0;
		virtual void read_packets() = 0;
		virtual void close() = 0;
};

#endif
