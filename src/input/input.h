#ifndef __INPUT_H__
#define __INPUT_H__

#include <atomic>
#include <thread>
#include <deque>

#include "pkt/pkt.h"
#include "pkt/pkt_factory.h"
#include "common/component.h"
#include "tasks/task_serializer.h"

class input : public component {
	public:
		input(const std::string& name, task_executor_ptr executor): component(name), executor_(executor), serializer_(executor) {};
		virtual ~input() {};

		virtual input* clone(const std::string &name) const { throw std::runtime_error("Cannot create input directly"); };

		void start();
		virtual void break_loop() {};
		void stop();

		enum running_status { idle, starting, running, stopping };
		const running_status get_running_status() const { return running_status_; };

	protected:
		std::thread processing_thread_;
		std::deque<pkt> pkts_;
		std::atomic<unsigned int> pkts_count_ = 0;
		task_serializer serializer_;
		task_executor_ptr executor_;

		virtual void open() = 0;
		virtual pkt* read_packet() = 0;
		virtual void close() = 0;

	private:
		std::atomic<running_status> running_status_ = idle;
		void read_packets();
};

#endif
