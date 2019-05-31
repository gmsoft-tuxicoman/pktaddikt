#ifndef __LOGGER_DEF_H__
#define __LOGGER_DEF_H__


#include "tasks/task_serializer.h"

#include <sstream>
#include <iostream>
#include <chrono>

class logger_entry {

	public:
		enum level { error, warn, info, debug };

		logger_entry(level lvl);
		~logger_entry();


		template <class T>
		logger_entry &operator<<(const T &x) {
			*stream_.get() << x;
			return *this;
		}


	protected:
		std::chrono::high_resolution_clock::time_point now_;
		level level_;

		std::unique_ptr<std::ostringstream> stream_;

		friend class logger;


};



class logger {

	public:
		logger(task_executor_ptr executor) : executor_(executor), serializer_(executor) {};
		logger_entry log(logger_entry::level level);

		void process(logger_entry *entry);

	protected:
		void output_to_stdout(std::string msg);

		task_serializer serializer_;
		task_executor_ptr executor_;

};

#endif
