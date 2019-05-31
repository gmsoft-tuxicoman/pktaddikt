
#include <iostream>

#include "logger_def.h"

logger *logger_;

logger_entry::logger_entry(level lvl) {


	now_ = std::chrono::high_resolution_clock::now();
	level_ = lvl;
	stream_ = std::move(std::make_unique<std::ostringstream>());
}

logger_entry::~logger_entry() {
	logger_->process(this);
}


logger_entry logger::log(logger_entry::level lvl) {

	return logger_entry(lvl);

}

void logger::process(logger_entry *entry) {

	auto msg = entry->stream_.release();
	serializer_.enqueue([msg] { std::cout << msg->str() << std::endl; delete msg; });
}


