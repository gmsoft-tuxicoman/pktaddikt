
#include <cassert>

#include "proto.h"
#include "logger.h"

conntrack_entry_root_ptr proto::conntrack_root_;

proto_numbers_vector proto_number::numbers_[PROTO_NUMBER_TYPE_COUNT];

void proto_number::register_number(type type, unsigned int id, proto_factory f) {
	assert(type <= PROTO_NUMBER_TYPE_COUNT);
	numbers_[type].push_back({id, f});
}

proto* proto_number::get_proto(type type, unsigned int id, pkt *pkt, conntrack_entry_ptr parent, task_executor_ptr executor) {

	for (auto const& num : numbers_[type]) {
		if (num.first == id) {
			return num.second(pkt, std::move(parent), std::move(executor));
		}
	}

	return nullptr;
}

void proto::init_conntrack(task_executor_ptr executor) {
	conntrack_root_->set_table(std::move(std::make_unique<conntrack_table_root>(executor)));
};

void proto::parse(pa_task parse_done) {

	parse_done_ = parse_done;

	if (parse_flags_ & parse_flag_pre) {
		try {
			parse_pre_session();
		} catch (const std::out_of_range& e) {
			parse_status_ = invalid;
		}

		if (parse_status_ > ok) {
			LOG_DEBUG << "Packet parsing failed";
			parse_done_();
			return;
		}
	}

	if (parse_flags_ & parse_flag_fetch) {

		if (parent_ == nullptr) {
			// FIXME must be a task
			conntrack_table_root* root_table = static_cast<conntrack_table_root*>(conntrack_root_->get_table());
			parent_ = root_table->get_child(typeid(*this));
		}

		parse_fetch_session([this] { this->fetch_session_done() ; });
	} else {
		parse_done_();
	}

}


void proto::fetch_session_done() {

	LOG_DEBUG << "Session fetched";
	executor_->enqueue(parse_done_);

}

