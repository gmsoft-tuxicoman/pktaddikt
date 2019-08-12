#include <memory>

#include "pkt.h"


void pkt::add_proto(proto_number::type type, unsigned int id) {

	conntrack_entry_ptr parent;
	if (cur_proto_ > 0) {
		parent = proto_stack_.at(cur_proto_ - 1)->get_conntrack();
	}

	proto *proto_type = proto_number::get_proto(type, id, this, parent, executor_);
	if (!proto_type) {
		// No matching protocol found
		return;
	}

	std::unique_ptr<proto> new_proto_ptr(proto_type);

	proto_stack_.push_back(std::move(new_proto_ptr));
}


void pkt::process(pa_task process_packet_done) {

	process_packet_done_ = process_packet_done;
	process_next();
}

void pkt::process_next() {

	if (cur_proto_ >= proto_stack_.size()) {
		// Processing of the packet is done
		process_packet_done_();
		return;
	}

	auto process_proto_next = [this]  { this->process_next(); };

	proto_stack_.at(cur_proto_++)->parse(process_proto_next);

}
