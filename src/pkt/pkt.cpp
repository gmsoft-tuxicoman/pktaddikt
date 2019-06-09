#include <memory>

#include "pkt.h"


void pkt::add_proto(proto_number::type type, unsigned int id) {

	proto *proto_type = proto_number::get_proto(type, id, this);
	if (!proto_type) {
		// No matching protocol found
		return;
	}

	std::unique_ptr<proto> new_proto_ptr(proto_type);

	proto_stack_.push_back(std::move(new_proto_ptr));
}


void pkt::process(pa_task parse_packet_done) {

	for (auto it = proto_stack_.begin(); it != proto_stack_.end(); it++) {
		it->get()->parse();
	}

	executor_->enqueue(parse_packet_done);
}
