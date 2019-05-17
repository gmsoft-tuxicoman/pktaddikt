#include <memory>

#include "pkt.h"


void pkt::add_proto(proto::number_type type, unsigned int id) {

	proto *proto_type = proto::get_proto(type, id);
	if (!proto_type) {
		// No matching protocol found
		return;
	}

	std::unique_ptr<proto> new_proto_ptr(proto_type->factory(this));

	proto_stack_.push_back(std::move(new_proto_ptr));
}


void pkt::process() {

	for (auto it = proto_stack_.begin(); it != proto_stack_.end(); it++) {
		it->get()->parse();
	}

}
