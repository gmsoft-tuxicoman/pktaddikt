#include <memory>

#include "pkt.h"



void pkt::set_proto(proto* p) {
	proto_ = proto_number::get_proto(type, id, executor_);
}

void pkt::process() {

	if (!proto_)
		return;

	proto_->process(self);

}
