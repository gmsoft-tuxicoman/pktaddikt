
#include <cassert>

#include "pkt_factory.h"


pkt_factory_entry pkt_factory::entries_[PKT_FACTORY_TYPE_COUNT];

void pkt_factory::register_number(type type, unsigned int id, pkt_factory_ctor ct) {
	assert(type <= PKT_FACTORY_TYPE_COUNT);
	entries_[type].push_back({id, ct});
}


pkt* pkt_factory::factory(type type, unsigned int id, pkt_buffer_ptr buf, pkt_ptr parent, task_executor_ptr executor) {

	for (auto const& entry : entries_[type]) {
		if (entry.first == id) {
			return entry.second(buf, std::move(parent), executor);
		}

	}

	return nullptr;
}

