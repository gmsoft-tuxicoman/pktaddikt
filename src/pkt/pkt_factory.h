#ifndef __PKT_FACTORY_H__
#define __PKT_FACTORY_H__

#include "pkt/pkt.h"
#include "pkt/pkt_buffer.h"

using pkt_factory_ctor = std::function<pkt*(pkt_buffer_ptr, pkt_ptr, task_executor_ptr)>;
using pkt_factory_entry = std::vector<std::pair<unsigned int, pkt_factory_ctor>>;

class pkt_factory {

	public:
		enum type { dlt, ethernet, ip, ppp, udp, PKT_FACTORY_TYPE_COUNT };

		static void register_number(type type, unsigned int id, pkt_factory_ctor ct);
		static pkt* factory(type type, unsigned int id, pkt_buffer_ptr buf, pkt_ptr parent, task_executor_ptr executor);


	protected:
		static pkt_factory_entry entries_[PKT_FACTORY_TYPE_COUNT];
		
};


#endif
