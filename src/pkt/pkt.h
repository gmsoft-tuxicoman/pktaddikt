#ifndef __PKT_H__
#define __PKT_H__

#include <chrono>
#include <vector>
#include <memory>

#include "proto/proto.h"
#include "pkt_buffer.h"
#include "tasks/task_executor.h"

class pkt;

using pkt_timestamp = std::chrono::duration<uint64_t, std::micro>;
using pkt_ptr = std::shared_ptr<pkt>;

class pkt {

	public:
		pkt(pkt_buffer_ptr buf, pkt_timestamp ts, pkt_ptr parent, task_executor_ptr executor) : buf_(buf), ts_(ts), parent_(parent), executor_(executor) {};

		void set_proto(proto_number::type type, unsigned int id);

		void process();

	protected:
		pkt_timestamp ts_;
		pkt_buffer_ptr buf_;
		proto *proto_ = NULL;
		pkt_ptr parent_;
		task_executor_ptr executor_;

};



#endif
