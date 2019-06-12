#ifndef __PKT_H__
#define __PKT_H__

#include <chrono>
#include <vector>
#include <memory>

#include "proto/proto.h"
#include "pkt_buffer.h"
#include "tasks/task_executor.h"

using pkt_timestamp = std::chrono::duration<uint64_t, std::micro>;

using pkt_proto_stack = std::vector<std::unique_ptr<proto>>;

class pkt {

	public:
		pkt(pkt_buffer *buf, pkt_timestamp ts, task_executor_ptr executor) : buf_(buf), executor_(executor) {};

		pkt_buffer *get_buffer() { return buf_; };

		void add_proto(proto_number::type type, unsigned int id);

		void process(pa_task process_packet_done);

	protected:
		void process_next();

		pkt_timestamp ts_;

		// FIXME use shared_ptr ?
		pkt_buffer *buf_;

		pkt_proto_stack::size_type cur_proto_ = 0;
		pkt_proto_stack proto_stack_;

		task_executor_ptr executor_;

		pa_task process_packet_done_;

};

#endif
