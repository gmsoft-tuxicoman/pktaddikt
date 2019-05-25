#ifndef __PKT_H__
#define __PKT_H__

#include <chrono>
#include <list>
#include <memory>

#include "proto/proto.h"
#include "pkt_buffer.h"
#include "tasks/task_executor.h"

using pkt_timestamp = std::chrono::duration<uint64_t, std::micro>;

class pkt {

	public:
		pkt(pkt_buffer *buf, pkt_timestamp ts, task_executor_ptr executor) : buf_(buf), executor_(executor) {};

		pkt_buffer *get_buffer() { return buf_; };

		void add_proto(proto::number_type type, unsigned int id);

		void process(pa_task process_packet_done);

	protected:
		pkt_timestamp ts_;

		// FIXME use shared_ptr ?
		pkt_buffer *buf_;

		std::list<std::unique_ptr<proto>> proto_stack_;

		task_executor_ptr executor_;

};

#endif
