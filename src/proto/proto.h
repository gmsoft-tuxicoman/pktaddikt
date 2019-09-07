#ifndef __PROTO_H__
#define __PROTO_H__

#include "ptype/ptype.h"
#include "tasks/task_executor.h"

class proto;
using proto_fields = std::vector<std::pair<std::string, ptype*>>;
using proto_factory = std::function<proto*(task_executor_ptr)>;

class proto {

	public:
		proto(task_executor_ptr executor): executor_(executor) {};


	protected:

		proto_fields fields_;

		task_executor_ptr executor_;


};

using proto_numbers_vector = std::vector<std::pair<unsigned int, proto_factory>>;

class proto_number {

	public:
		enum type { dlt, ethernet, ip, ppp, udp, PROTO_NUMBER_TYPE_COUNT};

		void register_number(type type, unsigned int id, proto_factory f);
		static proto* get_proto(type type, unsigned int id, task_executor_ptr executor);

	protected:
		static proto_numbers_vector numbers_[PROTO_NUMBER_TYPE_COUNT];

};

#endif
