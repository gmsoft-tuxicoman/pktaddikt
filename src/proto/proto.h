#ifndef __PROTO_H__
#define __PROTO_H__

#include <vector>
#include <functional>
#include <map>
#include "ptype/ptype.h"
#include "tasks/task_executor.h"

#include "conntrack.h"

class pkt;
class proto;
using proto_fields = std::vector<std::pair<std::string, ptype*>>;
using proto_factory = std::function<proto*(pkt*, conntrack_entry_ptr, task_executor_ptr)>;

class proto {

	public:
		proto(pkt* pkt, unsigned int parse_flags, conntrack_entry_ptr parent, task_executor_ptr executor): pkt_(pkt), parse_flags_(parse_flags), parent_(parent), executor_(executor) {};

		enum parse_status { todo, ok, stop, invalid, error};
		parse_status get_parse_status() { return parse_status_; };

		conntrack_entry_ptr get_conntrack() { return conntrack_; };

		void parse(pa_task parse_done);

		virtual void parse_pre_session() {};
		virtual void parse_fetch_session(pa_task fetch_session_done) {};
		virtual void parse_in_session() {};


		static void init_conntrack(task_executor_ptr executor);
		static conntrack_table_ptr conntrack_table_factory(task_executor executor) { return nullptr; };

	protected:

		pkt *pkt_;

		proto_fields fields_;

		static const unsigned int parse_flag_pre = 1;
		static const unsigned int parse_flag_fetch = 2;
		static const unsigned int parse_flag_in = 4;
		static const unsigned int parse_flag_post = 8;

		unsigned int parse_flags_ = 0;


		parse_status parse_status_ = todo;

		conntrack_entry_ptr parent_;
		conntrack_entry_ptr conntrack_;

		task_executor_ptr executor_;

	private:

		pa_task parse_done_;

		void fetch_session_done();

		static conntrack_entry_ptr conntrack_root_;



};

using proto_numbers_vector = std::vector<std::pair<unsigned int, proto_factory>>;

class proto_number {

	public:
		enum type { dlt, ethernet, ip, ppp, udp, PROTO_NUMBER_TYPE_COUNT};

		void register_number(type type, unsigned int id, proto_factory f);
		static proto* get_proto(type type, unsigned int id, pkt *pkt, conntrack_entry_ptr parent, task_executor_ptr executor);

	protected:
		static proto_numbers_vector numbers_[PROTO_NUMBER_TYPE_COUNT];

};

#endif
