#ifndef __PKT_H__
#define __PKT_H__

#include <vector>
#include <memory>


#include "ptype/ptype.h"
#include "pkt_buffer.h"
#include "tasks/task_executor.h"

class pkt;

using pkt_ptr = std::shared_ptr<pkt>;
//using pkt_list_ptr = std::vector<std::shared_ptr<pkt>>;
using pkt_fields = std::vector<std::pair<std::string, ptype*>>;

class pkt {

	public:
		pkt(pkt_buffer_ptr buf, pkt_ptr parent, task_executor_ptr executor) : buf_(buf), parent_(parent), executor_(executor), self_(this) {};
		virtual ~pkt() {};

		void process();


		enum parse_result { unknown, ok, invalid };


	protected:

		virtual parse_result parse() = 0;

		pkt_fields fields_;
		pkt_ptr self_;

		pkt_buffer_ptr buf_;
		task_executor_ptr executor_;

		pkt_ptr parent_; // Packet containing this one
		//pkt_list_ptr next_; // Packets contained in this one
	
	private:
		parse_result result_ = unknown;


};



#endif
