#ifndef __CONNTRACK_H_
#define __CONNTRACK_H_

#include "logger.h"
#include "tasks/task_executor.h"
#include "tasks/task_serializer.h"

#include <typeinfo>
#include <typeindex>
#include <memory>
#include <unordered_map>

class conntrack_priv;
class conntrack_entry;
class conntrack_table {
	public:
		conntrack_table(task_executor_ptr executor) : serializer_(executor) {};
	
	protected:
		task_serializer serializer_;
};


using conntrack_entry_ptr = std::shared_ptr<conntrack_entry>;
using conntrack_table_ptr = std::unique_ptr<conntrack_table>;
using conntrack_table_factory = std::function<conntrack_table*()>;

class conntrack_table_single : public conntrack_table {

	public:
		conntrack_table_single(task_executor_ptr executor) : conntrack_table(executor) {};

		conntrack_entry_ptr get_child() { return child_; };

	protected:
		conntrack_entry_ptr child_;

};

template <class T>
class conntrack_table_multi {
	
	public:
		conntrack_table_multi(task_executor_ptr executor) : conntrack_table(executor) {};

		conntrack_entry_ptr get_child(T &&t) {
			auto res = children_.insert(t);
			if (res.second) {
				res.first->second = std::make_shared<conntrack_entry>();
			}
			return res.first->second;
		}

	protected:
		std::unordered_map<T, conntrack_entry_ptr> children_;
		
};

using conntrack_priv_ptr = std::shared_ptr<conntrack_priv>;

class conntrack_entry {

	public:
		conntrack_entry(task_executor_ptr executor) : serializer_(executor) {};

		void set_table(conntrack_table_ptr table) { table_ = std::move(table); };
		conntrack_table_ptr get_table() { return table_.get(); };

		void add_priv(std::type_info type, conntrack_priv_ptr) { /* TODO */ };

	protected:

		conntrack_table_ptr table_;
		task_serializer serializer_;


};


class conntrack_table_root : public conntrack_table_multi<std::type_index> {

	public:

		conntrack_table_root(task_executor_ptr executor) : conntrack_table_multi(executor) {};


		conntrack_entry_ptr get_child(const std::type_info &t) {
			auto res = children_.insert(std::make_pair<std::type_index, conntrack_entry_ptr>(std::type_index(t), conntrack_entry_ptr()));
			if (res.second) { 
				LOG_DEBUG << "New root conntrack entry for " << t.name();
			}
			return res.first->second;
		};

};


#endif
