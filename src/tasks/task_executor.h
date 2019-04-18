#ifndef __TASKS_TASK_EXECUTOR_H__
#define __TASKS_TASK_EXECUTOR_H__

#include <memory>

#include "task.h"

class task_executor {

	public:
		virtual ~task_executor() {};
		virtual void enqueue(pa_task t) = 0;


};

using task_executor_ptr = std::shared_ptr<task_executor>;

#endif
