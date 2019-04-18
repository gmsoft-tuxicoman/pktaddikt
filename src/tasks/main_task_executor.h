#ifndef __TASKS_MAIN_TASK_EXECUTOR__
#define __TASKS_MAIN_TASK_EXECUTOR__

#include "task_executor.h"

class main_task_executor : public task_executor {
	public:
		main_task_executor();

		void enqueue(pa_task t) override;
};

#endif
