
#ifndef __TASK_SERIALIZER__
#define __TASK_SERIALIZER__


#include "task_executor.h"

#include "tbb/concurrent_queue.h"
#include "tbb/atomic.h"

class task_serializer : public task_executor {

	public:
		task_serializer(task_executor_ptr executor);

		void enqueue(pa_task t) override;

	private:
		task_executor_ptr base_executor_;
		tbb::concurrent_queue<pa_task> standby_tasks_;
		tbb::atomic<int> standby_count_{0};

		void enqueue_first();
		void on_task_done();

};

#endif
