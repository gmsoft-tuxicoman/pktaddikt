
#include <cassert>

#include "task_serializer.h"

task_serializer::task_serializer(task_executor_ptr executor) : base_executor_(executor) {};

void task_serializer::enqueue(pa_task t) {

	standby_tasks_.emplace(std::move(t));

	if (++standby_count_ == 1)
		enqueue_first();

}

void task_serializer::enqueue_first() {
	pa_task to_execute;
	bool res = standby_tasks_.try_pop(to_execute);
	assert(res);

	base_executor_->enqueue([this, t = std::move(to_execute)] {
		t();
		this->on_task_done();
	});
}

void task_serializer::on_task_done() {

	if (--standby_count_ != 0)
		enqueue_first();
}
