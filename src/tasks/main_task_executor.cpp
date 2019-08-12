
#include "tbb/task.h"
#include "main_task_executor.h"


struct task_wrapper : tbb::task {
	pa_task ftor_;

	task_wrapper(pa_task t) : ftor_(std::move(t)) {};

	tbb::task* execute() {
		ftor_();
		return nullptr;
	}
};


main_task_executor::main_task_executor() {};

void main_task_executor::enqueue(pa_task t) {
	
	t();
	//auto& tbb_task = *new(tbb::task::allocate_root()) task_wrapper(std::move(t));
	//tbb::task::enqueue(tbb_task);

}
