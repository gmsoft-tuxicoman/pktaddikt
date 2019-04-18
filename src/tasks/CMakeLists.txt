
add_library(tasks main_task_executor.cpp  main_task_executor.h
	task_executor.h  task.h  task_serializer.cpp  task_serializer.h)

target_link_libraries(tasks tbb)
