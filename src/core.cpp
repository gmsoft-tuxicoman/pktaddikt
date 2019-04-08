

#include "core.h"

void core::main_loop(std::chrono::seconds main_sleep) {
	while (running) {
		std::this_thread::sleep_for(main_sleep);
	}
}
