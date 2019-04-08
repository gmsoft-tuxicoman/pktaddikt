
#include <chrono>
#include <thread>

class core {

	public:
		void main_loop(std::chrono::seconds main_sleep);

	private:
		bool running = true;

};
