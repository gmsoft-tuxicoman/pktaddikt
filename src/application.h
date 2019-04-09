
#include <chrono>
#include <string>
#include <memory>

#include "registry.h"
#include "httpd.h"

#define APPLICATION_HTTPD_DEFAULT_ADDRESS "0.0.0.0,::"
#define APPLICATION_HTTPD_DEFAULT_PORT	8080

class application {

	public:
		application();

		void main_loop(std::chrono::seconds main_sleep);
		void halt() { running_ = false; };
		bool load_config(std::string &file);
		void start_httpd();

	private:
		bool running_ = true;

		registry registry_;
		httpd httpd_;

		std::string httpd_addr_ = APPLICATION_HTTPD_DEFAULT_ADDRESS;
		uint16_t httpd_port_ = APPLICATION_HTTPD_DEFAULT_PORT;

};
