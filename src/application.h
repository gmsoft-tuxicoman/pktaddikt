#ifndef __APPLICATION_H__
#define __APPLICATION_H__

#include <chrono>
#include <string>
#include <memory>
#include <map>

class application;

#include "input/input.h"
#include "httpd/httpd.h"

#define APPLICATION_HTTPD_DEFAULT_ADDRESS "0.0.0.0,::"
#define APPLICATION_HTTPD_DEFAULT_PORT	8080

using input_map = std::map<std::string, std::unique_ptr<input>>;

class application {

	public:

		application();

		void main_loop(std::chrono::seconds main_sleep);
		void halt() { running_ = false; };
		bool load_config(std::string &file);
		void start_httpd();

		void get_input_templates(void (*on_get_inputs) (const input_map&));

	private:
		bool running_ = true;

		std::unique_ptr<httpd> httpd_;

		input_map input_templates_;

		std::string httpd_addr_ = APPLICATION_HTTPD_DEFAULT_ADDRESS;
		uint16_t httpd_port_ = APPLICATION_HTTPD_DEFAULT_PORT;

};

#endif

