#ifndef __APPLICATION_H__
#define __APPLICATION_H__

#include <chrono>
#include <string>
#include <memory>
#include <map>

class application;

#include "input/input.h"
#include "proto/proto.h"
#include "httpd/httpd.h"
#include "rapidjson/document.h"
#include "tasks/main_task_executor.h"

#define APPLICATION_HTTPD_DEFAULT_ADDRESS "0.0.0.0,::"
#define APPLICATION_HTTPD_DEFAULT_PORT	8080

using input_template_map = std::map<const std::string, std::unique_ptr<input>>;
using input_map = tbb::concurrent_hash_map<const std::string, std::unique_ptr<input>>;
using protocol_map = std::map<const std::string, std::unique_ptr<proto>>;

class application {

	public:

		application();
		~application();

		void main_loop(std::chrono::seconds main_sleep);
		void halt() { running_ = false; };
		bool load_config(std::string &file);
		void start_httpd();

	private:
		bool running_ = true;

		task_executor_ptr executor_;

		std::unique_ptr<httpd> httpd_;

		input_template_map input_templates_;
		input_map inputs_;
		protocol_map protocols_;

		std::string httpd_addr_ = APPLICATION_HTTPD_DEFAULT_ADDRESS;
		uint16_t httpd_port_ = APPLICATION_HTTPD_DEFAULT_PORT;


		// HTTPD API
		int api_input_templates(rapidjson::Document &doc, const rapidjson::Document &param) const;
		int api_input_create(rapidjson::Document &doc, const rapidjson::Document &param);
		int api_input_show(input *input, rapidjson::Document &res, const rapidjson::Document &param) const;
		int api_input_destroy(input *input, rapidjson::Document &res, const rapidjson::Document &param);
		int api_input_update(input *input, rapidjson::Document &res, const rapidjson::Document &param);
};

#endif

