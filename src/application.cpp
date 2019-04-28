

#include <thread>
#include <yaml.h>
#include <iostream>

#include "application.h"

#include "input/input_pcap.h"

application::application() : httpd_(std::make_unique<httpd>(this)) {

	// Register all available inputs
	input_templates_.insert(std::make_pair("pcap_interface", std::make_unique<input_pcap_interface> ()));

	// Register GET /input/_templates
	api_endpoint input_template_api = [&] (rapidjson::Document &res, const rapidjson::Document &param) { return this->api_input_templates(res, param); };
	httpd_->api_add_endpoint(MHD_HTTP_METHOD_GET, "/input/_templates", input_template_api);

	// Register input api
	api_endpoint input_create_api = [&] (rapidjson::Document &res, const rapidjson::Document &param) { return this->api_input_create(res, param); };
	httpd_->api_add_endpoint("POST", "/input", input_create_api);
}


bool application::load_config(std::string &file) {

	YAML::Node config;
	try {
		config = YAML::LoadFile(file);
	} catch (const std::exception& e) {
		std::cout << "Unable to load config file : " << e.what() << std::endl;
		return false;
	}

	for(YAML::const_iterator it = config.begin(); it != config.end(); ++it) {
		std::cout << "Got " << it->first.as<std::string>() << std::endl;
	}


	return true;
}

void application::start_httpd() {

	httpd_->bind(httpd_addr_, httpd_port_);
}

void application::main_loop(std::chrono::seconds main_sleep) {

	while (running_) {
		std::this_thread::sleep_for(main_sleep);
	}
}


int application::api_input_templates(rapidjson::Document &res, const rapidjson::Document &param) const {
	rapidjson::Document::AllocatorType& allocator = res.GetAllocator();
	res.AddMember("status", MHD_HTTP_OK, allocator);
	for (auto const &input : input_templates_) {
		rapidjson::Value input_json;
		input_json.SetObject();
		const auto &parameters = input.second->get_parameters();
		for (auto const &param : parameters) {
			rapidjson::Value param_json;
			param_json.SetObject();
			param_json.AddMember("description", param.second->get_description(), allocator);
			param_json.AddMember("type", param.second->get_type(), allocator);
			param_json.AddMember("default_value", param.second->print_default_value(), allocator);

			input_json.AddMember(rapidjson::StringRef(param.first), param_json, allocator);
		}

		res.AddMember(rapidjson::StringRef(input.first), input_json, allocator);
	}

	return MHD_HTTP_OK;
}

int application::api_input_create(rapidjson::Document &res, const rapidjson::Document &param) {

	return MHD_HTTP_OK;
}
