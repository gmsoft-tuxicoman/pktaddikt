

#include <thread>
#include <yaml.h>
#include <iostream>

#include "application.h"
#include "httpd/http_exception.h"

#include "input/input_pcap.h"

const char *component_name_invalid_char = "\\/.%&=";

application::application() : httpd_(std::make_unique<httpd>(this)) {

	// Register all available inputs
	input_templates_.insert(std::make_pair("pcap_interface", std::make_unique<input_pcap_interface> ("pcap_interface")));

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
	for (auto const &input : input_templates_) {
		rapidjson::Value input_json;
		input_json.SetObject();

		rapidjson::Value input_params_json;
		input_params_json.SetObject();

		const auto &parameters = input.second->get_parameters();
		for (auto const &input_param : parameters) {
			rapidjson::Value param_json;
			param_json.SetObject();
			param_json.AddMember("description", input_param.second->get_description(), allocator);
			param_json.AddMember("type", input_param.second->get_type(), allocator);
			param_json.AddMember("default_value", input_param.second->print_default_value(), allocator);

			input_params_json.AddMember(rapidjson::StringRef(input_param.first), param_json, allocator);
		}
		input_json.AddMember("parameters", input_params_json, allocator);

		res.AddMember(rapidjson::StringRef(input.first), input_json, allocator);

	}

	return MHD_HTTP_OK;
}


int application::api_input_show(input *input, rapidjson::Document &res, const rapidjson::Document &param) const {
	rapidjson::Document::AllocatorType& allocator = res.GetAllocator();

	res.AddMember("name", input->get_name(), allocator);

	rapidjson::Value params_json;
	params_json.SetObject();

	const auto &parameters = input->get_parameters();
	for (auto const &input_param : parameters) {
		rapidjson::Value param_json;
		param_json.SetObject();
		param_json.AddMember("type", input_param.second->get_type(), allocator);
		param_json.AddMember("description", input_param.second->get_description(), allocator);
		param_json.AddMember("default_value", input_param.second->print_default_value(), allocator);
		param_json.AddMember("value", input_param.second->print_value(), allocator);


		params_json.AddMember(rapidjson::StringRef(input_param.first), param_json, allocator);

	}

	res.AddMember("parameters", params_json, allocator);

	return MHD_HTTP_OK;
}


int application::api_input_create(rapidjson::Document &res, const rapidjson::Document &param) {

	if (!param.HasMember("name") || !param["name"].IsString()) {
		throw http_exception(MHD_HTTP_BAD_REQUEST, "Input name not specified or invalid");
	}

	if (!param.HasMember("template") || !param["template"].IsString()) {
		throw http_exception(MHD_HTTP_BAD_REQUEST, "Input template type not specified or invalid");
	}

	// Check name validity
	std::string name = param["name"].GetString();
	std::string template_name = param["template"].GetString();

	if (name.size() < 1) {
		throw http_exception(MHD_HTTP_BAD_REQUEST, "Input name is empty");
	} else if (name[0] == '_') {
		throw http_exception(MHD_HTTP_FORBIDDEN, "Input name cannot start with an underscore");
	} else if (name.find_first_of(component_name_invalid_char) != std::string::npos) {
		throw http_exception(MHD_HTTP_FORBIDDEN, "Input name contains invalid characters");
	}

	input_template_map::iterator it = input_templates_.find(template_name);
	if (it == input_templates_.end()) {
		throw http_exception(MHD_HTTP_BAD_REQUEST, "Input template not found");
	}

	input_map::accessor ac;
	if (!inputs_.insert(ac, name)) {
		throw http_exception(MHD_HTTP_CONFLICT, "Requested input name already exists");
	}

	try {
		input *new_input = it->second->clone(name);

		api_endpoint input_show_api = [&, new_input] (rapidjson::Document &res, const rapidjson::Document &param) { return this->api_input_show(new_input, res, param); };
		httpd_->api_add_endpoint(MHD_HTTP_METHOD_GET, std::string("/input/") + name, input_show_api);

		api_endpoint input_destroy_api = [&, new_input] (rapidjson::Document &res, const rapidjson::Document &param) { return this->api_input_destroy(new_input, res, param); };
		httpd_->api_add_endpoint(MHD_HTTP_METHOD_DELETE, std::string("/input/") + name, input_destroy_api);


		res.AddMember("msg", "Input added", res.GetAllocator());

		std::cout << "Input " << name << " of type " << template_name << " added" << std::endl;
	} catch (std::exception &e) {
		std::cout << "Error while adding input " << name << " : " << e.what() << std::endl;
		throw http_exception(MHD_HTTP_INTERNAL_SERVER_ERROR, std::string("Error while adding the new input : ") + e.what());
	}

	return MHD_HTTP_CREATED;
}

int application::api_input_destroy(input *input, rapidjson::Document &res, const rapidjson::Document &param) {

	input_map::accessor ac;
	if (!inputs_.find(ac, input->get_name())) {
		throw http_exception(MHD_HTTP_INTERNAL_SERVER_ERROR, "Input not found");
	}

	httpd_->api_remove_endpoint(MHD_HTTP_METHOD_GET, std::string("/input/") + input->get_name());
	httpd_->api_remove_endpoint(MHD_HTTP_METHOD_DELETE, std::string("/input/") + input->get_name());

	inputs_.erase(ac);

	res.AddMember("msg", "Input deleted", res.GetAllocator());
	return MHD_HTTP_OK;

}
