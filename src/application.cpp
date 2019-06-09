

#include <thread>
#include <yaml.h>

#include "application.h"
#include "httpd/http_exception.h"

#include "input/input_pcap.h"


#include "proto/proto_ethernet.h"
#include "proto/proto_ipv4.h"

#include "logger.h"

const char *component_name_invalid_char = "\\/.%&=";

application::application() : httpd_(std::make_unique<httpd>(this)) {

	executor_ = std::make_shared<main_task_executor>();

	// Init the logger
	logger_ = new logger(executor_);

	// Register all available inputs
	input_templates_.insert(std::make_pair("pcap_interface", std::move(std::make_unique<input_pcap_interface> ("pcap_interface", executor_))));
	input_templates_.insert(std::make_pair("pcap_file", std::move(std::make_unique<input_pcap_file> ("pcap_file", executor_))));

	// Register GET /input/_templates
	api_endpoint input_template_api = [&] (rapidjson::Document &res, const rapidjson::Document &param) { return this->api_input_templates(res, param); };
	httpd_->api_add_endpoint(MHD_HTTP_METHOD_GET, "/input/_templates", input_template_api);

	// Register input api
	api_endpoint input_create_api = [&] (rapidjson::Document &res, const rapidjson::Document &param) { return this->api_input_create(res, param); };
	httpd_->api_add_endpoint("POST", "/input", input_create_api);


	// Register all available proto
	protocols_.insert(std::make_pair("ethernet", std::move(std::make_unique<proto_ethernet>(nullptr))));
	proto_ethernet::register_number();
	protocols_.insert(std::make_pair("ipv4", std::move(std::make_unique<proto_ipv4>(nullptr))));
	proto_ipv4::register_number();

	// Register proto api
	//api_endpoint proto_list_api = [&] (rapidjson::Document &res, const rapidjson::Document &param) { return this->proto_list_api(res, param); };
}

application::~application() {

	for (input_map::iterator it = inputs_.begin(); it != inputs_.end(); it++) {
		if (it->second->get_running_status() == input::running_status::running) {
			it->second->stop();
		}
	}

}


bool application::load_config(std::string &file) {

	YAML::Node config;
	try {
		config = YAML::LoadFile(file);
	} catch (const std::exception& e) {
		LOG_ERROR << "Unable to load config file : " << e.what();
		return false;
	}

	for(YAML::const_iterator it = config.begin(); it != config.end(); ++it) {
		LOG_DEBUG << "Got " << it->first.as<std::string>();
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

		api_endpoint input_show_api = [this, new_input] (rapidjson::Document &res, const rapidjson::Document &param) { return this->api_input_show(new_input, res, param); };
		httpd_->api_add_endpoint(MHD_HTTP_METHOD_GET, std::string("/input/") + name, input_show_api);

		api_endpoint input_destroy_api = [this, new_input] (rapidjson::Document &res, const rapidjson::Document &param) { return this->api_input_destroy(new_input, res, param); };
		httpd_->api_add_endpoint(MHD_HTTP_METHOD_DELETE, std::string("/input/") + name, input_destroy_api);

		api_endpoint input_update_api = [this, new_input] (rapidjson::Document &res, const rapidjson::Document &param) { return this->api_input_update(new_input, res, param); };
		httpd_->api_add_endpoint(MHD_HTTP_METHOD_PUT, std::string("/input/") + name, input_update_api);

		api_endpoint input_start_api = [new_input] (rapidjson::Document &res, const rapidjson::Document &param) { new_input->start(); return MHD_HTTP_OK; };
		httpd_->api_add_endpoint(MHD_HTTP_METHOD_POST, std::string("/input/") + name + "/start", input_start_api);

		api_endpoint input_stop_api = [new_input] (rapidjson::Document &res, const rapidjson::Document &param) { new_input->stop(); return MHD_HTTP_OK; };
		httpd_->api_add_endpoint(MHD_HTTP_METHOD_POST, std::string("/input/") + name + "/stop", input_stop_api);

		std::unique_ptr<input> new_input_ptr(new_input);
		ac->second = std::move(new_input_ptr);

		res.AddMember("msg", "Input added", res.GetAllocator());

		LOG_INFO << "Input " << name << " of type " << template_name << " added";
	} catch (std::exception &e) {
		LOG_ERROR << "Error while adding input " << name << " : " << e.what();
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
	httpd_->api_remove_endpoint(MHD_HTTP_METHOD_PUT, std::string("/input/") + input->get_name());
	httpd_->api_remove_endpoint(MHD_HTTP_METHOD_POST, std::string("/input/") + input->get_name() + "/start");

	inputs_.erase(ac);

	res.AddMember("msg", "Input deleted", res.GetAllocator());
	return MHD_HTTP_OK;

}

int application::api_input_update(input *input, rapidjson::Document &res, const rapidjson::Document &param) {

	if (!param.HasMember("parameters")) {
		throw http_exception(MHD_HTTP_BAD_REQUEST, "No parameter member");
	}

	if (!param.HasMember("parameters") || !param["parameters"].IsObject()) {
		throw http_exception(MHD_HTTP_BAD_REQUEST, "Parameters not provided or invalid");
	}

	const component_parameters& input_params = input->get_parameters();
	for (auto &m: param["parameters"].GetObject()) {
		const auto &param_name = m.name.GetString();
		if (!m.value.IsString()) {
			throw http_exception(MHD_HTTP_BAD_REQUEST, std::string("Parameter ") + param_name + " is not a string");
		}
		auto it = input_params.find(param_name);
		if (it == input_params.end()) {
			throw http_exception(MHD_HTTP_BAD_REQUEST, std::string("Parameter ") + param_name + " does not exists");
		}

		if (!it->second->parse_value(m.value.GetString())) {
			throw http_exception(MHD_HTTP_UNPROCESSABLE_ENTITY, std::string("Unable to parse parameter ") + param_name);
		}

	}


	return MHD_HTTP_OK;
}

