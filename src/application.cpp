

#include <thread>
#include <yaml.h>
#include <iostream>

#include "application.h"

#include "input/input_pcap.h"

application::application() : httpd_(std::make_unique<httpd>(this)) {

	// Register all available inputs
	input_templates_.insert(std::make_pair("pcap_interface", std::make_unique<input_pcap_interface> ()));
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

	input_pcap_interface input1;

	while (running_) {
		std::this_thread::sleep_for(main_sleep);
	}
}



const input_template_map& application::get_input_templates() const {

	return input_templates_;
}
