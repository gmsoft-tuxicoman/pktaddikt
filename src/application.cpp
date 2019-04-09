

#include <thread>
#include <yaml.h>
#include <iostream>

#include "application.h"


application::application() {

	registry_.add_class("input");
	registry_.add_class("output");
	registry_.add_class("protocol");
	registry_.add_class("datastore");
	registry_.add_class("objectstore");

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

	httpd_.bind(httpd_addr_, httpd_port_);
}

void application::main_loop(std::chrono::seconds main_sleep) {

	while (running_) {
		std::this_thread::sleep_for(main_sleep);
	}
}
