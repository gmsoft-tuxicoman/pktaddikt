#include <iostream>

#include <getopt.h>
#include <signal.h>

#include "application.h"


#define MAIN_LOOP_SLEEP_SEC 1

application *app = nullptr;

void signal_handler(int signal) {

	switch (signal) {
		case SIGCHLD:
			break;
		case SIGINT:
		case SIGTERM:
		default:
			std::cout << "Main process received signal " << signal << ", shutting down ..." << std::endl;
			app->halt();
			break;

	}
}

void print_usage() {

	std::cout << "Usage : " << std::endl;

}

int main(int argc, char *argv[]) {

	std::string cfg_file = "pktaddikt.yml";

	// Parse command line

	int c;
	while (1) {
		static struct option long_options[] = {
			{ "config", 1, 0, 'c' },
			{ 0 }
		};

		const char* args = "c:";

		c = getopt_long(argc, argv, args, long_options, NULL);

		if (c == -1)
			break;

		switch (c) {
			case 'c': {
				cfg_file = optarg;
				break;
			}
			default: {
				print_usage();
				return 1;
			}
		}
	}

	// Instanciate the app object
	app = new application;

	// Install signal handler

	struct sigaction mysigaction;
	sigemptyset(&mysigaction.sa_mask);
	mysigaction.sa_flags = 0;
	mysigaction.sa_handler = signal_handler;
	sigaction(SIGINT, &mysigaction, NULL);
	sigaction(SIGTERM, &mysigaction, NULL);
	sigaction(SIGCHLD, &mysigaction, NULL);

	// Load the config file
	app->load_config(cfg_file);

	// Start the web server
	app->start_httpd();

	std::chrono::seconds main_sleep(MAIN_LOOP_SLEEP_SEC);
	app->main_loop(main_sleep);

	// Cleanup the app object
	delete app;

	std::cout << "Finished" << std::endl;
}
