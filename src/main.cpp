#include <iostream>

#include <getopt.h>

#include "httpd/httpd.h"

void print_usage() {

	std::cout << "Usage : " << std::endl;

}

int main(int argc, char *argv[]) {

	std::cout << "Hello world\n";

	std::string cfg_file = "pktaddikt.yml";

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

	httpd blah;

	blah.bind("0.0.0.0", 8080);

}
