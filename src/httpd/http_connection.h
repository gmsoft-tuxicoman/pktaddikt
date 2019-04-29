
#ifndef __HTTP_CONNECTION_H__
#define __HTTP_CONNECTION_H__

#include <microhttpd.h>

enum http_connection_type { api, status, not_found };

struct http_connection {

	unsigned int status_code = MHD_HTTP_OK;
	MHD_Response *response = nullptr;

	std::string mime_type = "application/json";
	bool need_input_data = false;
	std::vector<char> input_data;

	http_connection_type type;

};

#endif
