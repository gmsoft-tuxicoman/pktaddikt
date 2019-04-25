
#ifndef __HTTP_CONNECTION_H__
#define __HTTP_CONNECTION_H__

#include <microhttpd.h>

struct http_connection {

	unsigned int status_code = MHD_HTTP_OK;
	MHD_Response *response = nullptr;
	std::string mime_type = "application/json";


};

#endif
