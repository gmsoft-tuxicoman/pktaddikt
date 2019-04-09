
#include <microhttpd.h>

class http_connection {

	private:
		unsigned int status_code = MHD_HTTP_OK;
		MHD_Response *response = nullptr;


};
