#ifndef __API_ENDPOINT_H__
#define __API_ENDPOINT_H__


#include <string>

#include <microhttpd.h>
#include "http_connection.h"

#include "rapidjson/document.h"

class api_endpoint {

	public:
		virtual unsigned int call(rapidjson::Document &doc, const std::string *data) = 0;


};


#endif
