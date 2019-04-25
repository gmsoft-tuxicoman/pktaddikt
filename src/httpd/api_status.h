

#include "api_endpoint.h"

class api_status : public api_endpoint {

	unsigned int call(rapidjson::Document &doc, const std::string *data);

};
