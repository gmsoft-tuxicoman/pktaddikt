

#include "api_status.h"

#include "config.h"

unsigned int api_status::call(rapidjson::Document &doc, const std::string *data) {

	rapidjson::Document::AllocatorType& allocator = doc.GetAllocator();

	doc.AddMember("status", MHD_HTTP_OK, allocator);
	doc.AddMember("version", PKTADDIKT_VERSION, allocator);

	return MHD_HTTP_OK;
}
