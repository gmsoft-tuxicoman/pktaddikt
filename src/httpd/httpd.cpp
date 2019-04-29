
#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>


#include <arpa/inet.h>

#include "httpd.h"
#include "http_exception.h"

#include "rapidjson/prettywriter.h"

#define HTTP_ADDR_DELIMITERS ",; "


httpd::httpd(const application* app) : app_(app) {

	// Register GET /status API endpoint
	api_endpoint status_api = [] (rapidjson::Document &res, const rapidjson::Document &param) {
		rapidjson::Document::AllocatorType& allocator = res.GetAllocator();
		res.AddMember("status", MHD_HTTP_OK, allocator);
		res.AddMember("version", PKTADDIKT_VERSION, allocator);
		return MHD_HTTP_OK;
	};
	api_add_endpoint(MHD_HTTP_METHOD_GET, "/status", status_api);


}

void httpd::enable_ssl(const std::string& cert, const std::string& key) {

	ssl_cert_ = std::make_unique<std::string> (cert);
	ssl_key_ = std::make_unique<std::string> (key);
	flags_ |= MHD_USE_SSL;

}

void httpd::disable_ssl() {
	flags_ &= ~MHD_USE_SSL;
}

int httpd::_static_mhd_answer_connection(void* cls, struct MHD_Connection *connection, const char *url, const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **con_cls) {

	if (cls == nullptr)
		return MHD_NO;

	httpd* h = static_cast<httpd*> (cls);
	return h->mhd_answer_connection(connection, url, method, version, upload_data, upload_data_size, con_cls);
}

void httpd::_static_mhd_request_completed(void *cls, struct MHD_Connection *connection, void **con_cls, enum MHD_RequestTerminationCode toe) {

	if (cls == nullptr)
		return;

	httpd* h = static_cast<httpd*> (cls);
	h->mhd_request_completed(connection, con_cls, toe);
}


bool httpd::bind(const std::string& addr, uint16_t port) {

	std::cout << "Binding to addr(s) " << addr << " on port " << port << std::endl;


	std::size_t start = 0, end;
	while (start != std::string::npos) {

		end = addr.find_first_of(HTTP_ADDR_DELIMITERS, start);
		if (end == start) {
			start++;
			continue;
		}


		// Get the addr
		struct addrinfo hints = { 0 };
		hints.ai_flags = AI_PASSIVE;
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;


		struct addrinfo *res;
		std::string cur_addr = addr.substr(start, end - start);
		start = end;

		if (getaddrinfo(cur_addr.c_str(), NULL, &hints, &res) < 0) {
			std::cout << "Cannot get info for address " << cur_addr << ". Ignoring," << std::endl;
			continue;
		}

		std::unique_ptr<addrinfo, decltype(freeaddrinfo)*> addrs(res, freeaddrinfo);

		for (struct addrinfo *tmpaddr = addrs.get(); tmpaddr; tmpaddr = tmpaddr->ai_next) {

			unsigned int flags = flags_;

			if (tmpaddr->ai_family == AF_INET6) {
				struct sockaddr_in6 *addr = reinterpret_cast<sockaddr_in6*>(tmpaddr->ai_addr);
				addr->sin6_port = ntohs(port);
				flags |= MHD_USE_IPv6;
			} else if (tmpaddr->ai_family == AF_INET) {
				struct sockaddr_in *addr = reinterpret_cast<sockaddr_in*>(tmpaddr->ai_addr);
				addr->sin_port = ntohs(port);
			} else {
				continue;
			}

			MHD_Daemon *d = NULL;
			if (flags_ & MHD_USE_SSL) {
				d = MHD_start_daemon(flags, port, NULL, NULL, &(httpd::_static_mhd_answer_connection), this, MHD_OPTION_SOCK_ADDR, tmpaddr->ai_addr, MHD_OPTION_NOTIFY_COMPLETED, &(httpd::_static_mhd_request_completed), NULL, MHD_OPTION_HTTPS_MEM_CERT, &ssl_cert_, MHD_OPTION_HTTPS_MEM_KEY, &ssl_key_, MHD_OPTION_END);
			} else {
				d = MHD_start_daemon(flags, port, NULL, NULL, &(httpd::_static_mhd_answer_connection), this, MHD_OPTION_SOCK_ADDR, tmpaddr->ai_addr, MHD_OPTION_NOTIFY_COMPLETED, &(httpd::_static_mhd_request_completed), NULL, MHD_OPTION_END);
			}

			if (d) {
				daemons_.push_back({d, MHD_stop_daemon});
			} else {
				std::cout << "Error while starting http daemon on address \"" << cur_addr << "\" and port " << port << std::endl;
			}
		}



	}

	return true;

}


int httpd::mhd_answer_new_connection(http_connection *con, const char *method, const char* url) {

	std::string_view api_url{HTTPD_API_URL};
	std::string_view status_url{HTTPD_STATUS_URL};

	std::string_view request_method{method};
	std::string_view request_url{url};
	std::cout << "GOT REQUEST | " << request_method << " " << request_url << std::endl;

	if (!request_url.compare(0, api_url.size(), api_url)) {

		if (request_method == MHD_HTTP_METHOD_POST) {
			con->need_input_data = true;
		}
		con->type = api;
	} else if (request_url == status_url) {
		con->type = status;
	} else {
		con->type = not_found;
	}

	return MHD_YES;
}

int httpd::mhd_answer_connection(struct MHD_Connection *connection, const char *url, const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **con_cls) {

	http_connection *con = static_cast<http_connection*> (*con_cls);

	if (con == nullptr) {
		// New request
		con = new http_connection();
		*con_cls = con;
		return mhd_answer_new_connection(con, method, url);;
	}

	if (*upload_data_size) {
		if (con->need_input_data) {
			// Accumulate all the input in a vector
			con->input_data.insert(con->input_data.end(), upload_data, upload_data + *upload_data_size);
		}
		*upload_data_size = 0;
		return MHD_YES;
	}

	if (con->type == api) {
		std::string_view request_url{url};
		std::string_view api_url{HTTPD_API_URL};
		request_url.remove_prefix(api_url.size());
		std::string key = method;
		key += request_url;


		// Result to send back
		rapidjson::Document ret;
		ret.SetObject();

		try {
			api_endpoint_map::const_accessor ac;
			const bool endpoint = api_endpoints_.find(ac, key);

			if (!endpoint) {
				throw http_exception(MHD_HTTP_NOT_FOUND, "No API endpoint for specified method and URL");
			}

			rapidjson::Document param;
			if (con->input_data.size() > 0) {
				rapidjson::MemoryStream stream(con->input_data.data(), con->input_data.size());
				param.ParseStream(stream);
				if (!param.IsObject()) {
					throw http_exception(MHD_HTTP_BAD_REQUEST, "Root JSON is not an object");
				}
			} else {
				param.SetObject();
			}

			rapidjson::Document out;
			out.SetObject();

			unsigned int status = ac->second(out, param);
			con->status_code = status;
			ac.release();

			// No exception occured, used the API call output
			ret = std::move(out);
		} catch (http_exception &e) {
			con->status_code = e.status_code();
			ret.AddMember("status", e.status_code(), ret.GetAllocator());
			ret.AddMember("error", rapidjson::StringRef(e.what()), ret.GetAllocator());
		} catch (std::exception &e) {
			con->status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
			ret.AddMember("status", con->status_code, ret.GetAllocator());
			ret.AddMember("error", rapidjson::StringRef(e.what()), ret.GetAllocator());
		}

		rapidjson::StringBuffer sb;
		rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(sb);
		ret.Accept(writer);

		// FIXME there is a better way to do this
		con->response = MHD_create_response_from_buffer(sb.GetSize(), (void*)sb.GetString(), MHD_RESPMEM_MUST_COPY);


	} else if (con->type == status) {
		std::cout << "GET A STATUS CALL : " << url << std::endl;
		std::string_view replystr = "<html><body>It works !</body></html>";

		con->response = MHD_create_response_from_buffer(replystr.size(), (void*)(replystr.data()), MHD_RESPMEM_MUST_COPY);
		con->mime_type = "text/html";
	} else if (con->type == not_found) {
		con->status_code = MHD_HTTP_NOT_FOUND;
		con->response = MHD_create_response_from_buffer(strlen(HTTPD_ANSWER_NOT_FOUND), (void*)HTTPD_ANSWER_NOT_FOUND, MHD_RESPMEM_PERSISTENT);
	} else {
		con->status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
		con->response = MHD_create_response_from_buffer(strlen(HTTPD_ANSWER_ERROR), (void*)HTTPD_ANSWER_ERROR, MHD_RESPMEM_PERSISTENT);
	}

	if (!con->response) {
		std::cout << "Error while creating response for request \"" << url << "\"" << std::endl;
		return MHD_NO;
	}

	if (!con->mime_type.empty() && MHD_add_response_header(con->response, MHD_HTTP_HEADER_CONTENT_TYPE, con->mime_type.c_str()) == MHD_NO) {
		std::cout << "Error, could not add " MHD_HTTP_HEADER_CONTENT_TYPE " header to the response" << std::endl;
		return MHD_NO;
	}

	if (MHD_add_response_header(con->response, MHD_HTTP_HEADER_SERVER, HTTPD_SERVER_STRING) == MHD_NO) {
		std::cout << "Error, could not add " MHD_HTTP_HEADER_SERVER " header to the response" << std::endl;
		return MHD_NO;
	}

	if (MHD_queue_response(connection, con->status_code, con->response) == MHD_NO) {
		std::cout << "Error, could not queue HTTP response" << std::endl;
		return MHD_NO;
	}


	return MHD_YES;
}

void httpd::mhd_request_completed(struct MHD_Connection *connection, void **con_cls, enum MHD_RequestTerminationCode toe) {

	if (*con_cls == nullptr)
		return;

	http_connection* con = static_cast<http_connection*> (*con_cls);
	delete con;
}
void httpd::api_add_endpoint(const std::string &method, const std::string &path, api_endpoint endpoint) {

	api_endpoint_map::accessor ac;
	std::string entry = method + path;
	api_endpoints_.insert(ac, entry);
	ac->second = std::move(endpoint);
	ac.release();
}

void httpd::api_remove_endpoint(const std::string &method, const std::string &path) {

	std::string entry = method + path;
	api_endpoints_.erase(entry);
}
