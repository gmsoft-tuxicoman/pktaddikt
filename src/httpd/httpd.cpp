
#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>



#include "httpd.h"
#include "http_connection.h"

#define HTTP_ADDR_DELIMITERS ",; "

void httpd::enable_ssl(const std::string& cert,const std::string& key) {

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
			MHD_Daemon *d = NULL;
			if (flags_ & MHD_USE_SSL) {
				d = MHD_start_daemon(flags_, port, NULL, NULL, &(httpd::_static_mhd_answer_connection), this, MHD_OPTION_SOCK_ADDR, tmpaddr->ai_addr, MHD_OPTION_NOTIFY_COMPLETED, &(httpd::_static_mhd_request_completed), NULL, MHD_OPTION_HTTPS_MEM_CERT, &ssl_cert_, MHD_OPTION_HTTPS_MEM_KEY, &ssl_key_, MHD_OPTION_END);
			} else {
				d = MHD_start_daemon(flags_, port, NULL, NULL, &(httpd::_static_mhd_answer_connection), this, MHD_OPTION_SOCK_ADDR, tmpaddr->ai_addr, MHD_OPTION_NOTIFY_COMPLETED, &(httpd::_static_mhd_request_completed), NULL, MHD_OPTION_END);
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



int httpd::mhd_answer_connection(struct MHD_Connection *connection, const char *url, const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **con_cls) {

	http_connection *con = static_cast<http_connection*> (*con_cls);

	if (con == nullptr) {
		con = new http_connection();
		*con_cls = con;
	}


	return MHD_YES;
}

void httpd::mhd_request_completed(struct MHD_Connection *connection, void **con_cls, enum MHD_RequestTerminationCode toe) {

	if (*con_cls == nullptr)
		return;

	http_connection* con = static_cast<http_connection*> (*con_cls);
	delete con;
}
