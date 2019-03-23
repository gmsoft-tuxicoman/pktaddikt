
#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <cstring>


#include "httpd.h"


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

bool httpd::bind(const std::string& addr, uint16_t port) {

	std::cout << "Binding to addr(s) " << addr << " on port " << port << std::endl;

	char *addr_tmp = strdup(addr.c_str());

	char *str, *token, *saveptr = NULL;
	for (str = addr_tmp; ; str = NULL) {
		token = strtok_r(str, ",; ", &saveptr);
		if (!token)
			break;

		// Get the addr
		struct addrinfo hints = { 0 };
		hints.ai_flags = AI_PASSIVE;
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;


		struct addrinfo *res;
		if (getaddrinfo(token, NULL, &hints, &res) < 0) {
			std::cout << "Cannot get info for address " << token << ". Ignoring," << std::endl;
			continue;
		}

		for (struct addrinfo *tmpres = res; tmpres; tmpres = tmpres->ai_next) {
			MHD_Daemon *d = NULL;
			if (flags_ & MHD_USE_SSL) {
				d = MHD_start_daemon(flags_, port, NULL, NULL, &(httpd::_static_mhd_answer_connection), this, MHD_OPTION_SOCK_ADDR, tmpres->ai_addr, MHD_OPTION_HTTPS_MEM_CERT, &ssl_cert_, MHD_OPTION_HTTPS_MEM_KEY, &ssl_key_, MHD_OPTION_END);
			} else {
				d = MHD_start_daemon(flags_, port, NULL, NULL, &(httpd::_static_mhd_answer_connection), this, MHD_OPTION_SOCK_ADDR, tmpres->ai_addr, tmpres->ai_addr, MHD_OPTION_END);
			}

			if (d) {
				daemons_.push_back({d, MHD_stop_daemon});
			} else {
				std::cout << "Error while starting http daemon on address \"" << token << "\" and port " << port << std::endl;
			}
		}

		freeaddrinfo(res);


	}

	free(addr_tmp);

	return true;

}



int httpd::mhd_answer_connection(struct MHD_Connection *connection, const char *url, const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **con_cls) {

	return 0;
}
