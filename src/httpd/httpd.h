#ifndef __HTTPD_H__
#define __HTTPD_H__

#include <memory>
#include <vector>
#include <string>
#include <functional>
#include <microhttpd.h>

#include "tbb/concurrent_hash_map.h"

class httpd;

#include "application.h"
#include "config.h"

#include "api_endpoint.h"


#define HTTPD_SERVER_STRING "pktaddikt " PKTADDIKT_VERSION
#define HTTPD_API_URL	"/api/v1"
#define HTTPD_STATUS_URL "/status.html"

using api_endpoint_map = tbb::concurrent_hash_map<const std::string, std::unique_ptr<api_endpoint>>;

class httpd {

	public:

		httpd(const application* app);
		
		void enable_ssl(const std::string& cert,const std::string& key);
		void disable_ssl();
		bool bind(const std::string& addr, uint16_t port);

		void api_add_endpoint(const std::string &method, const std::string &path, std::unique_ptr<api_endpoint> endpoint);
		void api_remove_endpoint(const std::string &method, const std::string &path);



	private:
		MHD_Daemon *daemon_;
		unsigned int flags_ = MHD_USE_THREAD_PER_CONNECTION | MHD_USE_INTERNAL_POLLING_THREAD | MHD_USE_POLL | MHD_USE_DEBUG | MHD_USE_PIPE_FOR_SHUTDOWN;
		uint16_t port_;
		std::unique_ptr<std::string> ssl_cert_;
		std::unique_ptr<std::string> ssl_key_;
		std::vector<std::unique_ptr<MHD_Daemon, std::function<void(MHD_Daemon*)>>> daemons_;

		static int _static_mhd_answer_connection(void *cls, struct MHD_Connection *connection, const char *url, const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **con_cls);
		int mhd_answer_connection(struct MHD_Connection *connection, const char *url, const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **con_cls);

		static void _static_mhd_request_completed(void *cls, struct MHD_Connection *connection, void **con_cls, enum MHD_RequestTerminationCode toe);
		void mhd_request_completed(struct MHD_Connection *connection, void **con_cls, enum MHD_RequestTerminationCode toe);

		const application *app_;

		api_endpoint_map api_endpoints_;
};


#endif
