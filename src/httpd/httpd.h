#include <memory>
#include <vector>
#include <string>
#include <functional>
#include <microhttpd.h>

class httpd {

	public:
		
		void enable_ssl(const std::string& cert,const std::string& key);
		void disable_ssl();
		bool bind(const std::string& addr, uint16_t port);

	private:
		MHD_Daemon *daemon_;
		unsigned int flags_ = MHD_USE_THREAD_PER_CONNECTION | MHD_USE_POLL | MHD_USE_DEBUG | MHD_USE_PIPE_FOR_SHUTDOWN;
		uint16_t port_;
		std::unique_ptr<std::string> ssl_cert_;
		std::unique_ptr<std::string> ssl_key_;
		std::vector<std::unique_ptr<MHD_Daemon, std::function<void(MHD_Daemon*)>>> daemons_;

		static int _static_mhd_answer_connection(void *cls, struct MHD_Connection *connection, const char *url, const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **con_cls);
		int mhd_answer_connection(struct MHD_Connection *connection, const char *url, const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **con_cls);

};

