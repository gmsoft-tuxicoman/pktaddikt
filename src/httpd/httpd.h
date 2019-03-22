#include <memory>
#include <vector>
#include <string>
#include <microhttpd.h>

class httpd {

	public:
		httpd();
		~httpd();
		
		void enable_ssl(const std::string& cert,const std::string& key);
		void disable_ssl();
		bool bind(const std::string& addr, uint16_t port);

	private:
		MHD_Daemon *daemon_;
		unsigned int flags_;
		uint16_t port_;
		std::unique_ptr<std::string> ssl_cert_;
		std::unique_ptr<std::string> ssl_key_;
		std::vector<std::unique_ptr<MHD_Daemon, std::function<void(MHD_Daemon*)>>> daemons_;

		static int _static_mhd_answer_connection(void *cls, struct MHD_Connection *connection, const char *url, const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **con_cls);
		int mhd_answer_connection(struct MHD_Connection *connection, const char *url, const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **con_cls);

};

