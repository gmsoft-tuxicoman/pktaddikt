
#ifndef __HTTP_EXCEPTION_H__
#define __HTTP_EXCEPTION_H__

#include <exception>

class http_exception : public std::runtime_error {

	public:
		http_exception(unsigned int status_code, const char *what): std::runtime_error(what), status_code_(status_code) {};
		unsigned int status_code() { return status_code_; };
	protected:
		unsigned int status_code_;
	
};


#endif
