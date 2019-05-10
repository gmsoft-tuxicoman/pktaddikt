#ifndef __PKT_BUFFER_H__
#define __PKT_BUFFER_H__


#include <cstddef>
#include <cstring>


class pkt_buffer {

	public:
		pkt_buffer(std::size_t size, unsigned char *data): size_(size), buff_(data) {};

		virtual ~pkt_buffer() {};

		const unsigned char *read(std::size_t size);
		std::size_t remaining();


	protected:
		unsigned char *buff_;
		std::size_t pos_ = 0;
		const std::size_t size_ = 0;

};

class pkt_buffer_copy : public pkt_buffer {

	public:
		pkt_buffer_copy(std::size_t size, const unsigned char *data): pkt_buffer(size, new unsigned char[size]) {
			memcpy(buff_, data, size);
		}

		~pkt_buffer_copy() {
			delete buff_;	
		}
};

class pkt_buffer_ref : public pkt_buffer {

	public:
		pkt_buffer_ref(std::size_t size, unsigned char *data): pkt_buffer(size, data) {};

};


#endif
