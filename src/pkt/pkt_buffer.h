#ifndef __PKT_BUFFER_H__
#define __PKT_BUFFER_H__


#include <cstddef>
#include <cstring>


class pkt_buffer {

	public:
		pkt_buffer(std::size_t size, unsigned char *data): orig_size_(size), orig_buff_(data), buff_(data), end_(data + size) {};

		virtual ~pkt_buffer() {};

		std::size_t remaining();
		void set_remaining(std::size_t remaining);

		uint8_t read_bits8(std::size_t bit_offset, std::size_t bit_len);

		uint8_t	read_8(std::size_t offset);
		uint16_t read_ntoh16(std::size_t offset);
		void read(void *dst, std::size_t src_offset, std::size_t size);

		void consume(std::size_t size);

	protected:
		unsigned char *orig_buff_ = nullptr;
		unsigned char *buff_ = nullptr;
		unsigned char *end_ = nullptr;
		const std::size_t orig_size_ = 0;

		void boundary_check(std::size_t size, std::size_t offset);

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
