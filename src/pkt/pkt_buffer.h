#ifndef __PKT_BUFFER_H__
#define __PKT_BUFFER_H__


#include <cstddef>
#include <cstring>

using pkt_buffer_data_ptr = std::shared_ptr<unsigned char *>;

class pkt_buffer {

	public:
		pkt_buffer(std::size_t size, pkt_buffer_data_ptr data): data_size_(size), size_(size), data_(data), offset(0) {};

		virtual ~pkt_buffer() {};

		uint8_t read_bits8(std::size_t bit_offset, std::size_t bit_len);

		uint8_t	read_8(std::size_t offset);
		uint16_t read_ntoh16(std::size_t offset);
		void read(void *dst, std::size_t src_offset, std::size_t size);

	protected:
		pkt_buffer_data_ptr data_;
		const std::size_t data_size_;

		const std::size_t offset_ = 0;
		const std::size_t size_;

		const unsigned char *safe_ptr(std::size_t offset, std::size_t size);

};

#endif
