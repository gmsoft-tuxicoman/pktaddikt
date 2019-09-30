#ifndef __PKT_BUFFER_H__
#define __PKT_BUFFER_H__


#include <chrono>
#include <cstddef>
#include <cstring>
#include <memory>

using pkt_buffer_timestamp = std::chrono::duration<uint64_t, std::micro>;

class pkt_buffer {

	public:

		virtual ~pkt_buffer() {};

		uint8_t read_bits8(std::size_t bit_offset, std::size_t bit_len);

		uint8_t	read_8(std::size_t offset);
		uint16_t read_ntoh16(std::size_t offset);
		void read(void *dst, std::size_t src_offset, std::size_t size);

		std::size_t get_size() { return size_; };

	protected:
		pkt_buffer(pkt_buffer_timestamp ts, std::size_t size, unsigned char *data): ts_(ts), size_(size), data_(data) {};
		pkt_buffer(const pkt_buffer &buf);
		unsigned char *data_;
		std::size_t size_;
		pkt_buffer_timestamp ts_;

		const unsigned char *safe_ptr(const std::size_t offset, const std::size_t size);

};

using pkt_buffer_ptr = std::shared_ptr<pkt_buffer>;

class pkt_buffer_copy : public pkt_buffer {

	public:
		pkt_buffer_copy(pkt_buffer_timestamp ts, std::size_t size, const unsigned char * data) : pkt_buffer(ts, size, nullptr) {
			data_ = new unsigned char[size];
			memcpy(data_, data, size);
		}

		~pkt_buffer_copy() {
			delete[] data_;
		}

};

class pkt_buffer_part : public pkt_buffer {

	public:
		pkt_buffer_part(pkt_buffer_ptr src, std::size_t offset, std::size_t size) : pkt_buffer(*src) {
			data_ += offset;
			parent_ = src;
		}
		pkt_buffer_part(pkt_buffer_ptr src, std::size_t offset) : pkt_buffer(*src) {
			data_ += offset;
			parent_ = src;
			size_ -= offset;
		}

	protected:
		pkt_buffer_ptr parent_;

};

#endif
