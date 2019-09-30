

#include <cassert>
#include <cstring>
#include <stdexcept>

#include "pkt_buffer.h"

pkt_buffer::pkt_buffer(const pkt_buffer &buf) {
	ts_ = buf.ts_;
	data_ = buf.data_;
	size_ = buf.size_;
}

uint8_t pkt_buffer::read_bits8(std::size_t bit_offset, std::size_t bit_len) {

	std::size_t offset = bit_offset >> 3;
	bit_offset %= 8;
	uint8_t data = *(safe_ptr(offset, sizeof(uint8_t)));

	data >>= (8 - (bit_offset + bit_len));
	data &= 0xff >> (8 - bit_len);

	return data;
}

uint8_t pkt_buffer::read_8(std::size_t offset) {
	return *(safe_ptr(offset, sizeof(uint8_t)));
}

uint16_t pkt_buffer::read_ntoh16(std::size_t offset) {
	const unsigned char *data = safe_ptr(offset, sizeof(uint16_t));
	return ((uint16_t) data[1]) | ((uint16_t) data[0] << 8);
}


void pkt_buffer::read(void *dst, std::size_t src_offset, std::size_t size) {
	memcpy(dst, safe_ptr(src_offset, size), size);
}


const unsigned char *pkt_buffer::safe_ptr(const std::size_t offset, const std::size_t size) {

	if (offset + size >= size_) {
		throw std::out_of_range("Read past the end of the buffer");
	}

	return data_ + offset;
}

