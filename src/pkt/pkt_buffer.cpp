

#include <cassert>
#include <cstring>
#include <stdexcept>

#include "pkt_buffer.h"


uint8_t pkt_buffer::read_bits8(std::size_t bit_offset, std::size_t bit_len) {

	std::size_t offset = bit_offset >> 3;
	bit_offset %= 8;
	uint8_t data = *(safe_ptr(sizeof(uint8_t), offset);

	data >> bit_offset;
	data &= 0xff >> ( 8 - bit_offset);

	return data;
}

uint8_t pkt_buffer::read_8(std::size_t offset) {
	return *(safe_ptr(sizeof(uint8_t), offset));
}

uint16_t pkt_buffer::read_ntoh16(std::size_t offset) {
	const unsigned char *safe_ptr(sizeof(uint16_t), offset);
	return ((uint16_t) data[1]) | ((uint16_t) data[0] << 8);
}


void pkt_buffer::read(void *dst, std::size_t src_offset, std::size_t size) {
	memcpy(dst, safe_ptr(src_offset, size), size);
}


unsigned char *pkt_buffer::safe_ptr(std::size_t offset, std::size_t size) {

	unsigned char *ptr = data_ + offset;
	if (ptr + size >= data_size_) {
		throw std::out_of_range("Read past the end of the buffer");
	}

	return ptr;
}

