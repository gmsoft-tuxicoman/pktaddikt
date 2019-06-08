

#include <cassert>
#include <cstring>
#include <stdexcept>

#include "pkt_buffer.h"


uint8_t pkt_buffer::read_bits8(std::size_t bit_offset, std::size_t bit_len) {

	std::size_t offset = bit_offset >> 3;
	bit_offset %= 8;
	boundary_check(sizeof(uint8_t), offset);

	uint8_t data = *(buff_ + offset);

	data >> bit_offset;
	data &= 0xff >> ( 8 - bit_offset);

	return data;
}

uint8_t pkt_buffer::read_8(std::size_t offset) {
	boundary_check(sizeof(uint8_t), offset);
	return *(buff_ + offset);
}

uint16_t pkt_buffer::read_ntoh16(std::size_t offset) {
	boundary_check(sizeof(uint16_t), offset);
	uint8_t *data = buff_ + offset;
	return ((uint16_t) data[1]) | ((uint16_t) data[0] << 8);
}


void pkt_buffer::read(void *dst, std::size_t src_offset, std::size_t size) {
	boundary_check(size, src_offset);
	memcpy(dst, buff_ + src_offset, size);
}

void pkt_buffer::consume(std::size_t size) {
	boundary_check(size, 0);
	buff_ += size;
}

void pkt_buffer::boundary_check(std::size_t size, std::size_t offset) {
	if (buff_ + size + offset >= end_) {
		throw std::out_of_range("Read past the end of the buffer");
	}
}

std::size_t pkt_buffer::remaining() {
	return end_ - buff_;
}

void pkt_buffer::set_remaining(std::size_t remaining) {
	boundary_check(remaining, 0);
	end_ = buff_ + remaining;
}
