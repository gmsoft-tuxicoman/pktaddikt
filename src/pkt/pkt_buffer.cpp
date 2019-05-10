

#include <cassert>
#include <cstring>
#include <stdexcept>

#include "pkt_buffer.h"


const unsigned char *pkt_buffer::read(std::size_t size) {

	if (pos_ + size > size_) {
		throw std::runtime_error("Read past the end of a packet");
	}

	unsigned char *ret = buff_ + pos_;
	pos_ += size;
	return ret;
}

std::size_t pkt_buffer::remaining() {
	return size_ - pos_;
}


