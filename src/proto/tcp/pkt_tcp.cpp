

#include "pkt_tcp.h"
#include "logger.h"

void pkt_tcp::register_number() {
	pkt_factory::register_number(pkt_factory::type::ip, 6, factory);
}

pkt::parse_result pkt_tcp::parse() {

	if (buf_->get_size() < 20) { // Buff len smaller than header length
		return invalid;
	}

	uint8_t data_offset = buf_->read_bits8(96, 4);

	unsigned int hdr_len = data_offset << 2;

	if (hdr_len > buf_->get_size() || hdr_len < 20) {
		// Incomplete or invalid packet
		return invalid;
	}

	unsigned int plen = buf_->get_size() - hdr_len;
	
	// Byte 0-1 : sport
	field_sport_.set_value(*buf_, 0);

	// Byte 2-3 : dport
	field_dport_.set_value(*buf_, 2);

	// Byte 4-7 : seq
	field_seq_.set_value(*buf_, 4);

	// Byte 8-11 : ack
	field_ack_.set_value(*buf_, 8);

	// Byte 13: flags
	field_flags_.set_value(*buf_, 13);

	// Byte 14-15: window
	field_win_.set_value(*buf_, 14);

	uint8_t flags = field_flags_.get_value();

	if ((flags & TH_SYN) && plen > 0) {
		// Invalid packet, SYN flag present and len > 0
		return invalid;
	}

	if ((flags & TH_SYN) && (flags & (TH_RST | TH_FIN))) {
		// Invalid packet SYN and either RST or FIN flag present
		return invalid;
	}

	if ((flags & TH_RST) && plen > 0) {
		plen = 0; // RFC 1122 4.2.2.12 : RST may contain the data that caused the packet to be sent, discard it
	}

	LOG_DEBUG << "tcp : " << field_sport_.print() << " -> " << field_dport_.print();

	return ok;
}
