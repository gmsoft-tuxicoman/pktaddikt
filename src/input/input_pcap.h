#ifndef __INPUT_PCAP_H__
#define __INPUT_PCAP_H__

#include <map>
#include <memory>

#include <pcap.h>

#include "input.h"
#include "common/parameter.h"
#include "ptype/ptype_bool.h"
#include "ptype/ptype_string.h"

#include "proto/proto_ethernet.h"

class input_pcap : public input {

	public:
		input_pcap(const std::string& name) : input(name) {};

	protected:
		pcap_t *pcap_ = nullptr;


};

class input_pcap_interface : public input_pcap {

	public:
		input_pcap_interface(const std::string &name);
		input_pcap_interface* clone(const std::string &name) const { return new input_pcap_interface(name); };

		void open();
		void read_packets();
		void close();

	protected:
		parameter<ptype_string> param_interface_;
		parameter<ptype_bool> param_promisc_;

};


#endif
