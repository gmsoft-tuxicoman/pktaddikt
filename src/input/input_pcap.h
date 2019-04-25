#ifndef __INPUT_PCAP_H__
#define __INPUT_PCAP_H__

#include <map>
#include <memory>

#include "input.h"
#include "common/parameter.h"

class input_pcap : public input {

	public:
		input_pcap(const std::string& name) : input(name) {};


};

class input_pcap_interface : public input_pcap {

	public:
		input_pcap_interface();
	

};

#endif
