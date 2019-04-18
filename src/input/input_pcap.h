#ifndef __INPUT_PCAP_H__
#define __INPUT_PCAP_H__

#include <map>
#include <memory>

#include "input.h"
#include "common/parameter.h"

class input_pcap : public input {

	protected:
		std::map<std::string, std::unique_ptr<parameter_base>> parameters_;

};

class input_pcap_interface : public input_pcap {

	public:
		input_pcap_interface();
	

};

#endif
