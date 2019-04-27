


#include <iostream>

#include "input_pcap.h"

#include "ptype/ptype_string.h"

input_pcap_interface::input_pcap_interface() : input_pcap("pcap_interface") {

	parameters_.insert(std::make_pair("interface", std::move(std::make_unique<parameter<ptype_string>>("eth0", "Interface to listen to"))));
	std::cout << "Value : " << parameters_["interface"]->print_value() << std::endl;

}
