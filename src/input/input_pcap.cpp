
#include <csignal>

#include "input_pcap.h"

#include "pkt/pkt_buffer.h"

#include "logger.h"


pkt* input_pcap::read_packet() {


	pcap_pkthdr *phdr;
	const u_char *data;
	int result = pcap_next_ex(pcap_, &phdr, &data);
	LOG_DEBUG << "Got packet of " << phdr->len << " with result " << result;

	if (result < 0) { // Error or EOF
		return NULL;
	}

	// We need to copy the packet as pcap does not garantee that the data will still be avail on the next call to pcap_next_ex()
	pkt_buffer *buf = new pkt_buffer_copy(phdr->len, static_cast<const unsigned char*>(data));
	pkt *p = new pkt(buf, std::chrono::seconds{phdr->ts.tv_sec} + std::chrono::microseconds{phdr->ts.tv_usec}, executor_);

	p->add_proto(proto::number_type::dlt, DLT_EN10MB);

	return p;

}

void input_pcap::break_loop() {

	if (pcap_) {
		pcap_breakloop(pcap_);
	}

	pthread_kill(processing_thread_.native_handle(), SIGCHLD);
}

void input_pcap::close() {

	if (pcap_) {
		pcap_close(pcap_);
		pcap_ = nullptr;
	}
}


input_pcap_interface::input_pcap_interface(const std::string &name, task_executor_ptr executor) : input_pcap(name, executor),
	param_interface_("eth0", "Interface to listen to"),
	param_promisc_("no", "Set the interface to promiscuous mode")
{

	parameters_.insert(std::make_pair("interface", &param_interface_));
	parameters_.insert(std::make_pair("promisc", &param_promisc_));

}

void input_pcap_interface::open() {

	std::string interface = param_interface_.ptype().get_value();

	char errbuff[PCAP_ERRBUF_SIZE] = { 0 };
	pcap_ = pcap_create(interface.c_str(), errbuff);

	if (pcap_ == nullptr) {
		throw std::runtime_error("Error opening interface " + interface + " : " + errbuff);
	}

	int err = pcap_set_promisc(pcap_, param_promisc_.ptype().get_value());
	if (err) {
		LOG_ERROR << "Error while setting promisc mode : " << pcap_statustostr(err);
	}

	err = pcap_activate(pcap_);

	if (err < 0) {
		throw std::runtime_error(std::string("Error while activating pcap : ") + pcap_statustostr(err));
	} if (err > 0) {
		LOG_WARN << "Warning while activating pcap : " << pcap_statustostr(err);
	}

	LOG_INFO << "Interface " << interface << " open";
}


input_pcap_file::input_pcap_file(const std::string &name, task_executor_ptr executor) : input_pcap(name, executor),
	param_file_("file,cap", "File in PCAP format")
{

	parameters_.insert(std::make_pair("file", &param_file_));

}
void input_pcap_file::open() {

	std::string file = param_file_.ptype().get_value();

	char errbuff[PCAP_ERRBUF_SIZE] = { 0 };
	pcap_ = pcap_open_offline(file.c_str(), errbuff);

	if (pcap_ == nullptr) {
		throw std::runtime_error("Error opening file " + file + " : " + errbuff);
	}

	LOG_INFO << "File " << file << " open";
}
