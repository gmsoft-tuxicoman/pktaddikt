use crate::packet::{Packet, PktTime, PktInfoStack};
use crate::proto::{Proto, Protocols};
use crate::config::Config;
use crate::input::InputConfig;

use serde::Deserialize;
use pcap::{Capture, Linktype, Offline, Active};
use tracing::warn;


#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PcapInterfaceConfig {
    pub iface: String,
    pub promisc: bool,
    pub snaplen: i32,
    pub buffer_size: i32,
    pub filter: Option<String>,
}

impl Default for PcapInterfaceConfig {
    fn default() -> Self {
        Self {
            iface: "eth0".to_string(),
            promisc: true,
            snaplen: 65535,
            buffer_size: 16777216,
            filter: None,
        }
    }
}


#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PcapFileConfig {
    pub file: String,
}

impl Default for PcapFileConfig {
   fn default() -> Self {
        Self {
            file: "file.cap".to_string(),
        }
   }
}


enum PcapCapture {
    File(Capture<Offline>),
    Interface(Capture<Active>),
}

pub struct InputPcap {

    capture: PcapCapture,
    truncated_warning: bool,

}

impl InputPcap {

    pub fn new_file() -> InputPcap {
        let cfg = Config::get();
        let InputConfig::PcapFile(ref c) = cfg.input else {
            panic!("Unexpected config");
        };

        InputPcap {
            capture: PcapCapture::File(Capture::from_file(&c.file).unwrap()),
            truncated_warning: false,
        }
    }

    pub fn new_interface() -> InputPcap {

        let cfg = Config::get();
        let InputConfig::PcapInterface(ref c) = cfg.input else {
            panic!("Unexpected config");
        };

        let mut capture = Capture::from_device(&*c.iface).unwrap()
            .timeout(1)
            .promisc(c.promisc)
            .snaplen(c.snaplen)
            .buffer_size(c.buffer_size)
            .open().unwrap();

        if c.filter.is_some() {
            capture.filter(c.filter.as_ref().unwrap(), true).unwrap();
        }

        InputPcap {
            capture: PcapCapture::Interface(capture),
            truncated_warning: false,
        }
    }

    pub fn main_loop(&mut self) {

        let datalink = match &mut self.capture {
            PcapCapture::File(cap) => cap.get_datalink(),
            PcapCapture::Interface(cap) => cap.get_datalink(),
        };
        println!("Capture datalink : {:?}", datalink);

        let proto = match datalink {
            Linktype::ETHERNET => Protocols::Ethernet,
            Linktype(12) => Protocols::Ipv4,
            Linktype::RAW => Protocols::Ipv4,
            _ => panic!("Unsupported protocol !"),
        };

        let mut proto_parser = Proto::new();

        while let Ok(pcap_pkt) = match &mut self.capture {
            PcapCapture::File(cap) => cap.next_packet(),
            PcapCapture::Interface(cap) => cap.next_packet(),
        } {

            if pcap_pkt.header.caplen < pcap_pkt.header.len && self.truncated_warning == false {
                warn!("Some packets were truncated during capture !");
                self.truncated_warning = true;
            }

            let ts = PktTime::from_timeval(pcap_pkt.header.ts.tv_sec, pcap_pkt.header.ts.tv_usec);

            let mut pkt = Packet::from_slice(ts, pcap_pkt.data);
            let mut infos = PktInfoStack::new(proto);



            proto_parser.process_packet(&mut pkt, &mut infos);
        }
    }
}


