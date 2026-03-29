use crate::input::pcap::{InputPcap, PcapFileConfig, PcapInterfaceConfig};

use serde::Deserialize;
pub mod pcap;

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum InputConfig {
    #[serde(rename = "pcap_file")]
    PcapFile(PcapFileConfig),
    #[serde(rename = "pcap_interface")]
    PcapInterface(PcapInterfaceConfig),
}

impl Default for InputConfig {
    fn default() -> Self {
        InputConfig::PcapInterface(PcapInterfaceConfig::default())
    }
}

pub enum Input {

    Pcap(InputPcap),
}


impl Input {

    pub fn new(cfg: InputConfig) -> Input {

        match cfg {
            InputConfig::PcapInterface(c) => {
                println!("Using pcap interface with iface {}", c.iface);
                Input::Pcap(InputPcap::new_interface(c))
            },
            InputConfig::PcapFile(c) => {
                println!("Using pcap file with file {}", c.file);
                Input::Pcap(InputPcap::new_file(c))
            }
        }
   }

   pub fn main_loop(&mut self) {
        match self {
            Input::Pcap(i) => i.main_loop()
        }
   }

}
