pub mod test;
pub mod ethernet;
pub mod ipv4;
pub mod ipv6;
pub mod udp;
pub mod tcp;
pub mod http;
pub mod arp;
pub mod vlan;

use crate::proto::test::ProtoTest;
use crate::proto::ethernet::ProtoEthernet;
use crate::proto::ipv4::ProtoIpv4;
use crate::proto::ipv6::ProtoIpv6;
use crate::proto::udp::ProtoUdp;
use crate::proto::tcp::{ProtoTcp, TcpConfig};
use crate::proto::arp::ProtoArp;
use crate::proto::vlan::ProtoVlan;
use crate::packet::{Packet, PktInfoStack};
use crate::timer::TimerManager;
use crate::config::ConfigRef;

use std::time::Instant;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub struct ProtoConfig {
    tcp: TcpConfig,
}

impl Default for ProtoConfig {
    fn default() -> Self {
        Self {
            tcp: TcpConfig::default(),
        }
    }
}


// List of implemented protocols
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Protocols {
    None,
    Test,
    Ethernet,
    Ipv4,
    Ipv6,
    Udp,
    Tcp,
    Http,
    Arp,
    Vlan,
}

#[derive(PartialEq, Debug)]
pub enum ProtoParseResult {
    Ok,
    Stop,
    Invalid,
//    New { pkt: Packet<'a>, infos: &'a mut PktInfoStack<'a>},
    None
}

pub trait ProtoPktProcessor {
    fn process(&mut self, pkt: &mut Packet, stack: &mut PktInfoStack) -> ProtoParseResult;
}


pub struct Proto {
    test: ProtoTest,
    ethernet: ProtoEthernet,
    ipv4: ProtoIpv4,
    ipv6: ProtoIpv6,
    udp: ProtoUdp,
    tcp: ProtoTcp,
    arp: ProtoArp,
    vlan: ProtoVlan,
}

impl Proto {

    pub fn new(cfg: ConfigRef) -> Self {
        Self {
            test: ProtoTest::new(),
            ethernet: ProtoEthernet::new(),
            ipv4: ProtoIpv4::new(cfg.clone()),
            ipv6: ProtoIpv6::new(),
            tcp: ProtoTcp::new(cfg.clone()),
            udp: ProtoUdp::new(),
            arp: ProtoArp::new(),
            vlan: ProtoVlan::new(),

        }
    }

    pub fn process_packet<'a>(&mut self, pkt: &mut Packet, infos: &mut PktInfoStack) {

        let start = Instant::now();

        TimerManager::update_time(pkt.ts);

        let mut ret = ProtoParseResult::None;

        loop {

            ret = match infos.proto_last().proto {
                Protocols::Test => self.test.process(pkt, infos),
                Protocols::Ethernet => self.ethernet.process(pkt, infos),
                Protocols::Ipv4 => self.ipv4.process(pkt, infos),
                Protocols::Ipv6 => self.ipv6.process(pkt, infos),
                Protocols::Udp => self.udp.process(pkt, infos),
                Protocols::Tcp => self.tcp.process(pkt, infos),
                Protocols::Arp => self.arp.process(pkt, infos),
                Protocols::Vlan => self.vlan.process(pkt, infos),
                _ => break,
            };

            if ret != ProtoParseResult::Ok {
                break;
            }


        }

        let processing_time = start.elapsed();

        print!("{} ", pkt.ts);
        for i in infos.iter() {
            if i.proto == Protocols::None {
                break;
            }
            print!("{:?} {{ ", i.proto);
            for f in i.iter_fields() {
                print!("{}: {:?}; ", f.name, f.value.unwrap());
            }
            print!("}}; ");
        }

        println!("[{:?} {}ns]", ret, processing_time.as_nanos());
    }

}
