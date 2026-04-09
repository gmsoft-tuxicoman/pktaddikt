pub mod test;
pub mod ethernet;
pub mod ipv4;
pub mod ipv6;
pub mod udp;
pub mod tcp;
pub mod http;
pub mod arp;
pub mod vlan;
pub mod icmp;

use crate::proto::test::ProtoTest;
use crate::proto::ethernet::ProtoEthernet;
use crate::proto::ipv4::{ProtoIpv4, Ipv4Config};
use crate::proto::ipv6::{ProtoIpv6, Ipv6Config};
use crate::proto::udp::{ProtoUdp, UdpConfig};
use crate::proto::tcp::{ProtoTcp, TcpConfig};
use crate::proto::arp::ProtoArp;
use crate::proto::vlan::ProtoVlan;
use crate::proto::icmp::ProtoIcmp;
use crate::packet::{Packet, PktInfoStack};
use crate::timer::TimerManager;
use crate::config::ConfigRef;

use std::time::Instant;
use serde::Deserialize;
use std::fmt;
use std::mem;

#[derive(Debug, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub struct ProtoConfig {
    ipv4: Ipv4Config,
    ipv6: Ipv6Config,
    tcp: TcpConfig,
    udp: UdpConfig,
}

impl Default for ProtoConfig {
    fn default() -> Self {
        Self {
            ipv4: Ipv4Config::default(),
            ipv6: Ipv6Config::default(),
            tcp: TcpConfig::default(),
            udp: UdpConfig::default(),
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
    Icmp,
}

pub enum ProtoParseResult {
    Ok,
    Stop,
    Invalid,
    New(Packet<'static>),
    None
}

impl PartialEq for ProtoParseResult {

    fn eq(&self, other:&Self) -> bool {
        use ProtoParseResult::*;

        match (self, other) {
            (Ok, Ok) => true,
            (Stop, Stop) => true,
            (Invalid, Invalid) => true,
            (New(_), New(_)) => true, // don't check content
            (None, None) => true,
            _ => false,
        }

    }

}

impl fmt::Debug for ProtoParseResult {

    fn fmt(&self, f:&mut fmt::Formatter<'_>) -> fmt::Result {
        use ProtoParseResult::*;

        match self {
            Ok => write!(f, "Ok"),
            Stop => write!(f, "Stop"),
            Invalid => write!(f, "Invalid"),
            None => write!(f, "None"),
            New(_) => write!(f, "New"),
        }

    }
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
    icmp: ProtoIcmp,
}

impl Proto {

    pub fn new(cfg: ConfigRef) -> Self {
        Self {
            test: ProtoTest::new(),
            ethernet: ProtoEthernet::new(),
            ipv4: ProtoIpv4::new(cfg.clone()),
            ipv6: ProtoIpv6::new(cfg.clone()),
            tcp: ProtoTcp::new(cfg.clone()),
            udp: ProtoUdp::new(cfg.clone()),
            arp: ProtoArp::new(),
            vlan: ProtoVlan::new(),
            icmp: ProtoIcmp::new(),

        }
    }

    pub fn process_packet<'a>(&mut self, orig_pkt: &mut Packet, infos: &mut PktInfoStack) {

        let start = Instant::now();

        TimerManager::update_time(orig_pkt.ts);

        let mut ret = ProtoParseResult::None;
        let mut pkt_holder: Option<Packet> = None;
        let mut stack_index: usize = 0;

        loop {

            let pkt = match pkt_holder.as_mut() {
                Some(p) => p,
                None => orig_pkt,
            };

            let info = match infos.proto_id(stack_index) {
                Some(i) => i,
                None => break,
            };
            stack_index += 1;

            ret = match info.proto {
                Protocols::Test => self.test.process(pkt, infos),
                Protocols::Ethernet => self.ethernet.process(pkt, infos),
                Protocols::Ipv4 => self.ipv4.process(pkt, infos),
                Protocols::Ipv6 => self.ipv6.process(pkt, infos),
                Protocols::Udp => self.udp.process(pkt, infos),
                Protocols::Tcp => self.tcp.process(pkt, infos),
                Protocols::Arp => self.arp.process(pkt, infos),
                Protocols::Vlan => self.vlan.process(pkt, infos),
                Protocols::Icmp => self.icmp.process(pkt, infos),
                _ => break,
            };

            if let ProtoParseResult::New(new_pkt) = mem::replace(&mut ret, ProtoParseResult::Ok) {
                pkt_holder = Some(new_pkt);
                continue;
            }

            if ret != ProtoParseResult::Ok {
                break;
            }


        }

        let processing_time = start.elapsed();

        print!("{} ", orig_pkt.ts);
        for i in infos.iter() {
            if i.proto == Protocols::None {
                break;
            }
            print!("{:?} {{ ", i.proto);
            for f in i.iter_fields() {
                print!("{}: {}; ", f.name, f.value.unwrap());
            }
            print!("}}; ");
        }

        println!("[{:?} {}ns]", ret, processing_time.as_nanos());
    }

}
