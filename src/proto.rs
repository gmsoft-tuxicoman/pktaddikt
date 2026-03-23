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
use crate::proto::tcp::ProtoTcp;
use crate::proto::arp::ProtoArp;
use crate::proto::vlan::ProtoVlan;
use crate::packet::{Packet, PktInfoStack};
use crate::timer::TimerManager;

use std::time::Instant;


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
    None
}

pub trait ProtoPktProcessor {
    fn process(pkt: &mut Packet, stack: &mut PktInfoStack) -> ProtoParseResult;
    fn purge();
}


pub struct Proto;

impl Proto {

    pub fn process_packet<'a>(pkt: &mut Packet, infos: &mut PktInfoStack) {

        let start = Instant::now();

        TimerManager::update_time(pkt.ts);

        let mut ret = ProtoParseResult::None;

        loop {

            ret = match infos.proto_last().proto {
                Protocols::Test => ProtoTest::process(pkt, infos),
                Protocols::Ethernet => ProtoEthernet::process(pkt, infos),
                Protocols::Ipv4 => ProtoIpv4::process(pkt, infos),
                Protocols::Ipv6 => ProtoIpv6::process(pkt, infos),
                Protocols::Udp => ProtoUdp::process(pkt, infos),
                Protocols::Tcp => ProtoTcp::process(pkt, infos),
                Protocols::Arp => ProtoArp::process(pkt, infos),
                Protocols::Vlan => ProtoVlan::process(pkt, infos),
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

    pub fn purge_all() {
        ProtoTest::purge();
        ProtoEthernet::purge();
        ProtoIpv4::purge();
        ProtoIpv6::purge();
        ProtoUdp::purge();
        ProtoTcp::purge();
        ProtoArp::purge();
        ProtoVlan::purge();

    }
}
