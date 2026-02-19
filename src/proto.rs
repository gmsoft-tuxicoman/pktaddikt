pub mod test;
pub mod ethernet;
pub mod ipv4;
pub mod ipv6;
pub mod udp;
pub mod tcp;
use crate::proto::test::ProtoTest;
use crate::proto::ethernet::ProtoEthernet;
use crate::proto::ipv4::ProtoIpv4;
use crate::proto::ipv6::ProtoIpv6;
use crate::proto::udp::ProtoUdp;
use crate::proto::tcp::ProtoTcp;
use crate::packet::Packet;
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
    Tcp
}

#[derive(PartialEq, Debug)]
pub enum ProtoParseResult {
    Ok,
    Stop,
    Invalid,
    None
}

pub trait ProtoProcessor {
    fn process(pkt: &mut Packet) -> ProtoParseResult;
    fn purge();
}


pub struct Proto;

impl Proto {

    pub fn process_packet<'a>(pkt: &mut Packet) {

        let start = Instant::now();

        TimerManager::update_time(pkt.ts);

        let mut next_proto = pkt.datalink;
        pkt.stack_push(next_proto, None);

        let mut ret = ProtoParseResult::None;

        loop {

            ret = match next_proto {
                Protocols::None => break,
                Protocols::Test => ProtoTest::process(pkt),
                Protocols::Ethernet => ProtoEthernet::process(pkt),
                Protocols::Ipv4 => ProtoIpv4::process(pkt),
                Protocols::Ipv6 => ProtoIpv6::process(pkt),
                Protocols::Udp => ProtoUdp::process(pkt),
                Protocols::Tcp => ProtoTcp::process(pkt)
            };

            if ret != ProtoParseResult::Ok {
                break;
            }

            next_proto = pkt.stack_last().proto;

        }

        let processing_time = start.elapsed();

        print!("{}.{} ", pkt.ts / 1000000, pkt.ts % 1000000);
        for s in pkt.iter_stack() {
            if s.proto == Protocols::None {
                break;
            }
            print!("{:?} {{ ", s.proto);
            for f in s.iter_fields() {
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

    }
}
