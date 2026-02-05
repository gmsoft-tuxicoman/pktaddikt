pub mod ethernet;
pub mod ipv4;
pub mod ipv6;
pub mod udp;
use crate::proto::ethernet::ProtoEthernet;
use crate::proto::ipv4::ProtoIpv4;
use crate::proto::ipv6::ProtoIpv6;
use crate::proto::udp::ProtoUdp;

use crate::packet::Packet;


// List of implemented protocols
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Protocols {
    None,
    Ethernet,
    Ipv4,
    Ipv6,
    Udp
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
}


pub struct Proto;

impl Proto {

    pub fn process_packet<'a>(pkt: &mut Packet) {


        let mut next_proto = pkt.datalink;
        pkt.stack_push(next_proto, None);

        let mut ret = ProtoParseResult::None;

        loop {

            ret = match next_proto {
                Protocols::None => break,
                Protocols::Ethernet => ProtoEthernet::process(pkt),
                Protocols::Ipv4 => ProtoIpv4::process(pkt),
                Protocols::Ipv6 => ProtoIpv6::process(pkt),
                Protocols::Udp => ProtoUdp::process(pkt)
            };

            if ret != ProtoParseResult::Ok {
                break;
            }

            next_proto = pkt.stack_last().proto;

        }

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

        println!("[{:?}]", ret );
    }
}
