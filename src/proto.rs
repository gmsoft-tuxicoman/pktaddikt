pub mod ethernet;
pub mod ipv4;
pub mod ipv6;
pub mod udp;
use pcap::Linktype;
use crate::proto::ethernet::ProtoEthernet;
use crate::proto::ipv4::ProtoIpv4;
use crate::proto::ipv6::ProtoIpv6;
use crate::proto::udp::ProtoUdp;

use crate::conntrack::ConntrackWeakRef;


// List of implemented protocols
pub enum Protocols {
    Ethernet,
    Ipv4,
    IPv6,
    Udp
}

pub trait ProtoProcessor {

    fn process(&mut self, ce_parent: Option<ConntrackWeakRef>) -> Result<ProtoProcessResult, ()>;
    fn print<'a>(&self, prev_layer: Option<&'a Box<dyn ProtoProcessor + 'a>>);
}

pub enum ProtoNumberType {
    Pcap,
    Ethernet,
    Ip,
    Udp,
}

pub struct ProtoProcessResult {
    pub next_slice: ProtoSlice,
    pub ct: Option<ConntrackWeakRef>
}

pub struct ProtoSlice {
    pub number_type : ProtoNumberType,
    pub number : u32,
    pub start : usize,
    pub end : usize,
}

pub struct ProtoStackEntry<'a> {
    pub parser: Box<dyn ProtoProcessor + 'a>,
    pub parse_result: bool

}



pub struct Proto;

impl Proto {

    fn get_next<'a>(&self, t: ProtoNumberType, num: u32, pload: &'a [u8]) -> Result<Box<dyn ProtoProcessor + 'a>, &'a str> {

        match t {
            ProtoNumberType::Pcap => match num {
                1 => Ok(Box::new(ProtoEthernet::new(pload))),
                _ => Err("Unsupported pcap type")
            },
            ProtoNumberType::Ethernet => match num {
                0x800 => Ok(Box::new(ProtoIpv4::new(pload))),
                0x86DD => Ok(Box::new(ProtoIpv6::new(pload))),
                _ => Err("Unsuported ethernet type")
            },
            ProtoNumberType::Ip => match num {
                4 => Ok(Box::new(ProtoIpv4::new(pload))),
                17 => Ok(Box::new(ProtoUdp::new(pload))),
                _ => Err("Unknown Ip protocol")
            },
            ProtoNumberType::Udp => Err("Not implemented")

        }
    }

    pub fn process_packet<'a>(&mut self, data: &'a[u8], lt: Linktype) {

        assert_eq!(lt, Linktype(1));

        let mut t = ProtoNumberType::Pcap;
        let mut n = lt.0 as u32;
        let mut data = data;
        let mut ce_parent: Option<ConntrackWeakRef> = None;


        let mut stack = Vec::new();
        loop {
            let p_res = self.get_next(t, n, data);
            let mut p = match p_res {
                Ok(p) => p,
                _ => break,
            };
            let opt_res = p.process(ce_parent);
            match opt_res {
                Ok(res) => {
                    let slice = res.next_slice;
                    t = slice.number_type;
                    n = slice.number;
                    data = &data[slice.start .. slice.end];
                    stack.push(ProtoStackEntry{parser: p, parse_result: true});
                    ce_parent = res.ct;
                },
                Err(()) => {
                    stack.push(ProtoStackEntry{parser: p, parse_result: false});
                    break
                }
            }
        }


        let mut prev_layer : Option<Box<dyn ProtoProcessor>> = None;
        for p in stack {
            match prev_layer {
                None => p.parser.print(None),
                Some(l) => p.parser.print(Some(&l))
            }
            prev_layer = Some(p.parser);
        }
        println!()
    }
}
