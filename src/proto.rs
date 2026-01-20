pub mod ethernet;
pub mod ipv4;
pub mod ipv6;
pub mod udp;
use pcap::Linktype;
use crate::proto::ethernet::ProtoEthernet;
use crate::proto::ipv4::ProtoIpv4;
use crate::proto::ipv6::ProtoIpv6;
use crate::proto::udp::ProtoUdp;

use std::net::Ipv4Addr;
use std::net::Ipv6Addr;


pub trait ProtoParser {

    fn name(&self) -> &str;
    fn process(&mut self) -> Result<ProtoSlice, ()>;
    fn get_fields(&self) -> &Vec<(&str, Option<ProtoField>)>;
    fn get_field(&self, name: &str) -> Option<ProtoField> {
       self.get_fields().into_iter().find_map(| &(x,y)| { if x == name { y } else { None }})
    }
    fn print<'a>(&self, prev_layer: Option<&'a Box<dyn ProtoParser + 'a>>);
}

pub enum ProtoNumberType {
    Pcap,
    Ethernet,
    Ip,
    Udp,
}

pub struct ProtoSlice {
    pub number_type : ProtoNumberType,
    pub number : u32,
    pub start : usize,
    pub end : usize,
}

pub struct ProtoStackEntry<'a> {
    pub parser: Box<dyn ProtoParser + 'a>,
    pub parse_result: bool

}

#[derive(Debug, Clone, Copy)]
pub enum ProtoField<'a> {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    Str(&'a str),
    Mac([u8;6]),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr)
}

impl<'a> ProtoField<'a> {

    fn get_u8(&self) -> u8 {
        match self {
            ProtoField::U8(val) => *val,
            _ => panic!("Trying to fetch u8")
        }
    }
    fn get_u16(&self) -> u16 {
        match self {
            ProtoField::U16(val) => *val,
            _ => panic!("Trying to fetch u16")
        }
    }
    fn get_u32(&self) -> u32 {
        match self {
            ProtoField::U32(val) => *val,
            _ => panic!("Trying to fetch u32")
        }
    }
    fn get_u64(&self) -> u64 {
        match self {
            ProtoField::U64(val) => *val,
            _ => panic!("Trying to fetch u64")
        }
    }
    fn get_str(&self) -> &str {
        match self {
            ProtoField::Str(val) => val,
            _ => panic!("Trying to fetch string")
        }
    }
    fn get_mac(&self) -> [u8;6] {
        match self {
            ProtoField::Mac(val) => *val,
            _ => panic!("Trying to fetch mac address")
        }
    }
    fn get_ipv4(&self) -> Ipv4Addr {
        match self {
            ProtoField::Ipv4(val) => *val,
            _ => panic!("Trying to fetch ipv4")
        }
    }
    fn get_ipv6(&self) -> Ipv6Addr {
        match self {
            ProtoField::Ipv6(val) => *val,
            _ => panic!("Trying to fetch ipv6")
        }
    }

}


pub struct Proto;

impl Proto {

    fn get_next<'a>(&self, t: ProtoNumberType, num: u32, pload: &'a [u8]) -> Result<Box<dyn ProtoParser + 'a>, &'a str> {

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

        let mut stack = Vec::new();
        loop {
            let p_res = self.get_next(t, n, data);
            let mut p = match p_res {
                Ok(p) => p,
                _ => break,
            };
            let res =  p.process();
            match res {
                Ok(proto_slice) => {
                    t = proto_slice.number_type;
                    n = proto_slice.number;
                    println!("{} -> {}",proto_slice.start, proto_slice.end);
                    data = &data[proto_slice.start .. proto_slice.end];
                    stack.push(ProtoStackEntry{parser: p, parse_result: true});
                },
                Err(()) => {
                    stack.push(ProtoStackEntry{parser: p, parse_result: false});
                    break
                }
            }
        }


        let mut prev_layer : Option<Box<dyn ProtoParser>> = None;
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
