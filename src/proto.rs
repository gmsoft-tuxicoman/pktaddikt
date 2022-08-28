pub mod ethernet;
pub mod ipv4;
pub mod udp;
use crate::proto::ethernet::ProtoEthernet;
use crate::proto::ipv4::ProtoIpv4;
use crate::proto::udp::ProtoUdp;

pub trait ProtoParser {

    fn name(&self) -> &str;
    fn process(&self) -> Result<ProtoSlice, ()>;
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


pub fn get_next_proto<'a>(t: ProtoNumberType, num: u32, pload: &'a [u8]) -> Result<Box<dyn ProtoParser + 'a>, &str> {

    match t {
        ProtoNumberType::Pcap => match num {
            1 => Ok(Box::new(ProtoEthernet{pload: pload})),
            _ => Err("Unsupported pcap type")
        },
        ProtoNumberType::Ethernet => match num {
            0x800 => Ok(Box::new(ProtoIpv4{pload: pload})),
            _ => Err("Unsuported ethernet type")
        },
        ProtoNumberType::Ip => match num {
            4 => Ok(Box::new(ProtoIpv4{pload: pload})),
            17 => Ok(Box::new(ProtoUdp{pload: pload})),
            _ => Err("Unknown Ip protocol")
        },
        ProtoNumberType::Udp => Err("Not implemented")
        
    }

}
