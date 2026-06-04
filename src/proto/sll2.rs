use crate::base::{Parser, ParseErr};
use crate::proto::{ProtoPktProcessor, Protocols, ProtoInfo};
use crate::packet::{Packet, PktInfoStack};
use crate::proto::ethernet::EthernetMac;


#[derive(Debug, PartialEq)]
pub struct ProtoSll2Info {
    pub src: EthernetMac,
    pub iface_id: u32,
}


pub struct ProtoSll2 {}

impl ProtoSll2 {

    pub fn next_proto(eth_type: u16) -> Protocols {
         match eth_type {
            0x0800 => Protocols::Ipv4,
            0x8100 => Protocols::Vlan,
            0x0806 => Protocols::Arp,
            0x86DD => Protocols::Ipv6,
            _ => Protocols::None
        }
    }

}

impl ProtoPktProcessor for ProtoSll2 {

    fn new() -> Self {
        Self {}
    }

    fn process(&mut self, pkt: &mut Packet, stack: &mut PktInfoStack) -> Result<(), ParseErr> {

        let proto = pkt.read_u16_be()?;


        pkt.skip_u16()?; // reserved
        let iface_id = pkt.read_u32_be()?;
        let arphdr_type = pkt.read_u16_be()?;

        if arphdr_type != 1 {
            return Err(ParseErr::Invalid("Non-ethernet packet not supported"));
        }

        pkt.skip_u8()?; // direction
        let ll_addr_len = pkt.read_u8()?;
        if ll_addr_len != 6 {
            return Err(ParseErr::Invalid("Invalid ethernet address len"));
        }

        let src = EthernetMac(pkt.read_fixed::<6>()?);

        pkt.skip(2)?; // Padding

        let info = stack.proto_last_mut();

        let proto_info = ProtoSll2Info {
            src,
            iface_id,
        };


        info.proto_info = Some(ProtoInfo::Sll2(proto_info));

        stack.proto_push(ProtoSll2::next_proto(proto), None);

        Ok(())

    }

}

