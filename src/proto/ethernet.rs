use crate::base::{Parser, ParseErr};
use crate::proto::{ProtoPktProcessor, Protocols, ProtoInfo};
use crate::packet::{Packet, PktInfoStack};

use serde::{Serialize, Serializer};
use std::fmt;

#[derive(Debug, PartialEq, Copy, Clone)]
pub struct EthernetMac(pub [u8;6]);

impl From<&[u8]> for EthernetMac {

    fn from(slice: &[u8]) -> Self {
        assert_eq!(slice.len(), 6, "Slice must be 6 bytes long");
        let mut bytes = [0u8; 6];
        bytes.copy_from_slice(slice);
        EthernetMac(bytes)
    }
}

impl fmt::Display for EthernetMac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5])
    }
}

impl Serialize for EthernetMac {

    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }

}

#[derive(Debug, PartialEq)]
pub struct ProtoEthernetInfo {
    pub src: EthernetMac,
    pub dst: EthernetMac,
    pub eth_type: u16,
}


pub struct ProtoEthernet {}

impl ProtoEthernet {

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

impl ProtoPktProcessor for ProtoEthernet {

    fn new() -> Self {
        Self {}
    }

    fn process(&mut self, pkt: &mut Packet, stack: &mut PktInfoStack) -> Result<(), ParseErr> {

        let src = EthernetMac(pkt.read_fixed::<6>()?);
        let dst = EthernetMac(pkt.read_fixed::<6>()?);
        let eth_type = pkt.read_u16_be()?;

        let info = stack.proto_last_mut();

        let proto_info = ProtoEthernetInfo {
            src,
            dst,
            eth_type,
        };


        info.proto_info = Some(ProtoInfo::Ethernet(proto_info));

        stack.proto_push(ProtoEthernet::next_proto(eth_type), None);

        Ok(())

    }

}


#[cfg(test)]
mod tests {

    use super::*;
    use crate::packet::PktTime;

    #[test]
    fn ethernet_parse_basic() {
        let data = vec![ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0xBE, 0xEF, 0x01, 0x02, 0x03];
        let mut pkt = Packet::from_slice(PktTime::from_micros(0), &data);
        let mut infos = PktInfoStack::new(Protocols::Ethernet);

        let ret = ProtoEthernet::new().process(&mut pkt, &mut infos);
        assert_eq!(ret, Ok(()));

        let info = infos.iter().next().unwrap();

        let expected = ProtoInfo::Ethernet(ProtoEthernetInfo {
            src: EthernetMac([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            dst: EthernetMac([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]),
            eth_type: 0xBEEF,
        });

        assert_eq!(info.proto_info, Some(expected));

    }

    #[test]
    fn ethernet_too_short() {
        let data = vec![ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0xBE];
        let mut pkt = Packet::from_slice(PktTime::from_micros(0), &data);
        let mut infos = PktInfoStack::new(Protocols::Ethernet);

        let ret = ProtoEthernet::new().process(&mut pkt, &mut infos);
        assert_eq!(ret, Err(ParseErr::Truncated));
    }
}
