use crate::proto::{ProtoPktProcessor, Protocols, ProtoParseResult, ProtoInfo};
use crate::packet::{Packet, PktInfoStack};


#[derive(Debug, PartialEq)]
pub struct EthernetMac(pub [u8;6]);

impl From<&[u8]> for EthernetMac {

    fn from(slice: &[u8]) -> Self {
        assert_eq!(slice.len(), 6, "Slice must be 6 bytes long");
        let mut bytes = [0u8; 6];
        bytes.copy_from_slice(slice);
        EthernetMac(bytes)
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

    pub fn new() -> Self {
        Self {}
    }

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

    fn process(&mut self, pkt: &mut Packet, stack: &mut PktInfoStack) -> ProtoParseResult {

        if pkt.remaining_len() < 14 {
            return ProtoParseResult::Invalid;
        }

        let src: EthernetMac = pkt.read_bytes(6).unwrap().try_into().unwrap();
        let dst: EthernetMac = pkt.read_bytes(6).unwrap().try_into().unwrap();
        let eth_type = pkt.read_u16().unwrap();

        let info = stack.proto_last_mut();

        let proto_info = ProtoEthernetInfo {
            src,
            dst,
            eth_type,
        };


        info.proto_info = Some(ProtoInfo::Ethernet(proto_info));

        stack.proto_push(ProtoEthernet::next_proto(eth_type), None);

        ProtoParseResult::Ok

    }

}


#[cfg(test)]
mod tests {

    use super::*;
    use crate::packet::{PktTime, PktDataBorrowed};

    #[test]
    fn ethernet_parse_basic() {
        let data = vec![ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0xBE, 0xEF, 0x01, 0x02, 0x03];
        let pkt_data = PktDataBorrowed::new(&data);
        let mut pkt = Packet::new(PktTime::from_micros(0), pkt_data);
        let mut infos = PktInfoStack::new(Protocols::Ethernet);

        let ret = ProtoEthernet::new().process(&mut pkt, &mut infos);
        assert_eq!(ret, ProtoParseResult::Ok);

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
        let pkt_data = PktDataBorrowed::new(&data);
        let mut pkt = Packet::new(PktTime::from_micros(0), pkt_data);
        let mut infos = PktInfoStack::new(Protocols::Ethernet);

        let ret = ProtoEthernet::new().process(&mut pkt, &mut infos);
        assert_eq!(ret, ProtoParseResult::Invalid);
    }
}
