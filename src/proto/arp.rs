use crate::proto::{ProtoPktProcessor, ProtoParseResult, ProtoInfo};
use crate::packet::{Packet, PktInfoStack};
use crate::proto::ethernet::EthernetMac;

use std::net::Ipv4Addr;

#[derive(Debug, PartialEq)]
pub struct ProtoArpInfo {
    pub sender_ip: Ipv4Addr,
    pub target_ip: Ipv4Addr,
    pub sender_hw: EthernetMac,
    pub target_hw: EthernetMac,
    pub opcode: u16,

}


pub struct ProtoArp {}

impl ProtoArp {
    pub fn new() -> Self {
        Self {}
    }
}

impl ProtoPktProcessor for ProtoArp {

    fn process(&mut self, pkt: &mut Packet, infos: &mut PktInfoStack) -> ProtoParseResult {

        let plen = pkt.remaining_len();

        if plen < 28 {
            return ProtoParseResult::Invalid;
        }

        let hw_type = pkt.read_u16().unwrap();
        let proto_type = pkt.read_u16().unwrap();
        let hw_len = pkt.read_u8().unwrap();
        let proto_len = pkt.read_u8().unwrap();

        if hw_type != 0x1 {
            // Only ethernet is supported
            return ProtoParseResult::Invalid;
        }

        if proto_type != 0x0800 {
            // Only IPv4 is supported
            return ProtoParseResult::Invalid;
        }

        if hw_len != 6 || proto_len != 4 {
            // Invalid size for ethernet/ipv4
            return ProtoParseResult::Invalid;
        }

        let opcode = pkt.read_u16().unwrap();
        let sender_hw: EthernetMac = pkt.read_bytes(6).unwrap().try_into().unwrap();
        let sender_ip_raw = pkt.read_bytes(4).unwrap();
        let sender_ip = Ipv4Addr::new(sender_ip_raw[0], sender_ip_raw[1], sender_ip_raw[2], sender_ip_raw[3]);
        let target_hw: EthernetMac = pkt.read_bytes(6).unwrap().try_into().unwrap();
        let target_ip_raw = pkt.read_bytes(4).unwrap();
        let target_ip = Ipv4Addr::new(target_ip_raw[0], target_ip_raw[1], target_ip_raw[2], target_ip_raw[3]);

        let info = infos.proto_last_mut();

        let proto_info = ProtoArpInfo {
            sender_ip,
            target_ip,
            sender_hw,
            target_hw,
            opcode
        };

        info.proto_info = Some(ProtoInfo::Arp(proto_info));

        return ProtoParseResult::Ok;
    }

}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::packet::{PktDataBorrowed, PktTime};
    use crate::proto::Protocols;

    #[test]
    fn arp_parse_basic() {
        let data = vec![0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x01, 0x01, 0x01, 0x01, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x02, 0x02, 0x02, 0x02];
        let pkt_data = PktDataBorrowed::new(&data);
        let mut pkt = Packet::new(PktTime::from_micros(0), pkt_data);
        let mut infos = PktInfoStack::new(Protocols::Arp);

        let ret = ProtoArp::new().process(&mut pkt, &mut infos);
        assert_eq!(ret, ProtoParseResult::Ok);

        let info = infos.iter().next().unwrap();

        let expected = ProtoInfo::Arp(ProtoArpInfo {
            opcode: 0x01,
            sender_hw: EthernetMac([0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A]),
            sender_ip: Ipv4Addr::new(0x01, 0x01, 0x01, 0x01),
            target_hw: EthernetMac([0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B]),
            target_ip: Ipv4Addr::new(0x02, 0x02, 0x02, 0x02),
        });

        assert_eq!(info.proto_info, Some(expected));
    }

}
