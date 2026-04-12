use crate::proto::{ProtoPktProcessor, ProtoParseResult, ProtoInfo};
use crate::packet::{Packet, PktInfoStack};
use crate::proto::ethernet::ProtoEthernet;


#[derive(Debug, PartialEq)]
pub struct ProtoVlanInfo {
    pub priority: u8,
    pub drop_eligible: u8,
    pub id: u16,
    pub eth_type: u16,
}

pub struct ProtoVlan {}

impl ProtoVlan {

    pub fn new() -> Self {
        Self {}
    }

}

impl ProtoPktProcessor for ProtoVlan {

    fn process(&mut self, pkt: &mut Packet, infos: &mut PktInfoStack) -> ProtoParseResult {

        let plen = pkt.remaining_len();

        if plen < 4 {
            return ProtoParseResult::Invalid;
        }

        let tci = pkt.read_u16().unwrap();
        let eth_type = pkt.read_u16().unwrap();


        let priority = ((tci & 0xE000) >> 13) as u8;
        let drop_eligible = ((tci & 0x1000) >> 12) as u8;
        let id = tci & 0x0FFF;

        let info = infos.proto_last_mut();

        let proto_info = ProtoVlanInfo {
            priority,
            drop_eligible,
            id,
            eth_type,
        };

        info.proto_info = Some(ProtoInfo::Vlan(proto_info));

        infos.proto_push(ProtoEthernet::next_proto(eth_type), None);

        ProtoParseResult::Ok
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::packet::{PktDataBorrowed, PktTime};
    use crate::proto::Protocols;

    #[test]
    fn vlan_parse_basic() {
        let data = vec![0x50, 0x0a, 0x81, 0x00];
        let pkt_data = PktDataBorrowed::new(&data);
        let mut pkt = Packet::new(PktTime::from_micros(0), pkt_data);
        let mut infos = PktInfoStack::new(Protocols::Vlan);

        let ret = ProtoVlan::new().process(&mut pkt, &mut infos);
        assert_eq!(ret, ProtoParseResult::Ok);

        let info = infos.iter().next().unwrap();

        let expected = ProtoInfo::Vlan(ProtoVlanInfo {
            priority: 0x02,
            drop_eligible: 0x01,
            id: 0x0a,
            eth_type: 0x8100,
        });

        assert_eq!(info.proto_info, Some(expected));
    }

}
