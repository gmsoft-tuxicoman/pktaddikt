use crate::proto::{ProtoPktProcessor, ProtoParseResult};
use crate::param::{Param, ParamValue};
use crate::packet::{Packet, PktInfoStack};

use std::net::Ipv4Addr;

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

        let opcode = ParamValue::U16(pkt.read_u16().unwrap());
        let sender_hw = ParamValue::Mac(pkt.read_bytes(6).unwrap().try_into().unwrap());
        let sender_ip_raw = pkt.read_bytes(4).unwrap();
        let sender_ip = ParamValue::Ipv4(Ipv4Addr::new(sender_ip_raw[0], sender_ip_raw[1], sender_ip_raw[2], sender_ip_raw[3]));
        let target_hw = ParamValue::Mac(pkt.read_bytes(6).unwrap().try_into().unwrap());
        let target_ip_raw = pkt.read_bytes(4).unwrap();
        let target_ip = ParamValue::Ipv4(Ipv4Addr::new(target_ip_raw[0], target_ip_raw[1], target_ip_raw[2], target_ip_raw[3]));

        let info = infos.proto_last_mut();
        info.field_push(Param { name: "opcode", value: Some(opcode) });
        info.field_push(Param { name: "sender_hw", value: Some(sender_hw) });
        info.field_push(Param { name: "sender_ip", value: Some(sender_ip) });
        info.field_push(Param { name: "target_hw", value: Some(target_hw) });
        info.field_push(Param { name: "target_ip", value: Some(target_ip) });

        return ProtoParseResult::Stop;
    }

}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::packet::{PktDataBorrowed, PktTime};
    use crate::proto::Protocols;
    use crate::param::tests::param_assert_eq;

    #[test]
    fn arp_parse_basic() {
        let data = vec![0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x01, 0x01, 0x01, 0x01, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x02, 0x02, 0x02, 0x02];
        let pkt_data = PktDataBorrowed::new(&data);
        let mut pkt = Packet::new(PktTime::from_nanos(0), pkt_data);
        let mut infos = PktInfoStack::new(Protocols::Arp);

        let ret = ProtoArp::process(&mut pkt, &mut infos);
        assert_eq!(ret, ProtoParseResult::Stop);

        let info = infos.iter().next().unwrap();
        let mut field_iter = info.iter_fields();

        let opcode = field_iter.next().unwrap();
        param_assert_eq(opcode, "opcode", ParamValue::U16(0x01));
        let sender_hw = field_iter.next().unwrap();
        param_assert_eq(sender_hw, "sender_hw", ParamValue::Mac([0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A]));
        let sender_ip = field_iter.next().unwrap();
        param_assert_eq(sender_ip, "sender_ip", ParamValue::Ipv4(Ipv4Addr::new(0x01, 0x01, 0x01, 0x01)));
        let target_hw = field_iter.next().unwrap();
        param_assert_eq(target_hw, "target_hw", ParamValue::Mac([0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B]));
        let target_ip = field_iter.next().unwrap();
        param_assert_eq(target_ip, "target_ip", ParamValue::Ipv4(Ipv4Addr::new(0x02, 0x02, 0x02, 0x02)));
    }

}
