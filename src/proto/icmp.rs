use crate::proto::{ProtoPktProcessor, ProtoParseResult};
use crate::param::{Param, ParamValue};
use crate::packet::{Packet, PktInfoStack};

pub struct ProtoIcmp {}

impl ProtoIcmp {
    pub fn new() -> Self {
        Self {}
    }
}

impl ProtoPktProcessor for ProtoIcmp {

    fn process(&mut self, pkt: &mut Packet, infos: &mut PktInfoStack) -> ProtoParseResult {

        let plen = pkt.remaining_len();

        if plen < 8 {
            return ProtoParseResult::Invalid;
        }

        let icmp_type = pkt.read_u8().unwrap();
        let icmp_code = pkt.read_u8().unwrap();

        let info = infos.proto_last_mut();
        info.field_push(Param { name: "type", value: Some(ParamValue::U8(icmp_type)) });
        info.field_push(Param { name: "code", value: Some(ParamValue::U8(icmp_code)) });

        return ProtoParseResult::Ok;
    }

}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::packet::{PktDataBorrowed, PktTime};
    use crate::proto::Protocols;
    use crate::param::tests::param_assert_eq;

    #[test]
    fn icmp_parse_basic() {
        let data = vec![0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let pkt_data = PktDataBorrowed::new(&data);
        let mut pkt = Packet::new(PktTime::from_micros(0), pkt_data);
        let mut infos = PktInfoStack::new(Protocols::Icmp);

        let ret = ProtoIcmp::new().process(&mut pkt, &mut infos);
        assert_eq!(ret, ProtoParseResult::Ok);

        let info = infos.iter().next().unwrap();
        let mut field_iter = info.iter_fields();

        let icmp_type = field_iter.next().unwrap();
        param_assert_eq(icmp_type, "type", ParamValue::U8(0x01));
        let icmp_code = field_iter.next().unwrap();
        param_assert_eq(icmp_code, "code", ParamValue::U8(0x02));
    }

}
