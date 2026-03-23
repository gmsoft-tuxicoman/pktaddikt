use crate::proto::{ProtoPktProcessor, ProtoParseResult};
use crate::param::{Param, ParamValue};
use crate::packet::{Packet, PktInfoStack};
use crate::proto::ethernet::ProtoEthernet;

pub struct ProtoVlan {}


impl ProtoPktProcessor for ProtoVlan {

    fn process(pkt: &mut Packet, infos: &mut PktInfoStack) -> ProtoParseResult {

        let plen = pkt.remaining_len();

        if plen < 4 {
            return ProtoParseResult::Invalid;
        }

        let tci = pkt.read_u16().unwrap();
        let eth_type = pkt.read_u16().unwrap();


        let priority = ParamValue::U8(((tci & 0xE000) >> 13) as u8);
        let drop_eligible = ParamValue::U8(((tci & 0x1000) >> 12) as u8);
        let id = ParamValue::U16(tci & 0x0FFF);

        let info = infos.proto_last_mut();
        info.field_push(Param { name: "priority", value: Some(priority) });
        info.field_push(Param { name: "drop_eligible", value: Some(drop_eligible) });
        info.field_push(Param { name: "id", value: Some(id) });

        infos.proto_push(ProtoEthernet::next_proto(eth_type), None);

        ProtoParseResult::Ok
    }

    fn purge() {}
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::packet::{PktDataBorrowed, PktTime};
    use crate::proto::Protocols;
    use crate::param::tests::param_assert_eq;

    #[test]
    fn vlan_parse_basic() {
        let data = vec![0x50, 0x0a, 0x81, 0x00];
        let pkt_data = PktDataBorrowed::new(&data);
        let mut pkt = Packet::new(PktTime::from_nanos(0), pkt_data);
        let mut infos = PktInfoStack::new(Protocols::Vlan);

        let ret = ProtoVlan::process(&mut pkt, &mut infos);
        assert_eq!(ret, ProtoParseResult::Ok);

        let info = infos.iter().next().unwrap();
        let mut field_iter = info.iter_fields();

        let priority = field_iter.next().unwrap();
        param_assert_eq(priority, "priority", ParamValue::U8(0x02));
        let drop_eligible = field_iter.next().unwrap();
        param_assert_eq(drop_eligible, "drop_eligible", ParamValue::U8(0x01));
        let id = field_iter.next().unwrap();
        param_assert_eq(id, "id", ParamValue::U16(0x0a));
    }

}
