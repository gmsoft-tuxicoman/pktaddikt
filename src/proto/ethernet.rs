use crate::proto::{ProtoPktProcessor, Protocols, ProtoParseResult};
use crate::param::{Param, ParamValue};
use crate::packet::{Packet, PktInfoStack};

pub struct ProtoEthernet {}

impl ProtoPktProcessor for ProtoEthernet {


    fn process(pkt: &mut Packet, stack: &mut PktInfoStack) -> ProtoParseResult {


        if pkt.remaining_len() < 14 {
            return ProtoParseResult::Invalid;
        }



        let f_src = ParamValue::Mac(pkt.read_bytes(6).unwrap().try_into().unwrap());
        let f_dst = ParamValue::Mac(pkt.read_bytes(6).unwrap().try_into().unwrap());
        let eth_type = pkt.read_u16().unwrap();
        let f_eth_type = ParamValue::U16(eth_type);

        let info = stack.proto_last_mut();

        info.field_push(Param { name: "src", value: Some(f_src)});
        info.field_push(Param { name: "dst", value: Some(f_dst)});
        info.field_push(Param { name: "type", value: Some(f_eth_type)});

        let next_proto = match eth_type {
            0x0800 => Protocols::Ipv4,
            0x86DD => Protocols::Ipv6,
            _ => Protocols::None
        };

        stack.proto_push(next_proto, None);

        ProtoParseResult::Ok

    }

    fn purge() {}
}


#[cfg(test)]
mod tests {

    use super::*;
    use crate::param::tests::param_assert_eq;
    use crate::packet::{PktTime, PktDataBorrowed};

    #[test]
    fn ethernet_parse_basic() {
        let data = vec![ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0xBE, 0xEF, 0x01, 0x02, 0x03];
        let pkt_data = PktDataBorrowed::new(&data);
        let mut pkt = Packet::new(PktTime::from_nanos(0), pkt_data);
        let mut infos = PktInfoStack::new(Protocols::Ethernet);

        let ret = ProtoEthernet::process(&mut pkt, &mut infos);
        assert_eq!(ret, ProtoParseResult::Ok);

        let info = infos.iter().next().unwrap();

        let mut field_iter = info.iter_fields();

        let src = field_iter.next().unwrap();
        param_assert_eq(src, "src", ParamValue::Mac([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]));
        let dst = field_iter.next().unwrap();
        param_assert_eq(dst, "dst", ParamValue::Mac([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]));
        let t = field_iter.next().unwrap();
        param_assert_eq(t, "type", ParamValue::U16(0xBEEF));


    }

    #[test]
    fn ethernet_too_short() {
        let data = vec![ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0xBE];
        let pkt_data = PktDataBorrowed::new(&data);
        let mut pkt = Packet::new(PktTime::from_nanos(0), pkt_data);
        let mut infos = PktInfoStack::new(Protocols::Ethernet);

        let ret = ProtoEthernet::process(&mut pkt, &mut infos);
        assert_eq!(ret, ProtoParseResult::Invalid);
    }
}
