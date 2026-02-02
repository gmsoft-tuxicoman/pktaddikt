use crate::proto::{ProtoProcessor, Protocols, ProtoParseResult};
use crate::param::{Param, ParamValue};
use crate::packet::Packet;

pub struct ProtoEthernet {}

impl ProtoProcessor for ProtoEthernet {


    fn process(pkt: &mut Packet) -> ProtoParseResult {


        if pkt.data_len() < 14 {
            return ProtoParseResult::Invalid;
        }



        let f_src = ParamValue::Mac(pkt.read_bytes(6).unwrap().try_into().unwrap());
        let f_dst = ParamValue::Mac(pkt.read_bytes(6).unwrap().try_into().unwrap());
        let eth_type = pkt.read_u16().unwrap();
        let f_eth_type = ParamValue::U16(eth_type);

        let info = pkt.stack_last_mut();

        info.field_push(Param { name: "src", value: Some(f_src)});
        info.field_push(Param { name: "dst", value: Some(f_dst)});
        info.field_push(Param { name: "type", value: Some(f_eth_type)});

        let next_proto = match eth_type {
            0x0800 => Protocols::Ipv4,
            0x86DD => Protocols::Ipv6,
            _ => Protocols::None
        };

        pkt.stack_push(next_proto, None);

        ProtoParseResult::Ok

    }
}
