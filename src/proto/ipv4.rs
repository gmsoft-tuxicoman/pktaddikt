use crate::proto::{ProtoProcessor, ProtoParseResult, Protocols};
use crate::param::{Param, ParamValue};
use crate::conntrack::{ConntrackTable, ConntrackKeyBidir};
use crate::packet::Packet;


use std::sync::OnceLock;
use std::net::Ipv4Addr;


pub struct ProtoIpv4 {}

type ConntrackKeyIpv4 = ConntrackKeyBidir<u32>;

static CT_IPV4_SIZE :usize = 65535;
static CT_IPV4: OnceLock<ConntrackTable<ConntrackKeyIpv4>> = OnceLock::new();

impl ProtoProcessor for ProtoIpv4 {


    fn process(pkt: &mut Packet) -> ProtoParseResult {

        let plen = pkt.data_len();
        if plen < 20 { // length smaller than IP header
            return ProtoParseResult::Invalid;
        }

        let hdr = pkt.read_bytes(20).unwrap();


        if hdr[0] >> 4 != 4 { // not IP version 4
            return ProtoParseResult::Invalid;
        }

        let hdr_len = (hdr[0] & 0xf) as u16 * 4;

        if hdr_len < 20 { // header length smaller than minimum IP header
            return ProtoParseResult::Invalid;
        }

        let tot_len :u16 = (hdr[2] as u16) << 8 | hdr[3] as u16;
        if tot_len < hdr_len { // datagram size < header length
            return ProtoParseResult::Invalid;
        } else if (tot_len as usize) > plen { // Truncated packet
            return ProtoParseResult::Invalid;
        }

        let src = Ipv4Addr::new(hdr[12], hdr[13], hdr[14], hdr[15]);
        let dst = Ipv4Addr::new(hdr[16], hdr[17], hdr[18], hdr[19]);
        let proto = hdr[9];

        let f_src = ParamValue::Ipv4(src);
        let f_dst = ParamValue::Ipv4(dst);
        let f_hdr_len = ParamValue::U16(hdr_len);
        let f_proto = ParamValue::U8(proto);

        let info = pkt.stack_last_mut();
        info.field_push(Param { name: "src", value: Some(f_src) });
        info.field_push(Param { name: "dst", value: Some(f_dst) });
        info.field_push(Param { name: "hdr_len", value: Some(f_hdr_len) });
        info.field_push(Param { name: "proto", value: Some(f_proto) });


        let ct_key = ConntrackKeyIpv4 { a: src.to_bits(), b: dst.to_bits()};
        let ce = CT_IPV4.get_or_init(|| ConntrackTable::new(CT_IPV4_SIZE)).get(ct_key, info.parent_ce());

        let next_proto = match proto {
            17 => Protocols::Udp,
            _ => Protocols::None
        };

        pkt.stack_push(next_proto, Some(ce));

        ProtoParseResult::Ok

    }

}
