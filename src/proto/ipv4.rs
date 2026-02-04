use crate::proto::{ProtoProcessor, ProtoParseResult, Protocols};
use crate::param::{Param, ParamValue};
use crate::conntrack::{ConntrackTable, ConntrackKeyBidir, ConntrackData};
use crate::packet::{PktTime, Packet, PktDataMultipart};


use std::sync::OnceLock;
use std::net::Ipv4Addr;
use std::collections::HashMap;
use std::any::Any;

const IP_DONT_FRAG: u16 = 0x4000;
const IP_MORE_FRAG: u16 = 0x2000;
const IP_OFFSET_MASK: u16 = 0x1FFF;

pub struct ProtoIpv4 {}

type ConntrackKeyIpv4 = ConntrackKeyBidir<u32>;


struct Ipv4Frags {
    ts: PktTime,
    data: PktDataMultipart
}

struct ConntrackIpv4 {
    fragments: HashMap<u16, Ipv4Frags>
}

static CT_IPV4_SIZE :usize = 65535;
static CT_IPV4: OnceLock<ConntrackTable<ConntrackKeyIpv4>> = OnceLock::new();

impl ProtoProcessor for ProtoIpv4 {


    fn process(pkt: &mut Packet) -> ProtoParseResult {

        let plen = pkt.remaining_len();
        if plen < 20 { // length smaller than IP header
            return ProtoParseResult::Invalid;
        }

        let hdr = pkt.read_bytes(20).unwrap();

        if hdr[0] >> 4 != 4 { // not IP version 4
            return ProtoParseResult::Invalid;
        }

        let tot_len :u16 = (hdr[2] as u16) << 8 | hdr[3] as u16;
        let hdr_len = (hdr[0] & 0xf) as u16 * 4;
        let id = (hdr[3] as u16) << 8 | (hdr[4] as u16);
        let src = Ipv4Addr::new(hdr[12], hdr[13], hdr[14], hdr[15]);
        let dst = Ipv4Addr::new(hdr[16], hdr[17], hdr[18], hdr[19]);
        let proto = hdr[9];
        let frag_off = (hdr[6] as u16) << 8 | (hdr[7] as u16);

        if hdr_len < 20 { // header length smaller than minimum IP header
            return ProtoParseResult::Invalid;
        }

        if tot_len <= hdr_len { // datagram size <= header length
            return ProtoParseResult::Invalid;
        } else if (tot_len as usize) > plen { // Truncated packet
            return ProtoParseResult::Stop;
        }

        // Shrink payload to the right size
        let data_len = (tot_len - hdr_len) as usize;
        if data_len > plen {
            pkt.shrink(data_len.into());
        }


        // Skip IP options
        if hdr_len > 20 {
            if pkt.skip_bytes((hdr_len - 20).into()) == Err(()) {
                return ProtoParseResult::Invalid;
            }
        }


        let f_src = ParamValue::Ipv4(src);
        let f_dst = ParamValue::Ipv4(dst);
        let f_hdr_len = ParamValue::U16(hdr_len);
        let f_proto = ParamValue::U8(proto);
        let f_id = ParamValue::U16(id);

        let info = pkt.stack_last_mut();
        info.field_push(Param { name: "src", value: Some(f_src) });
        info.field_push(Param { name: "dst", value: Some(f_dst) });
        info.field_push(Param { name: "hdr_len", value: Some(f_hdr_len) });
        info.field_push(Param { name: "id", value: Some(f_id) });
        info.field_push(Param { name: "proto", value: Some(f_proto) });


        let ct_key = ConntrackKeyIpv4 { a: src.to_bits(), b: dst.to_bits()};
        let ce = CT_IPV4.get_or_init(|| ConntrackTable::new(CT_IPV4_SIZE)).get(ct_key, info.parent_ce());

        let next_proto = match proto {
            17 => Protocols::Udp,
            _ => Protocols::None
        };




        // Check if the packet is fragmented and needs more handling

        // Full packet (offset is 0 and no more packets)
        if (frag_off & IP_MORE_FRAG) == 0 && (frag_off & IP_OFFSET_MASK) == 0 {
            pkt.stack_push(next_proto, Some(ce));
            return ProtoParseResult::Ok;
        }

        // Packet cannot be fragmented
        if (frag_off & IP_DONT_FRAG) != 0 {
            pkt.stack_push(next_proto, Some(ce));
            return ProtoParseResult::Ok;
        }

        pkt.stack_push(next_proto, Some(ce.clone()));

        let offset = ((frag_off & IP_OFFSET_MASK) << 3) as usize;

        let mut ce_mut = ce.lock().unwrap();

        let cd = ce_mut.get_or_insert(Box::new(ConntrackIpv4 { fragments: HashMap::new() }) as ConntrackData)
                    .downcast_mut::<ConntrackIpv4>()
                    .unwrap();

        let frags = cd.fragments.entry(id).or_insert(Ipv4Frags {ts: pkt.ts, data: PktDataMultipart::new(1500) });
        frags.data.add(offset, pkt.remaining_data());


        ProtoParseResult::Stop

    }

}
