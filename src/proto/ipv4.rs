use crate::proto::{Proto, ProtoProcessor, ProtoParseResult, Protocols};
use crate::param::{Param, ParamValue};
use crate::conntrack::{ConntrackTable, ConntrackKeyBidir, ConntrackData};
use crate::packet::{Packet, PktDataMultipart};

use std::sync::OnceLock;
use std::net::Ipv4Addr;
use std::collections::HashMap;
use std::time::Duration;
use tracing::trace;

const IP_DONT_FRAG: u16 = 0x4000;
const IP_MORE_FRAG: u16 = 0x2000;
const IP_OFFSET_MASK: u16 = 0x1FFF;

const IP_TIMEOUT :u64 = 7200;

pub struct ProtoIpv4 {}

type ConntrackKeyIpv4 = ConntrackKeyBidir<u32>;


struct ConntrackIpv4 {
    fragments: HashMap<u16, PktDataMultipart>
}

static CT_IPV4_SIZE :usize = 65535;
static CT_IPV4: OnceLock<ConntrackTable<ConntrackKeyIpv4>> = OnceLock::new();

impl ProtoProcessor for ProtoIpv4 {


    fn process(pkt: &mut Packet) -> ProtoParseResult {

        let plen = pkt.remaining_len();
        if plen < 20 { // length smaller than IP header
            trace!("Payload lenght smaller than IP header in packet {:p}", pkt);
            return ProtoParseResult::Invalid;
        }

        let hdr = pkt.read_bytes(20).unwrap();

        let ip_version = hdr[0] >> 4;
        if ip_version != 4 { // not IP version 4
            trace!("Invalid protocol version : {} in packet {:p}", ip_version, pkt);
            return ProtoParseResult::Invalid;
        }

        let tot_len :u16 = (hdr[2] as u16) << 8 | hdr[3] as u16;
        let hdr_len = (hdr[0] & 0xf) as u16 * 4;
        let id = (hdr[4] as u16) << 8 | (hdr[5] as u16);
        let src = Ipv4Addr::new(hdr[12], hdr[13], hdr[14], hdr[15]);
        let dst = Ipv4Addr::new(hdr[16], hdr[17], hdr[18], hdr[19]);
        let proto = hdr[9];
        let frag_off = (hdr[6] as u16) << 8 | (hdr[7] as u16);

        if hdr_len < 20 { // header length smaller than minimum IP header
            trace!("Header length too small for packet {:p}", pkt);
            return ProtoParseResult::Invalid;
        }

        if tot_len <= hdr_len { // Total length <= header length
            trace!("Total length shorter than header size in packet {:p}", pkt);
            return ProtoParseResult::Invalid;
        } else if (tot_len as usize) > plen { // Truncated packet
            trace!("Truncated packet {:p}", pkt);
            return ProtoParseResult::Stop;
        }

        // Skip IP options
        if hdr_len > 20 {
            if pkt.skip_bytes((hdr_len - 20).into()) == Err(()) {
                return ProtoParseResult::Invalid;
            }
        }

        // Shrink payload to the right size
        let data_len = (tot_len - hdr_len) as usize;
        if data_len < pkt.remaining_len() {
            pkt.shrink_remaining(data_len.into());
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
            ce.lock().unwrap().set_timeout(Duration::from_secs(IP_TIMEOUT), pkt.ts);
            pkt.stack_push(next_proto, Some(ce));
            return ProtoParseResult::Ok;
        }

        // Packet cannot be fragmented
        if (frag_off & IP_DONT_FRAG) != 0 {
            ce.lock().unwrap().set_timeout(Duration::from_secs(IP_TIMEOUT), pkt.ts);
            pkt.stack_push(next_proto, Some(ce));
            return ProtoParseResult::Ok;
        }

        pkt.stack_push(next_proto, Some(ce.clone()));

        let offset = ((frag_off & IP_OFFSET_MASK) << 3) as usize;

        let mut ce_locked = ce.lock().unwrap();
        ce_locked.set_timeout(Duration::from_secs(IP_TIMEOUT), pkt.ts);

        let cd = ce_locked.get_or_insert(Box::new(ConntrackIpv4 { fragments: HashMap::new() }) as ConntrackData)
                    .downcast_mut::<ConntrackIpv4>()
                    .unwrap();

        let frags_entry = cd.fragments.entry(id);

        let frags = frags_entry.or_insert(PktDataMultipart::new(1500));

        frags.add(offset, pkt.remaining_data());

        if (frag_off & IP_MORE_FRAG) == 0 {
            // Last fragment
            frags.set_expected_len(offset + data_len);
        }

        if frags.is_complete() {
            // Process the reassembled packet
            let mut frags = cd.fragments.remove(&id).unwrap();
            let mut pkt = Packet::new(pkt.ts, next_proto, &mut frags);

            Proto::process_packet(&mut pkt);

        }

        ProtoParseResult::Stop

    }

    fn purge() {
       if let Some(ct) = CT_IPV4.get() {
           ct.purge();
        }
    }
}


#[cfg(test)]
mod tests {

    use super::*;
    use crate::packet::PktDataSimple;
    use crate::param::tests::param_assert_eq;
    use tracing_test::traced_test;

    fn ipv4_parse_test(data: &[u8]) -> ProtoParseResult {
        let mut pkt_data = PktDataSimple::new(&data);
        let mut pkt = Packet::new(0, Protocols::Ipv4, &mut pkt_data);
        pkt.stack_push(Protocols::Ipv4, None);

        ProtoIpv4::process(&mut pkt)
    }

    #[test]
    fn ipv4_parse_basic() {
        let data = vec![ 0x45, 0x00, 0x00, 0x16, 0xbe, 0xef, 0x00, 0x00, 0x40, 0x11, 0xff, 0xff, 0x01, 0x02, 0x03, 0x04, 0x10, 0x20, 0x30, 0x40, 0xde, 0xad ];
        let mut pkt_data = PktDataSimple::new(&data);
        let mut pkt = Packet::new(0, Protocols::Ipv4, &mut pkt_data);
        pkt.stack_push(Protocols::Ipv4, None);

        let ret = ProtoIpv4::process(&mut pkt);
        assert_eq!(ret, ProtoParseResult::Ok);

        let info = pkt.iter_stack().next().unwrap();
        let mut field_iter = info.iter_fields();

        let src = field_iter.next().unwrap();
        param_assert_eq(src, "src", ParamValue::Ipv4(Ipv4Addr::new(0x01, 0x02, 0x03, 0x04)));
        let dst = field_iter.next().unwrap();
        param_assert_eq(dst, "dst", ParamValue::Ipv4(Ipv4Addr::new(0x10, 0x20, 0x30, 0x40)));
        let hdr_len = field_iter.next().unwrap();
        param_assert_eq(hdr_len, "hdr_len", ParamValue::U16(20));
        let id = field_iter.next().unwrap();
        param_assert_eq(id, "id", ParamValue::U16(48879));
        let proto = field_iter.next().unwrap();
        param_assert_eq(proto, "proto", ParamValue::U8(17));


    }

    #[test]
    #[traced_test]
    fn ipv4_packet_too_short() {
        let data = vec![ 0x45, 0x00, 0x05, 0xdc, 0xbe, 0xef, 0x00, 0x00, 0x40, 0x11, 0xff, 0xff, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02 ];
        let ret = ipv4_parse_test(&data);
        assert_eq!(ret, ProtoParseResult::Invalid);
        assert!(logs_contain("Payload lenght smaller than IP header"));
    }

    #[test]
    #[traced_test]
    fn ipv4_invalid_version() {
        let data = vec![ 0x55, 0x00, 0x05, 0xdc, 0xbe, 0xef, 0x00, 0x00, 0x40, 0x11, 0xff, 0xff, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02 ];
        let ret = ipv4_parse_test(&data);
        assert_eq!(ret, ProtoParseResult::Invalid);
        assert!(logs_contain("Invalid protocol version : 5"));
    }

    #[test]
    #[traced_test]
    fn ipv4_hlen_too_short() {
        let data = vec![ 0x44, 0x00, 0x05, 0xdc, 0xbe, 0xef, 0x00, 0x00, 0x40, 0x11, 0xff, 0xff, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02 ];
        let ret = ipv4_parse_test(&data);
        assert_eq!(ret, ProtoParseResult::Invalid);
        assert!(logs_contain("Header length too small"));
    }

    #[test]
    #[traced_test]
    fn ipv4_totlen_too_short() {
        let data = vec![ 0x45, 0x00, 0x00, 0x14, 0xbe, 0xef, 0x00, 0x00, 0x40, 0x11, 0xff, 0xff, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02 ];
        let ret = ipv4_parse_test(&data);
        assert_eq!(ret, ProtoParseResult::Invalid);
        assert!(logs_contain("Total length shorter than header size"));
    }

    #[test]
    #[traced_test]
    fn ipv4_truncated_pkt() {
        let data = vec![ 0x45, 0x00, 0x00, 0xff, 0xbe, 0xef, 0x00, 0x00, 0x40, 0x11, 0xff, 0xff, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02 ];
        let ret = ipv4_parse_test(&data);
        assert_eq!(ret, ProtoParseResult::Stop);
        assert!(logs_contain("Truncated packet"));
    }

    #[test]
    fn ipv4_pkt_shrink() {
        let data = vec![ 0x45, 0x00, 0x00, 0x15, 0xbe, 0xef, 0x00, 0x00, 0x40, 0x11, 0xff, 0xff, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0xff, 0xff ];
        let mut pkt_data = PktDataSimple::new(&data);
        let mut pkt = Packet::new(0, Protocols::Ipv4, &mut pkt_data);
        pkt.stack_push(Protocols::Ipv4, None);

        let ret = ProtoIpv4::process(&mut pkt);
        assert_eq!(ret, ProtoParseResult::Ok);

        let remaining = pkt.remaining_len();
        println!("remaining: {}", remaining);
        assert_eq!(pkt.remaining_len(), 1);

    }
}
