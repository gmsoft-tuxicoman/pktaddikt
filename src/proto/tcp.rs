use crate::proto::{ProtoProcessor, ProtoParseResult, Protocols};
use crate::param::{Param, ParamValue};
use crate::conntrack::{ConntrackTable, ConntrackKeyBidir};
use crate::packet::Packet;

use std::sync::OnceLock;
use std::time::Duration;
use tracing::trace;


type ConntrackKeyTcp = ConntrackKeyBidir<u16>;

static TCP_TIMEOUT :u64 = 120;

static CT_TCP_SIZE :usize = 32768;
static CT_TCP: OnceLock<ConntrackTable<ConntrackKeyTcp>> = OnceLock::new();


const TCP_TH_FIN: u8 = 0x1;
const TCP_TH_SYN: u8 = 0x2;
const TCP_TH_RST: u8 = 0x4;
const TCP_TH_ACK: u8 = 0x10;

pub struct ProtoTcp {}


impl ProtoProcessor for ProtoTcp {

    fn process(pkt: &mut Packet) -> ProtoParseResult {

        let plen = pkt.remaining_len();
        if plen < 20 { // length smaller than TCP header
            trace!("Payload length smaller than TCP header in packet {:p}", pkt);
            return ProtoParseResult::Invalid;
        }

        let hdr = pkt.read_bytes(20).unwrap();

        let sport: u16 = (hdr[0] as u16) << 8 | (hdr[1] as u16);
        let dport: u16 = (hdr[2] as u16) << 8 | (hdr[3] as u16);
        let seq: u32 = (hdr[4] as u32) << 24 | (hdr[5] as u32) << 16 | (hdr[6] as u32) << 8 | (hdr[7] as u32);
        let ack: u32 = (hdr[8] as u32) << 24 | (hdr[9] as u32) << 16 | (hdr[10] as u32) << 8 | (hdr[11] as u32);
        let window: u16 = (hdr[14] as u16) << 8 | (hdr[15] as u16);
        let flags: u8 = hdr[13];

        let hdr_len = ((hdr[12] & 0xf0) >> 2) as usize;

        if hdr_len < 20 {
            // Header length too small
            trace!("Header length too small in packet {:p}", pkt);
            return ProtoParseResult::Invalid;
        }

        if hdr_len > plen {
            // Header length bigger than payload size
            trace!("Header length bigger than payload size in packet {:p}", pkt);
            return ProtoParseResult::Invalid;
        }

        if hdr_len > 20 {
            // Skip options and padding
            if pkt.skip_bytes((hdr_len - 20).into()) == Err(()) {
                return ProtoParseResult::Invalid;
            }
        }

        let mut data_len = plen - hdr_len;
        if ((flags & TCP_TH_SYN) != 0) && data_len > 0 {
            // No payload allowed in SYN packets
            trace!("SYN segment contains data in packet {:p}", pkt);
            return ProtoParseResult::Invalid;
        }

        if ((flags & TCP_TH_RST) != 0) && data_len > 0 {
            // RFC 1122 4.2.2.12 : RST may contain the data that caused the packet to be sent,
            // discard it
            pkt.shrink_remaining(0);
            data_len = 0;
        }



        let info = pkt.stack_last_mut();
        info.field_push(Param { name: "sport", value: Some(ParamValue::U16(sport)) });
        info.field_push(Param { name: "dport", value: Some(ParamValue::U16(dport)) });
        info.field_push(Param { name: "seq", value: Some(ParamValue::U32(seq)) });
        info.field_push(Param { name: "ack", value: Some(ParamValue::U32(ack)) });
        info.field_push(Param { name: "win", value: Some(ParamValue::U16(window)) });


        let ct_key = ConntrackKeyTcp { a: sport, b: dport };
        let ce = CT_TCP.get_or_init(|| ConntrackTable::new(CT_TCP_SIZE)).get(ct_key, info.parent_ce(), Some((Duration::from_secs(TCP_TIMEOUT), pkt.ts)));

        // WIP, needs to be improved
        let next_proto = match dport {
            0 => Protocols::Test,
            _ => Protocols::None
        };

        pkt.stack_push(next_proto, Some(ce));


        ProtoParseResult::Ok

    }

    fn purge() {
        if let Some(ct) = CT_TCP.get() {
           ct.purge();
        }
    }

}


#[cfg(test)]
mod tests {

    use super::*;
    use crate::packet::PktDataBorrowed;
    use crate::param::tests::param_assert_eq;
    use crate::proto::ProtoTest;
    use tracing_test::traced_test;

    fn tcp_parse_test(data: &[u8]) -> ProtoParseResult {
        let mut pkt_data = PktDataBorrowed::new(&data);
        let mut pkt = Packet::new(0, Protocols::Tcp, &mut pkt_data);

        ProtoTcp::process(&mut pkt)

    }

    #[test]
    fn tcp_parse_basic() {
        let data = vec![ 0x00, 0x01, 0x00, 0x02, 0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb, 0x50, 0x00, 0x00, 0x10, 0xff, 0xff, 0x00, 0x00, 0xcc ];
        let mut pkt_data = PktDataBorrowed::new(&data);
        let mut pkt = Packet::new(0, Protocols::Tcp, &mut pkt_data);

        let ret = ProtoTcp::process(&mut pkt);
        assert_eq!(ret, ProtoParseResult::Ok);

        let info = pkt.iter_stack().next().unwrap();
        let mut field_iter = info.iter_fields();

        let sport = field_iter.next().unwrap();
        param_assert_eq(sport, "sport", ParamValue::U16(1));
        let dport = field_iter.next().unwrap();
        param_assert_eq(dport, "dport", ParamValue::U16(2));
        let seq = field_iter.next().unwrap();
        param_assert_eq(seq, "seq", ParamValue::U32(2863311530));
        let ack = field_iter.next().unwrap();
        param_assert_eq(ack, "ack", ParamValue::U32(3149642683));
        let win = field_iter.next().unwrap();
        param_assert_eq(win, "win", ParamValue::U16(16));
    }

    #[test]
    #[traced_test]
    fn tcp_packet_too_short() {
        let data = vec![ 0x00, 0x01, 0x00, 0x02, 0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb, 0x50, 0x00, 0x00, 0x10, 0xff, 0xff, 0x00 ];
        let ret = tcp_parse_test(&data);
        assert_eq!(ret, ProtoParseResult::Invalid);
        assert!(logs_contain("Payload length smaller than TCP header"));
    }

    #[test]
    #[traced_test]
    fn tcp_header_too_small() {
        let data = vec![ 0x00, 0x01, 0x00, 0x02, 0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb, 0x40, 0x00, 0x00, 0x10, 0xff, 0xff, 0x00, 0x00, 0xcc ];
        let ret = tcp_parse_test(&data);
        assert_eq!(ret, ProtoParseResult::Invalid);
        assert!(logs_contain("Header length too small"));
    }

    #[test]
    #[traced_test]
    fn tcp_header_too_big() {
        let data = vec![ 0x00, 0x01, 0x00, 0x02, 0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb, 0x70, 0x00, 0x00, 0x10, 0xff, 0xff, 0x00, 0x00, 0xcc ];
        let ret = tcp_parse_test(&data);
        assert_eq!(ret, ProtoParseResult::Invalid);
        assert!(logs_contain("Header length bigger than payload size"));
    }

    #[test]
    #[traced_test]
    fn tcp_skip_options() {
        let data = vec![ 0x00, 0x01, 0x00, 0x00, 0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb, 0x70, 0x00, 0x00, 0x10, 0xff, 0xff, 0x00, 0x00, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xdd ];

        let expected_data = vec![ 0xdd ];
        ProtoTest::add_expectation(&expected_data, 0);

        let mut pkt_data = PktDataBorrowed::new(&data);
        let mut pkt = Packet::new(0, Protocols::Tcp, &mut pkt_data);

        let ret = ProtoTcp::process(&mut pkt);
        assert_eq!(ret, ProtoParseResult::Ok);
        assert_eq!(pkt.stack_last().proto, Protocols::Test);

        ProtoTest::process(&mut pkt);
        ProtoTest::assert_empty();

    }

    #[test]
    #[traced_test]
    fn tcp_syn_with_pload() {
        let data = vec![ 0x00, 0x01, 0x00, 0x02, 0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb, 0x50, 0x02, 0x00, 0x10, 0xff, 0xff, 0x00, 0x00, 0xcc ];
        let ret = tcp_parse_test(&data);
        assert_eq!(ret, ProtoParseResult::Invalid);
        assert!(logs_contain("SYN segment contains data"));
    }

}
