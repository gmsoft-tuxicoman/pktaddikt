mod seq;
pub mod conntrack;

use crate::proto::{ProtoPktProcessor, ProtoParseResult, Protocols};
use crate::param::{Param, ParamValue};
use crate::conntrack::{ConntrackTable, ConntrackKeyBidir, ConntrackData};
use crate::packet::{Packet, PktInfoStack};
use crate::proto::tcp::conntrack::{ConntrackTcp, TcpState};

use std::sync::OnceLock;
use std::time::Duration;
use tracing::trace;


type ConntrackKeyTcp = ConntrackKeyBidir<u16>;

static TCP_TIMEOUT_SYN_RECV :u64 = 60;
static TCP_TIMEOUT_SYN_SENT :u64 = 180;
static TCP_TIMEOUT_ESTABLISHED: u64 = 1800;
static TCP_TIMEOUT_HALF_CLOSED: u64 = 120;
static TCP_TIMEOUT_CLOSED: u64 = 30;

static CT_TCP_SIZE :usize = 32768;
static CT_TCP: OnceLock<ConntrackTable<ConntrackKeyTcp>> = OnceLock::new();


const TCP_TH_FIN: u8 = 0x1;
const TCP_TH_SYN: u8 = 0x2;
const TCP_TH_RST: u8 = 0x4;
const TCP_TH_ACK: u8 = 0x10;

pub struct ProtoTcp {}

impl ProtoTcp {
    fn next_proto(port: u16) -> Protocols {
        match port {
            0 => Protocols::Test,
            80 => Protocols::Http,
            _ => Protocols::None
        }
    }

}

impl ProtoPktProcessor for ProtoTcp {

    fn process(pkt: &mut Packet, infos: &mut PktInfoStack) -> ProtoParseResult {

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

        // Check if flags are somewhat valid
        let f_syn_fin_rst = flags & (TCP_TH_SYN | TCP_TH_FIN | TCP_TH_RST);
        if f_syn_fin_rst.count_ones() > 1 {
            trace!("More than one SYN/FIN/RST at the same time in packet {:p}", pkt);
            return ProtoParseResult::Invalid;
        }

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

        if ((flags & TCP_TH_RST) != 0) && pkt.remaining_len() > 0 {
            // RFC 1122 4.2.2.12 : RST may contain the data that caused the packet to be sent,
            // discard it
            pkt.shrink_remaining(0);
        }



        let info = infos.proto_last_mut();
        info.field_push(Param { name: "sport", value: Some(ParamValue::U16(sport)) });
        info.field_push(Param { name: "dport", value: Some(ParamValue::U16(dport)) });
        info.field_push(Param { name: "seq", value: Some(ParamValue::U32(seq)) });
        info.field_push(Param { name: "ack", value: Some(ParamValue::U32(ack)) });
        info.field_push(Param { name: "win", value: Some(ParamValue::U16(window)) });


        // WIP, needs to be improved
        let next_proto = match ProtoTcp::next_proto(dport) {
            Protocols::None => ProtoTcp::next_proto(sport),
            proto => proto
        };

        let ct_key = ConntrackKeyTcp { a: sport, b: dport };
        let (ce, ce_dir) = CT_TCP.get_or_init(|| ConntrackTable::new(CT_TCP_SIZE)).get(ct_key, info.parent_ce());

        infos.proto_push(next_proto, Some((ce.clone(), ce_dir)));


        let mut ce_locked = ce.lock().unwrap();
        let cd = ce_locked.get_or_insert_with(|| Box::new(ConntrackTcp::new(next_proto, infos)) as ConntrackData)
                    .downcast_mut::<ConntrackTcp>().unwrap();

        cd.process_packet(ce_dir, seq, ack, flags, pkt);


        let timeout = match cd.get_state() {
            TcpState::New => TCP_TIMEOUT_SYN_RECV,
            TcpState::SynRecv => TCP_TIMEOUT_SYN_RECV,
            TcpState::SynSent => TCP_TIMEOUT_SYN_SENT,
            TcpState::Established => TCP_TIMEOUT_ESTABLISHED,
            TcpState::HalfClosedFwd => TCP_TIMEOUT_HALF_CLOSED,
            TcpState::HalfClosedRev => TCP_TIMEOUT_HALF_CLOSED,
            TcpState::Closed => TCP_TIMEOUT_CLOSED,
        };

        ce_locked.set_timeout(Duration::from_secs(timeout), pkt.ts);


        ProtoParseResult::Stop

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
    use crate::packet::{PktTime, PktDataBorrowed};
    use crate::param::tests::param_assert_eq;
    use crate::proto::ProtoTest;
    use tracing_test::traced_test;

    fn tcp_parse_test(data: &[u8]) -> ProtoParseResult {
        let pkt_data = PktDataBorrowed::new(&data);
        let mut pkt = Packet::new(PktTime::from_nanos(0), pkt_data);
        let mut infos = PktInfoStack::new(Protocols::Tcp);

        ProtoTcp::process(&mut pkt, &mut infos)

    }

    #[test]
    fn tcp_parse_basic() {
        let data = vec![ 0x00, 0x01, 0x00, 0x02, 0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb, 0x50, 0x00, 0x00, 0x10, 0xff, 0xff, 0x00, 0x00, 0xcc ];
        let pkt_data = PktDataBorrowed::new(&data);
        let mut pkt = Packet::new(PktTime::from_nanos(0), pkt_data);
        let mut infos = PktInfoStack::new(Protocols::Tcp);

        let ret = ProtoTcp::process(&mut pkt, &mut infos);
        assert_eq!(ret, ProtoParseResult::Stop);

        let info = infos.iter().next().unwrap();
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

        ProtoTest::add_expectation(&[ 0xdd ] , PktTime::from_nanos(0));

        let pkt_data = PktDataBorrowed::new(&data);
        let mut pkt = Packet::new(PktTime::from_nanos(0), pkt_data);
        let mut infos = PktInfoStack::new(Protocols::Tcp);

        let ret = ProtoTcp::process(&mut pkt, &mut infos);
        assert_eq!(ret, ProtoParseResult::Stop);
        assert_eq!(infos.proto_last().proto, Protocols::Test);

        ProtoTest::process(&mut pkt, &mut infos);
        ProtoTest::assert_empty();

    }

    #[test]
    #[traced_test]
    fn tcp_packet_invalid_flags() {
        let data = vec![ 0x00, 0x01, 0x00, 0x02, 0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb, 0x50, 0x07, 0x00, 0x10, 0xff, 0xff, 0x00, 0x00, 0xcc ];
        let ret = tcp_parse_test(&data);
        assert_eq!(ret, ProtoParseResult::Invalid);
        assert!(logs_contain("More than one SYN/FIN/RST at the same time"));
    }

}
