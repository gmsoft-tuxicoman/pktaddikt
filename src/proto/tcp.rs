mod seq;
pub mod conntrack;

use crate::proto::{ProtoPktProcessor, ProtoParseResult, Protocols, ProtoInfo};
use crate::conntrack::{ConntrackTable, ConntrackKeyBidir, ConntrackData};
use crate::packet::{Packet, PktInfoStack};
use crate::proto::tcp::conntrack::{ConntrackTcp, TcpState};
use crate::config::ConfigRef;
use crate::event::EventId;

use std::time::Duration;
use tracing::trace;
use serde::Deserialize;


#[derive(Debug, PartialEq)]
pub struct ProtoTcpInfo {
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub window: u16,
    pub flags: u8,
}


#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TcpConfig {

    pub timeout_syn_recv: u64,
    pub timeout_syn_sent: u64,
    pub timeout_established: u64,
    pub timeout_half_closed: u64,
    pub timeout_closed: u64,
    pub conntrack_size: usize,
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            timeout_syn_recv: 60,
            timeout_syn_sent: 180,
            timeout_established: 1800,
            timeout_half_closed: 120,
            timeout_closed: 30,
            conntrack_size: 32768,
        }
    }
}

type ConntrackKeyTcp = ConntrackKeyBidir<u16>;

const TCP_TH_FIN: u8 = 0x1;
const TCP_TH_SYN: u8 = 0x2;
const TCP_TH_RST: u8 = 0x4;
const TCP_TH_ACK: u8 = 0x10;

pub struct ProtoTcp {
    cfg: ConfigRef,
    ct: ConntrackTable<ConntrackKeyTcp>,
}

impl ProtoTcp {
    fn next_proto(port: u16) -> Protocols {
        match port {
            0 => Protocols::Test,
            53 => Protocols::Dns,
            80 => Protocols::Http,
            _ => Protocols::None
        }
    }

}

impl ProtoTcp {
    pub fn new(cfg: ConfigRef) -> Self {
        Self {
            cfg: cfg.clone(),
            ct: ConntrackTable::new(cfg.proto.tcp.conntrack_size),
        }
    }
}

impl ProtoPktProcessor for ProtoTcp {

    fn process(&mut self, pkt: &mut Packet, infos: &mut PktInfoStack) -> ProtoParseResult {

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

        let proto_info = ProtoTcpInfo {
            sport,
            dport,
            seq,
            ack,
            window,
            flags,
        };
        info.proto_info = Some(ProtoInfo::Tcp(proto_info));

        // WIP, needs to be improved
        let next_proto = match ProtoTcp::next_proto(dport) {
            Protocols::None => ProtoTcp::next_proto(sport),
            Protocols::Test => { return ProtoParseResult::Stop; },
            proto => proto
        };

        let ct_key = ConntrackKeyTcp { a: sport, b: dport };
        let (ce, ce_dir) = self.ct.get(ct_key, info.parent_ce());

        infos.proto_push(next_proto, Some((ce.clone(), ce_dir)));


        let mut ce_locked = ce.lock().unwrap();
        let cd = ce_locked.get_or_insert_with(|| {
            let conn_id = EventId::new(pkt.ts);
            infos.set_conn_id(conn_id);
            Box::new(ConntrackTcp::new(next_proto, infos)) as ConntrackData })

            .downcast_mut::<ConntrackTcp>().unwrap();


        let ip_len = infos.proto_from_last(2).map(|p| p.tot_len).unwrap_or(0);
        cd.process_packet(ce_dir, seq, ack, flags, pkt, ip_len);

        infos.set_conn_id(cd.get_conn_id().clone());

        let timeout = match cd.get_state() {
            TcpState::New => self.cfg.proto.tcp.timeout_syn_recv,
            TcpState::SynRecv => self.cfg.proto.tcp.timeout_syn_recv,
            TcpState::SynSent => self.cfg.proto.tcp.timeout_syn_sent,
            TcpState::Established => self.cfg.proto.tcp.timeout_established,
            TcpState::HalfClosedFwd => self.cfg.proto.tcp.timeout_half_closed,
            TcpState::HalfClosedRev => self.cfg.proto.tcp.timeout_half_closed,
            TcpState::Closed => self.cfg.proto.tcp.timeout_closed,
        };

        ce_locked.set_timeout(Duration::from_secs(timeout), pkt.ts);


        ProtoParseResult::Stop

    }
}

impl Drop for ProtoTcp {

    fn drop(&mut self) {
        self.ct.purge();
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::packet::{PktTime, PktDataBorrowed};
    use crate::proto::ProtoTest;
    use crate::config::Config;
    use crate::proto::ipv4::ProtoIpv4Info;
    use tracing_test::traced_test;
    use std::net::Ipv4Addr;

    fn tcp_parse_test(proto: &mut ProtoTcp, data: &[u8]) -> ProtoParseResult {
        let pkt_data = PktDataBorrowed::new(&data);
        let mut pkt = Packet::new(PktTime::from_micros(0), pkt_data);
        let mut infos = PktInfoStack::new(Protocols::Tcp);

        proto.process(&mut pkt, &mut infos)

    }

    #[test]
    fn tcp_parse_basic() {
        let data = vec![ 0x00, 0x01, 0x00, 0x02, 0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb, 0x50, 0x00, 0x00, 0x10, 0xff, 0xff, 0x00, 0x00, 0xcc ];
        let pkt_data = PktDataBorrowed::new(&data);
        let mut pkt = Packet::new(PktTime::from_micros(0), pkt_data);
        let mut infos = PktInfoStack::new(Protocols::Ipv4);
        let info = infos.proto_last_mut();

        info.proto_info = Some(ProtoInfo::Ipv4(ProtoIpv4Info {
            src: Ipv4Addr::new(10, 0, 0, 1),
            dst: Ipv4Addr::new(10, 0, 0, 2),
            id: 0,
            hdr_len: 0,
            ttl: 0,
            proto: 17,
        }));

        infos.proto_push(Protocols::Tcp, None);

        let ret = ProtoTcp::new(Config::new()).process(&mut pkt, &mut infos);
        assert_eq!(ret, ProtoParseResult::Stop);

        let check = infos.proto_from_last(1).unwrap();

        let expected = ProtoInfo::Tcp(ProtoTcpInfo {
            sport: 1,
            dport: 2,
            seq: 2863311530,
            ack: 3149642683,
            flags: 0,
            window: 16,
        });

        assert_eq!(check.proto_info, Some(expected));

    }

    #[test]
    #[traced_test]
    fn tcp_packet_too_short() {
        let data = vec![ 0x00, 0x01, 0x00, 0x02, 0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb, 0x50, 0x00, 0x00, 0x10, 0xff, 0xff, 0x00 ];
        let ret = tcp_parse_test(&mut ProtoTcp::new(Config::new()), &data);
        assert_eq!(ret, ProtoParseResult::Invalid);
        assert!(logs_contain("Payload length smaller than TCP header"));
    }

    #[test]
    #[traced_test]
    fn tcp_header_too_small() {
        let data = vec![ 0x00, 0x01, 0x00, 0x02, 0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb, 0x40, 0x00, 0x00, 0x10, 0xff, 0xff, 0x00, 0x00, 0xcc ];
        let ret = tcp_parse_test(&mut ProtoTcp::new(Config::new()), &data);
        assert_eq!(ret, ProtoParseResult::Invalid);
        assert!(logs_contain("Header length too small"));
    }

    #[test]
    #[traced_test]
    fn tcp_header_too_big() {
        let data = vec![ 0x00, 0x01, 0x00, 0x02, 0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb, 0x70, 0x00, 0x00, 0x10, 0xff, 0xff, 0x00, 0x00, 0xcc ];
        let ret = tcp_parse_test(&mut ProtoTcp::new(Config::new()), &data);
        assert_eq!(ret, ProtoParseResult::Invalid);
        assert!(logs_contain("Header length bigger than payload size"));
    }

    #[test]
    #[traced_test]
    fn tcp_skip_options() {
        let data = vec![ 0x00, 0x01, 0x00, 0x00, 0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb, 0x70, 0x00, 0x00, 0x10, 0xff, 0xff, 0x00, 0x00, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xdd ];


        let mut test = ProtoTest::new();
        test.add_expectation(&[ 0xdd ] , PktTime::from_micros(0));

        let pkt_data = PktDataBorrowed::new(&data);
        let mut pkt = Packet::new(PktTime::from_micros(0), pkt_data);
        let mut infos = PktInfoStack::new(Protocols::Tcp);

        let ret = ProtoTcp::new(Config::new()).process(&mut pkt, &mut infos);
        assert_eq!(ret, ProtoParseResult::Stop);

        test.process(&mut pkt, &mut infos);

    }

    #[test]
    #[traced_test]
    fn tcp_packet_invalid_flags() {
        let data = vec![ 0x00, 0x01, 0x00, 0x02, 0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb, 0x50, 0x07, 0x00, 0x10, 0xff, 0xff, 0x00, 0x00, 0xcc ];
        let ret = tcp_parse_test(&mut ProtoTcp::new(Config::new()), &data);
        assert_eq!(ret, ProtoParseResult::Invalid);
        assert!(logs_contain("More than one SYN/FIN/RST at the same time"));
    }

}
