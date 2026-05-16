mod seq;
pub mod conntrack;

use crate::base::{Parser, ParseErr};
use crate::proto::{ProtoPktProcessor, Protocols, ProtoInfo};
use crate::conntrack::{ConntrackTable, ConntrackKeyBidir, ConntrackData};
use crate::packet::{Packet, PktInfoStack};
use crate::proto::tcp::conntrack::{ConntrackTcp, TcpState};
use crate::config::Config;
use crate::event::EventId;

use std::time::Duration;
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
    ct: ConntrackTable<ConntrackKeyTcp>,
}

impl ProtoTcp {
    fn next_proto(port: u16) -> Protocols {
        match port {
            0 => Protocols::Test,
            53 => Protocols::Dns,
            80 => Protocols::Http,
            443 => Protocols::Tls,
            2049 => Protocols::SunRpc,
            _ => Protocols::None
        }
    }

}

impl ProtoPktProcessor for ProtoTcp {

    fn new() -> Self {
        let cfg = Config::get();
        Self {
            ct: ConntrackTable::new(cfg.proto.tcp.conntrack_size),
        }
    }

    fn process(&mut self, pkt: &mut Packet, infos: &mut PktInfoStack) -> Result<(), ParseErr> {

        let sport = pkt.read_u16_be()?;
        let dport = pkt.read_u16_be()?;
        let seq = pkt.read_u32_be()?;
        let ack = pkt.read_u32_be()?;
        let hdr_len = ((pkt.read_u8()? & 0xf0) >> 2) as usize;
        let flags = pkt.read_u8()?;
        let window = pkt.read_u16_be()?;
        pkt.skip_u32()?; // cksum. urg ptr

        // Check if flags are somewhat valid
        let f_syn_fin_rst = flags & (TCP_TH_SYN | TCP_TH_FIN | TCP_TH_RST);
        if f_syn_fin_rst.count_ones() > 1 {
            return Err(ParseErr::Invalid("More than one SYN/FIN/RST at the same time"));
        }

        if hdr_len < 20 {
            // Header length too small
            return Err(ParseErr::Invalid("Header length too small"));
        }

        if (hdr_len - 20) > pkt.remaining_len() {
            // Header length bigger than payload size
            return Err(ParseErr::Invalid("Header length bigger than payload size"));
        }

        if hdr_len > 20 {
            // Skip options and padding
            pkt.skip(hdr_len - 20)?;
        }

        if ((flags & TCP_TH_RST) != 0) && pkt.remaining_len() > 0 {
            // RFC 1122 4.2.2.12 : RST may contain the data that caused the packet to be sent,
            // discard it
            pkt.shrink(0);
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
            Protocols::Test => return Err(ParseErr::Stop),
            proto => proto
        };

        let ct_key = ConntrackKeyTcp { a: sport, b: dport };
        let (ce, ce_dir) = self.ct.get(ct_key, info.parent_ce());

        infos.proto_push(next_proto, Some((ce.clone(), ce_dir)));


        let mut ce_locked = ce.lock().unwrap();
        let cd = ce_locked.get_or_insert_with(|| {
            let conn_id = EventId::new(pkt.timestamp());
            infos.set_conn_id(conn_id);
            Box::new(ConntrackTcp::new(next_proto, infos)) as ConntrackData })

            .downcast_mut::<ConntrackTcp>().unwrap();


        let ip_len = infos.proto_from_last(2).map(|p| p.tot_len).unwrap_or(0);
        cd.process_packet(ce_dir, seq, ack, flags, pkt, ip_len);

        infos.set_conn_id(cd.get_conn_id().clone());

        let cfg = Config::get();
        let timeout = match cd.get_state() {
            TcpState::New => cfg.proto.tcp.timeout_syn_recv,
            TcpState::SynRecv => cfg.proto.tcp.timeout_syn_recv,
            TcpState::SynSent => cfg.proto.tcp.timeout_syn_sent,
            TcpState::Established => cfg.proto.tcp.timeout_established,
            TcpState::HalfClosedFwd => cfg.proto.tcp.timeout_half_closed,
            TcpState::HalfClosedRev => cfg.proto.tcp.timeout_half_closed,
            TcpState::Closed => cfg.proto.tcp.timeout_closed,
        };

        ce_locked.set_timeout(Duration::from_secs(timeout), pkt.timestamp());


        Err(ParseErr::Stop)

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
    use crate::packet::PktTime;
    use crate::proto::ProtoTest;
    use crate::proto::ipv4::ProtoIpv4Info;
    use tracing_test::traced_test;
    use std::net::Ipv4Addr;

    fn tcp_parse_test(proto: &mut ProtoTcp, data: &[u8]) -> Result<(), ParseErr> {
        let mut pkt = Packet::from_slice(PktTime::from_micros(0), data);
        let mut infos = PktInfoStack::new(Protocols::Tcp);

        proto.process(&mut pkt, &mut infos)

    }

    #[test]
    fn tcp_parse_basic() {
        let data = vec![ 0x00, 0x01, 0x00, 0x02, 0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb, 0x50, 0x00, 0x00, 0x10, 0xff, 0xff, 0x00, 0x00, 0xcc ];
        let mut pkt = Packet::from_slice(PktTime::from_micros(0), &data);
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

        let ret = ProtoTcp::new().process(&mut pkt, &mut infos);
        assert_eq!(ret, Err(ParseErr::Stop));

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
    fn tcp_packet_too_short() {
        let data = vec![ 0x00, 0x01, 0x00, 0x02, 0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb, 0x50, 0x00, 0x00, 0x10, 0xff, 0xff, 0x00 ];
        let ret= tcp_parse_test(&mut ProtoTcp::new(), &data);
        assert_eq!(ret, Err(ParseErr::Truncated));
    }

    #[test]
    fn tcp_header_too_small() {
        let data = vec![ 0x00, 0x01, 0x00, 0x02, 0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb, 0x40, 0x00, 0x00, 0x10, 0xff, 0xff, 0x00, 0x00, 0xcc ];
        let Err(ret) = tcp_parse_test(&mut ProtoTcp::new(), &data) else {
            panic!("Unexpected success");
        };
        assert_eq!(ret.invalid_reason(), "Header length too small");
    }

    #[test]
    fn tcp_header_too_big() {
        let data = vec![ 0x00, 0x01, 0x00, 0x02, 0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb, 0x70, 0x00, 0x00, 0x10, 0xff, 0xff, 0x00, 0x00, 0xcc ];
        let Err(ret) = tcp_parse_test(&mut ProtoTcp::new(), &data) else {
            panic!("Unexpected succes");
        };
        assert_eq!(ret.invalid_reason(), "Header length bigger than payload size");
    }

    #[test]
    #[traced_test]
    fn tcp_skip_options() {
        let data = vec![ 0x00, 0x01, 0x00, 0x00, 0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb, 0x70, 0x00, 0x00, 0x10, 0xff, 0xff, 0x00, 0x00, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xdd ];


        let mut test = ProtoTest::new();
        test.add_expectation(&[ 0xdd ] , PktTime::from_micros(0));

        let mut pkt = Packet::from_slice(PktTime::from_micros(0), &data);
        let mut infos = PktInfoStack::new(Protocols::Tcp);

        let ret = ProtoTcp::new().process(&mut pkt, &mut infos);
        assert_eq!(ret, Err(ParseErr::Stop));

        let _ = test.process(&mut pkt, &mut infos);

    }

    #[test]
    #[traced_test]
    fn tcp_packet_invalid_flags() {
        let data = vec![ 0x00, 0x01, 0x00, 0x02, 0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb, 0x50, 0x07, 0x00, 0x10, 0xff, 0xff, 0x00, 0x00, 0xcc ];
        let Err(ret) = tcp_parse_test(&mut ProtoTcp::new(), &data) else {
            panic!("Unexpected success");
        };
        assert_eq!(ret.invalid_reason(), "More than one SYN/FIN/RST at the same time");
    }

}
