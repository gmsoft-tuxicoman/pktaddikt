use crate::base::{Parser, ParseErr};
use crate::proto::{ProtoPktProcessor, Protocols, ProtoInfo};
use crate::conntrack::{ConntrackTable, ConntrackKeyBidir, ConntrackDirection};
use crate::packet::{Packet, PktInfoStack, PktTime};
use crate::config::Config;
use crate::event::{Event, EventPayload, EventKind};
use crate::messagebus::MessageBus;
use crate::base::UniqueId;
use crate::expectation::ExpectationTable;

use std::time::Duration;
use std::net::IpAddr;
use serde::{Serialize, Deserialize};


#[derive(Debug, PartialEq)]
pub struct ProtoUdpInfo {
    pub sport: u16,
    pub dport: u16,
}


type ConntrackKeyUdp = ConntrackKeyBidir<u16>;

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UdpConfig {
    pub conntrack_size: usize,
    pub conntrack_timeout: u64,
}

impl Default for UdpConfig {
    fn default() -> Self {
        Self {
            conntrack_size: 32768,
            conntrack_timeout: 120,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct NetUdpConnectionStart {
    pub conn_id: UniqueId,
    pub src_host: Option<IpAddr>,
    pub dst_host: Option<IpAddr>,
    pub src_port: u16,
    pub dst_port: u16,
}

#[derive(Debug, Serialize)]
pub struct NetUdpConnectionEnd {
    pub conn_id: UniqueId,
    pub duration: PktTime,
    pub src_host: Option<IpAddr>,
    pub dst_host: Option<IpAddr>,
    pub src_port: u16,
    pub dst_port: u16,
    pub fwd_bytes: u64,
    pub rev_bytes: u64,
    pub fwd_ip_bytes: u64,
    pub rev_ip_bytes: u64,
    pub fwd_pkts: u64,
    pub rev_pkts: u64,
}


struct ConntrackUdpDir {
    tot_bytes: u64,
    tot_ip_bytes: u64,
    tot_pkts: u64,
}

struct ConntrackUdp {
    forward: ConntrackUdpDir,
    reverse: ConntrackUdpDir,
    conn_id: UniqueId,
    start_ts: PktTime,
    last_ts: PktTime,
    src_port: u16,
    dst_port: u16,
    src_host: Option<IpAddr>,
    dst_host: Option<IpAddr>,
    next_proto: Protocols,
}

pub struct ProtoUdp {
    ct: ConntrackTable<ConntrackKeyUdp>,
    et: &'static ExpectationTable,
}


impl ProtoUdp {

    fn next_proto(port: u16) -> Protocols {
        match port {
            53 => Protocols::Dns,
            67 | 68 => Protocols::Dhcp,
            111 | 2049 => Protocols::SunRpc,
            _ => Protocols::None
        }
    }
}

impl ProtoPktProcessor for ProtoUdp {

    fn new() -> Self {
        let cfg = Config::get();
        Self {
            ct: ConntrackTable::new(cfg.proto.udp.conntrack_size),
            et: ExpectationTable::init(Protocols::Udp),
        }
    }

    fn process(&mut self, pkt: &mut Packet, infos: &mut PktInfoStack) -> Result<(), ParseErr> {

        let sport: u16 = pkt.read_u16_be()?;
        let dport: u16 = pkt.read_u16_be()?;
        let tot_len: u16 = pkt.read_u16_be()?;
        pkt.skip_u16()?; // checksum


        let data_len = (tot_len as u32) - 8;
        pkt.has_len(data_len)?;

        if data_len < pkt.remaining_len() {
            // Shrink remaining payload to advertised size
            pkt.shrink(data_len);
        }

        let info = infos.proto_last_mut();

        let proto_info = ProtoUdpInfo {
            sport,
            dport,
        };

        info.proto_info = Some(ProtoInfo::Udp(proto_info));
        info.tot_len = tot_len as u32;
        info.data_len = data_len;


        let ct_key = ConntrackKeyUdp { a: sport, b: dport };
        let (ce, ce_dir) = self.ct.get(ct_key, info.parent_ce());

        let mut ce_locked = ce.lock().unwrap();

        let cfg = Config::get();
        ce_locked.set_timeout(Duration::from_secs(cfg.proto.udp.conntrack_timeout), pkt.timestamp());

        let ts = pkt.timestamp();
        let cd = ce_locked.get_or_insert_with(||
            {
                let conn_id = UniqueId::new(ts);
                let ip_info = infos.proto_from_last(1).map(|p| p.proto_info.as_ref().unwrap());
                let (src_host, dst_host) = match ip_info {
                    Some(ProtoInfo::Ipv4(v4)) => (Some(IpAddr::V4(v4.src)), Some(IpAddr::V4(v4.dst))),
                    Some(ProtoInfo::Ipv6(v6)) => (Some(IpAddr::V6(v6.src)), Some(IpAddr::V6(v6.dst))),
                    _ => (None, None),
                };

                let next_proto = match self.et.check(infos) {
                    Some(p) => p,
                    None => match ProtoUdp::next_proto(dport) {
                        Protocols::None => ProtoUdp::next_proto(sport),
                        proto => proto,
                    },
                };

                let cd = Box::new(ConntrackUdp {
                    forward: ConntrackUdpDir {
                        tot_bytes: 0,
                        tot_ip_bytes: 0,
                        tot_pkts: 0,
                    },
                    reverse: ConntrackUdpDir {
                        tot_bytes: 0,
                        tot_ip_bytes: 0,
                        tot_pkts: 0,
                    },
                    conn_id: conn_id.clone(),
                    start_ts: ts,
                    last_ts: ts,
                    src_port: sport,
                    dst_port: dport,
                    src_host,
                    dst_host,
                    next_proto: next_proto,
                    }
                );

                if MessageBus::event_has_subscribers(EventKind::NetUdpConnectionStart) {

                    let evt_pload = NetUdpConnectionStart {
                        conn_id: conn_id.clone(),
                        src_port: sport,
                        dst_port: dport,
                        src_host: cd.src_host,
                        dst_host: cd.dst_host,
                    };
                    let evt = Event::new(cd.start_ts, EventPayload::NetUdpConnectionStart(evt_pload));
                    MessageBus::publish_event(evt);
                }
                cd

            }

        ).downcast_mut::<ConntrackUdp>().unwrap();

        infos.set_conn_id(cd.conn_id.clone());


        infos.proto_push(cd.next_proto, Some((ce.clone(), ce_dir)));


        let ip_len = infos.proto_from_last(2).map(|p| p.tot_len).unwrap_or(0);


        match ce_dir {
            ConntrackDirection::Forward => {
                cd.forward.tot_bytes += pkt.remaining_len() as u64;
                cd.forward.tot_pkts += 1;
                cd.forward.tot_ip_bytes += ip_len as u64;
            },
            ConntrackDirection::Reverse => {
                cd.reverse.tot_bytes += pkt.remaining_len() as u64;
                cd.reverse.tot_pkts += 1;
                cd.reverse.tot_ip_bytes += ip_len as u64;
            },

        }

        Ok(())

    }
}


impl Drop for ConntrackUdp {

    fn drop(&mut self) {
        if ! (MessageBus::event_has_subscribers(EventKind::NetUdpConnectionEnd)) {
            return;
        }

        let evt_pload = NetUdpConnectionEnd {
            conn_id: self.conn_id.clone(),
            src_port: self.src_port,
            dst_port: self.dst_port,
            src_host: self.src_host,
            dst_host: self.dst_host,
            duration: self.last_ts - self.start_ts,
            fwd_bytes: self.forward.tot_bytes,
            rev_bytes: self.reverse.tot_bytes,
            fwd_ip_bytes: self.forward.tot_ip_bytes,
            rev_ip_bytes: self.reverse.tot_ip_bytes,
            fwd_pkts: self.forward.tot_pkts,
            rev_pkts: self.reverse.tot_pkts,
        };

        let evt = Event::new(self.last_ts, EventPayload::NetUdpConnectionEnd(evt_pload));
        MessageBus::publish_event(evt);
    }

}


#[cfg(test)]
mod test {

    use super::*;
    use crate::proto::ipv4::ProtoIpv4Info;
    use std::net::Ipv4Addr;

    #[test]
    fn udp_parse_basic() {
        let data = vec![ 0xde, 0xad, 0xbe, 0xef, 0x00, 0x09, 0xff, 0xff, 0xa ];
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
	infos.proto_push(Protocols::Udp, None);


        let ret = ProtoUdp::new().process(&mut pkt, &mut infos);
        assert_eq!(ret, Ok(()));

        let check = infos.proto_from_last(1).unwrap();

        let expected = ProtoInfo::Udp(ProtoUdpInfo {
            sport: 57005,
            dport: 48879,
        });

        assert_eq!(check.proto_info, Some(expected));

    }

}
