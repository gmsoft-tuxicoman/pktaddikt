use crate::proto::{ProtoPktProcessor, ProtoParseResult, Protocols};
use crate::param::{Param, ParamValue};
use crate::conntrack::{ConntrackTable, ConntrackKeyBidir, ConntrackDirection};
use crate::packet::{Packet, PktInfoStack, PktTime};
use crate::config::ConfigRef;
use crate::event::{Event, EventPayload, EventId, EventKind, EventBus};

use std::time::Duration;
use serde::{Serialize, Deserialize};

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
    pub conn_id: EventId,
    pub src_host: Option<ParamValue>,
    pub dst_host: Option<ParamValue>,
    pub src_port: u16,
    pub dst_port: u16,
}

#[derive(Debug, Serialize)]
pub struct NetUdpConnectionEnd {
    pub conn_id: EventId,
    pub duration: PktTime,
    pub src_host: Option<ParamValue>,
    pub dst_host: Option<ParamValue>,
    pub src_port: u16,
    pub dst_port: u16,
    pub fwd_bytes: usize,
    pub rev_bytes: usize,
    pub fwd_ip_bytes: usize,
    pub rev_ip_bytes: usize,
    pub fwd_pkts: usize,
    pub rev_pkts: usize,
}


struct ConntrackUdpDir {
    tot_bytes: usize,
    tot_ip_bytes: usize,
    tot_pkts: usize,
}

struct ConntrackUdp {
    forward: ConntrackUdpDir,
    reverse: ConntrackUdpDir,
    conn_id: EventId,
    start_ts: PktTime,
    last_ts: PktTime,
    src_port: u16,
    dst_port: u16,
    src_host: Option<ParamValue>,
    dst_host: Option<ParamValue>,
}

pub struct ProtoUdp {
    cfg: ConfigRef,
    ct: ConntrackTable<ConntrackKeyUdp>,
}


impl ProtoUdp {

    pub fn new(cfg: ConfigRef) -> Self {
        Self {
            cfg: cfg.clone(),
            ct: ConntrackTable::new(cfg.proto.udp.conntrack_size),
        }
    }
}

impl ProtoPktProcessor for ProtoUdp {

    fn process(&mut self, pkt: &mut Packet, infos: &mut PktInfoStack) -> ProtoParseResult {

        let plen = pkt.remaining_len();
        if plen < 9 { // length smaller than UDP header and 1 byte of data
            return ProtoParseResult::Invalid;
        }

        let hdr = pkt.read_bytes(8).unwrap();

        let sport : u16 = (hdr[0] as u16) << 8 | (hdr[1] as u16);
        let dport : u16 = (hdr[2] as u16) << 8 | (hdr[3] as u16);
        let len : u16 = (hdr[4] as u16) << 8 | (hdr[5] as u16);


        let plen = (len as usize) - 8;
        if plen > pkt.remaining_len() {
            // Stop processing if payload is not complete
            return ProtoParseResult::Stop;
        } else if plen < pkt.remaining_len() {
            // Shrink remaining payload to advertised size
            pkt.shrink_remaining(plen);
        }

        let info = infos.proto_last_mut();
        info.field_push(Param { name: "sport", value: Some(ParamValue::U16(sport)) });
        info.field_push(Param { name: "dport", value: Some(ParamValue::U16(dport)) });


        let ct_key = ConntrackKeyUdp { a: sport, b: dport };
        let (ce, dir) = self.ct.get(ct_key, info.parent_ce());

        // WIP
        infos.proto_push(Protocols::None, None);

        let mut ce_locked = ce.lock().unwrap();

        match ce_locked.has_children() {
            true => ce_locked.set_timeout(Duration::ZERO, pkt.ts),
            false => ce_locked.set_timeout(Duration::from_secs(self.cfg.proto.udp.conntrack_timeout), pkt.ts)
        }

        if ! (EventBus::has_subscribers(EventKind::NetUdpConnectionStart)
                || EventBus::has_subscribers(EventKind::NetUdpConnectionEnd))
        {
            // Don't bother creating conntrack data if there is no subscriber
            return ProtoParseResult::Ok;
        }

        let cd = ce_locked.get_or_insert_with(||
            {
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
                    conn_id: EventId::new(pkt.ts),
                    start_ts: pkt.ts,
                    last_ts: PktTime::from_micros(0),
                    src_port: sport,
                    dst_port: dport,
                    src_host: infos.proto_from_last(3).and_then(|p| p.get_field(0).value),
                    dst_host: infos.proto_from_last(3).and_then(|p| p.get_field(1).value),
                    }
                );

                let evt_pload = NetUdpConnectionStart {
                    conn_id: cd.conn_id.clone(),
                    src_port: sport,
                    dst_port: dport,
                    src_host: cd.src_host,
                    dst_host: cd.dst_host,
                };
                let evt = Event::new(cd.start_ts, EventPayload::NetUdpConnectionStart(evt_pload));
                evt.send();
                cd

            }

        ).downcast_mut::<ConntrackUdp>().unwrap();

        cd.last_ts = pkt.ts;

        let ip_len = infos.proto_from_last(3).and_then(|p| p.get_field(2).value);


        match dir {
            ConntrackDirection::Forward => {
                cd.forward.tot_bytes += pkt.remaining_len();
                cd.forward.tot_pkts += 1;
                cd.forward.tot_ip_bytes += ip_len.unwrap_or(ParamValue::U32(0)).get_u32() as usize;
            },
            ConntrackDirection::Reverse => {
                cd.reverse.tot_bytes += pkt.remaining_len();
                cd.reverse.tot_pkts += 1;
                cd.reverse.tot_ip_bytes += ip_len.unwrap_or(ParamValue::U32(0)).get_u32() as usize;
            },

        }

        ProtoParseResult::Ok

    }
}


impl Drop for ConntrackUdp {

    fn drop(&mut self) {
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
        evt.send();
    }

}
