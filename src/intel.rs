
use crate::intel::hostdb::{HostDb, HostDbConfig};
use crate::intel::activity::{Activity, ActivityConfig, ActivityRole};
use crate::proto::Protocols;
use crate::conntrack::ConntrackFlowCounters;
use crate::proto::ethernet::EthernetMac;
use crate::base::UniqueId;
use crate::messagebus::{MessageBus, MessageTxChannel, MessageRxChannel, Message};
use crate::event::{EventKind, EventPayload};
use crate::packet::{PktLinkType, PktTime};

use serde::Deserialize;
use ipnet::IpNet;

use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use crossbeam_channel;

pub mod hostdb;
pub mod activity;

static INTEL: OnceLock<Intel> = OnceLock::new();

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IntelConfig {

    /// Networks to treat as local (CIDR, IPv4 and IPv6). An address in these
    /// seen in a connection becomes a host even without ARP; other addresses
    /// never resolve to a host.
    /// Defaults to the RFC 1918 private ranges plus the IPv6 unique local range.
    pub local_nets: Vec<IpNet>,
    /// Host DB configuration
    #[serde(default)]
    pub hostdb: Option<HostDbConfig>,
    /// Per-host activity configuration
    #[serde(default)]
    pub activity: Option<ActivityConfig>,
}

impl Default for IntelConfig {
    fn default() -> Self {
        Self {
            local_nets: [
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "fd00::/8",
            ]
            .iter()
            .map(|n| n.parse().expect("valid default local_nets CIDR"))
            .collect(),
            hostdb: None,
            activity: None,
        }
    }
}

#[derive(Debug)]
pub struct Intel {
    runner: Option<IntelRunner>
}

impl Intel {

    /// Intel only runs if its events are wanted: the outputs subscribed
    /// before it started.
    pub fn new() -> Self {
        Self {
            runner: MessageBus::event_has_subscribers(EventKind::IntelHostActivity).then(IntelRunner::new)
        }
    }

    pub fn init() {
        INTEL.set(Self::new()).unwrap();
    }

    /// Stop the event dispatcher and join its thread.
    pub fn shutdown() {
        if let Some(intel) = INTEL.get() {
            if let Some(runner) = &intel.runner {
                runner.join();
            }
        }
    }

}


/// Owns Intel's event subscription: receives bus messages and dispatches them to
/// the host DB. Mirrors `OutputRunner` (tx + joinable thread).
#[derive(Debug)]
struct IntelRunner {
    tx: MessageTxChannel,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl IntelRunner {

    fn new() -> Self {

        let (tx, rx) = crossbeam_channel::unbounded();

        // Intel — not HostDb — owns the event subscription. Add more kinds here
        // as NDP/etc. learning is wired up.
        for kind in [
            EventKind::NetArpReply,
            EventKind::NetTcpConnectionStart, EventKind::NetTcpConnectionEstablished,
            EventKind::NetTcpFlowUpdate, EventKind::NetTcpConnectionEnd,
            EventKind::NetUdpConnectionStart, EventKind::NetUdpFlowUpdate, EventKind::NetUdpConnectionEnd,
        ] {
            MessageBus::event_subscribe_kind(kind, &tx);
        }

        let intel_cfg = &crate::config::Config::get().intel;
        let activity = Activity::new(&intel_cfg.activity.clone().unwrap_or_default());

        let hostdb_cfg = intel_cfg.hostdb.clone().unwrap_or_default();
        let sweep_interval = Duration::from_secs(hostdb_cfg.sweep_interval);
        let db = HostDb::new(&hostdb_cfg, &intel_cfg.local_nets);

        let thread = std::thread::spawn(move || {
            Self::run(db, activity, rx, sweep_interval);
        });

        Self { tx, thread: Mutex::new(Some(thread)) }

    }

    fn run(mut db: HostDb, mut activity: Activity, rx: MessageRxChannel, sweep_interval: Duration) {

        // Eviction is O(hosts), so sweep for idle hosts at most once per
        // `sweep_interval` of capture time rather than on every event.
        let sweep_interval = PktTime::from(sweep_interval);
        let mut next_sweep: Option<PktTime> = None;

        for msg in rx {
            match msg {
                Message::Shutdown => break,
                Message::Event(evt) => {
                    // Before dispatch: the event belongs to the bucket holding its time.
                    activity.tick(evt.ts);
                    IntelRunner::dispatch(&mut db, &mut activity, &evt);

                    if next_sweep.map_or(true, |due| evt.ts >= due) {
                        db.evict_idle(evt.ts);
                        next_sweep = Some(evt.ts + sweep_interval);
                    }
                }
                _ => {}
            }
        }

        activity.flush();

    }

    fn dispatch(db: &mut HostDb, activity: &mut Activity, evt: &crate::event::EventRef) {

        match &evt.payload {
            EventPayload::NetArpReply(arp) => {
                let merge = db.evt_arp_reply(arp, evt.ts);
                if let Some(m) = merge {
                    activity.merge_host(m.from, m.to);
                }
            }
            EventPayload::NetTcpConnectionStart(p) => {
                IntelRunner::conn_start(db, activity, evt.ts, &p.conn_id, Protocols::Tcp, p.client_addr, p.client_mac, p.server_addr, None, p.server_port);
            }
            EventPayload::NetUdpConnectionStart(p) => {
                IntelRunner::conn_start(db, activity, evt.ts, &p.conn_id, Protocols::Udp, p.client_addr, p.client_mac, p.server_addr, p.link_pkt_type, p.server_port);
            }
            EventPayload::NetTcpConnectionEstablished(p) => {
                activity.conn_established(&p.conn_id);
            }
            EventPayload::NetTcpFlowUpdate(update) | EventPayload::NetUdpFlowUpdate(update) => {
                activity.conn_flow(update);
            }
            EventPayload::NetTcpConnectionEnd(p) => {
                let totals = ConntrackFlowCounters { fwd_bytes: p.fwd_bytes, rev_bytes: p.rev_bytes, fwd_pkts: p.fwd_pkts, rev_pkts: p.rev_pkts };
                activity.conn_end(&p.conn_id, &totals);
            }
            EventPayload::NetUdpConnectionEnd(p) => {
                let totals = ConntrackFlowCounters { fwd_bytes: p.fwd_bytes, rev_bytes: p.rev_bytes, fwd_pkts: p.fwd_pkts, rev_pkts: p.rev_pkts };
                activity.conn_end(&p.conn_id, &totals);
            }
            _ => {}
        }

    }

    /// Resolve the endpoints of a new connection to hosts, then record it.
    /// `client_mac` and `link_pkt_type` come from the client's first packet;
    /// TCP has no `link_pkt_type`, it's always unicast. A broadcast or
    /// multicast destination isn't a host at all.
    fn conn_start(db: &mut HostDb, activity: &mut Activity, ts: PktTime, conn_id: &UniqueId, proto: Protocols,
        client_addr: IpAddr, client_mac: Option<EthernetMac>,
        server_addr: IpAddr, link_pkt_type: Option<PktLinkType>, server_port: u16) {

        let role = ActivityRole::of_client(&server_addr, link_pkt_type);
        let client = db.host_for_ip(&client_addr, client_mac, ts);
        let server = match role {
            ActivityRole::Client => db.host_for_ip(&server_addr, None, ts),
            _ => None,
        };
        activity.conn_start(conn_id, proto, role, client_addr, server_addr, server_port, client, server);

    }

    fn join(&self) {

        self.tx.send(Message::Shutdown).ok();

        if let Some(thread) = self.thread.lock().unwrap().take() {
            thread.join().unwrap();
        }

    }

}
