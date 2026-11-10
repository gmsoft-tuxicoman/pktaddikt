use crate::base::UniqueId;
use crate::event::{Event, EventPayload};
use crate::messagebus::MessageBus;
use crate::conntrack::{ConntrackFlowCounters, ConntrackFlowUpdate};
use crate::intel::hostdb::HostId;
use crate::packet::{PktLinkType, PktTime};
use crate::proto::Protocols;

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use tracing::trace;


/// Distinct peers remembered per counter before we stop listing them and just
/// flag the overflow. Matches the SmallVec inline capacity so it never spills.
const MAX_PEERS: usize = 8;


#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ActivityConfig {
    /// Width of one aggregation bucket, in seconds.
    pub interval: u64,
}

impl Default for ActivityConfig {
    fn default() -> Self {
        Self {
            interval: 60,
        }
    }
}


/// A host's part in a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ActivityRole {
    /// It opened a unicast connection.
    Client,
    /// It accepted one.
    Server,
    /// It sent to a broadcast or multicast address: nobody answers on the
    /// same flow, so there's no server side.
    Broadcast,
    Multicast,
}

impl ActivityRole {

    /// The client's role for a connection to `addr`, whose first packet was
    /// addressed as `link` at the link layer. A multicast IP or the limited
    /// broadcast settles it alone. A directed broadcast only shows at the link
    /// layer, which is reliable here: broadcast and link-local multicast never
    /// cross a router.
    pub fn of_client(addr: &IpAddr, link: Option<PktLinkType>) -> Self {
        let bcast_ip = matches!(addr, IpAddr::V4(a) if a.is_broadcast());
        match link {
            _ if addr.is_multicast() => ActivityRole::Multicast,
            _ if bcast_ip => ActivityRole::Broadcast,
            Some(PktLinkType::Broadcast) => ActivityRole::Broadcast,
            Some(PktLinkType::Multicast) => ActivityRole::Multicast,
            _ => ActivityRole::Client,
        }
    }
}


/// Counts that don't apply to the counter's role and protocol are `None`,
/// and left out of the event.
#[derive(Debug, Clone, Serialize)]
pub struct ActivityCounter {
    /// Connections that started in this bucket.
    pub new_conns: u32,
    /// Unicast connections that ended in this bucket without a single packet
    /// back: a scanned port, a dead host, or a one-way stream.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unanswered_conns: Option<u32>,
    /// TCP connections that ended in this bucket after an answer but never got
    /// established: SYN then RST, typically.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refused_conns: Option<u32>,
    /// Payload bytes and packets, from the host's point of view.
    pub bytes_out: u64,
    pub bytes_in: u64,
    pub pkts_out: u64,
    pub pkts_in: u64,
    /// Addresses of the other end; resolved to hosts when read, not here.
    pub peers: SmallVec<[IpAddr; MAX_PEERS]>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub peers_overflow: bool,
}

impl ActivityCounter {

    /// Broadcast and multicast are never answered on the same flow, and only
    /// TCP can be refused.
    fn new(role: ActivityRole, proto: Protocols) -> Self {
        let unicast = matches!(role, ActivityRole::Client | ActivityRole::Server);
        Self {
            new_conns: 0,
            unanswered_conns: unicast.then_some(0),
            refused_conns: (unicast && proto == Protocols::Tcp).then_some(0),
            bytes_out: 0,
            bytes_in: 0,
            pkts_out: 0,
            pkts_in: 0,
            peers: SmallVec::new(),
            peers_overflow: false,
        }
    }

    /// A connection of this counter ended: count it as unanswered or refused
    /// where that applies.
    fn add_end(&mut self, unanswered: bool, refused: bool) {
        if let Some(n) = self.unanswered_conns.as_mut() {
            *n += unanswered as u32;
        }
        if let Some(n) = self.refused_conns.as_mut() {
            *n += refused as u32;
        }
    }

    fn add_traffic(&mut self, counters: &ConntrackFlowCounters, role: ActivityRole) {
        let c = counters;
        let (bytes_out, bytes_in, pkts_out, pkts_in) = match role {
            ActivityRole::Server => (c.rev_bytes, c.fwd_bytes, c.rev_pkts, c.fwd_pkts),
            _ => (c.fwd_bytes, c.rev_bytes, c.fwd_pkts, c.rev_pkts),
        };
        self.bytes_out += bytes_out;
        self.bytes_in += bytes_in;
        self.pkts_out += pkts_out;
        self.pkts_in += pkts_in;
    }

    fn merge(&mut self, other: ActivityCounter) {
        self.new_conns += other.new_conns;
        for (n, o) in [(&mut self.unanswered_conns, other.unanswered_conns), (&mut self.refused_conns, other.refused_conns)] {
            if let (Some(n), Some(o)) = (n.as_mut(), o) {
                *n += o;
            }
        }
        self.bytes_out += other.bytes_out;
        self.bytes_in += other.bytes_in;
        self.pkts_out += other.pkts_out;
        self.pkts_in += other.pkts_in;
        self.peers_overflow |= other.peers_overflow;
        for peer in other.peers {
            self.add_peer(peer);
        }
    }

    fn add_peer(&mut self, peer: IpAddr) {
        if !self.peers.contains(&peer) {
            if self.peers.len() < MAX_PEERS {
                self.peers.push(peer);
            } else {
                self.peers_overflow = true;
            }
        }
    }
}


/// Traffic in `totals` that isn't in `base`, an earlier snapshot of them.
fn since(totals: &ConntrackFlowCounters, base: &ConntrackFlowCounters) -> ConntrackFlowCounters {
    ConntrackFlowCounters {
        fwd_bytes: totals.fwd_bytes.saturating_sub(base.fwd_bytes),
        rev_bytes: totals.rev_bytes.saturating_sub(base.rev_bytes),
        fwd_pkts: totals.fwd_pkts.saturating_sub(base.fwd_pkts),
        rev_pkts: totals.rev_pkts.saturating_sub(base.rev_pkts),
    }
}


/// What a counter is for: a host, its part, and the service, keyed on the
/// server port for every role: for `Server` it's the service the host
/// offered, for the others the one it used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ActivityKey {
    host: HostId,
    role: ActivityRole,
    proto: Protocols,
    port: u16,
}

/// A live connection with at least one endpoint being a known host.
#[derive(Debug)]
struct ActivityConn {
    proto: Protocols,
    server_port: u16,
    /// `Client` for unicast, else `Broadcast` / `Multicast` with no server.
    client_role: ActivityRole,
    client_addr: IpAddr,
    server_addr: IpAddr,
    /// Endpoints resolved through the host DB when the connection started.
    client: Option<HostId>,
    server: Option<HostId>,
    /// Totals of the last flow update: what's already accounted.
    reported: ConntrackFlowCounters,
    established: bool,
}


/// `intel.host.activity`: what one host did during one bucket, published
/// once the bucket is over. The event's timestamp is the bucket start.
#[derive(Debug, Serialize)]
pub struct IntelHostActivity {
    pub host: HostId,
    pub services: Vec<IntelHostActivityService>,
}

#[derive(Debug, Serialize)]
pub struct IntelHostActivityService {
    pub role: ActivityRole,
    pub proto: Protocols,
    pub port: u16,
    #[serde(flatten)]
    pub counter: ActivityCounter,
}


/// Per-host connection activity, aggregated in fixed-width time buckets.
///
/// Fed by the conntrack events: a connection is counted when it starts, its
/// traffic accumulates from the flow updates while it's alive, and whatever
/// the updates didn't cover is taken from the end event's totals.
///
/// Only the live bucket is kept: whatever arrives goes in it, and it's
/// published once capture time moves past it. A flow update or an end event
/// can thus count traffic in the bucket after the one it happened in.
#[derive(Debug)]
pub struct Activity {
    /// Bucket width, in µs.
    interval: u64,
    /// Start of the live bucket, in µs.
    start: u64,
    counters: HashMap<ActivityKey, ActivityCounter>,
    conns: HashMap<UniqueId, ActivityConn>,
}

impl Activity {

    pub fn new(cfg: &ActivityConfig) -> Self {
        Self {
            interval: PktTime::from_secs(cfg.interval.max(1)).into(),
            start: 0,
            counters: HashMap::new(),
            conns: HashMap::new(),
        }
    }

    /// Capture time reached `ts`: if that's past the live bucket, publish it
    /// and start the one holding `ts`. Called before recording the event at
    /// `ts`.
    pub fn tick(&mut self, ts: PktTime) {
        let ts: u64 = ts.into();
        if ts < self.start + self.interval {
            return;
        }
        self.publish();
        self.start = ts - ts % self.interval;
    }

    /// Publish the live bucket.
    pub fn flush(&mut self) {
        self.publish();
    }

    fn publish(&mut self) {
        let ts = PktTime::from_micros(self.start);
        for activity in self.take_activities() {
            trace!("activity: bucket {} {:?}", ts, activity);
            MessageBus::publish_event(Event::new(ts, EventPayload::IntelHostActivity(activity)));
        }
    }

    /// Empty the live bucket into one event payload per host, in host order.
    fn take_activities(&mut self) -> Vec<IntelHostActivity> {
        let mut hosts: BTreeMap<HostId, Vec<IntelHostActivityService>> = BTreeMap::new();
        for (k, counter) in self.counters.drain() {
            hosts.entry(k.host).or_default().push(IntelHostActivityService { role: k.role, proto: k.proto, port: k.port, counter });
        }
        hosts.into_iter().map(|(host, services)| IntelHostActivity { host, services }).collect()
    }

    /// Apply `f` to the counter of each known endpoint of `conn`, and record
    /// the other end as its peer.
    fn record(counters: &mut HashMap<ActivityKey, ActivityCounter>, conn: &ActivityConn, f: impl Fn(&mut ActivityCounter, ActivityRole)) {
        for (host, peer, role) in [
            (conn.client, conn.server_addr, conn.client_role),
            (conn.server, conn.client_addr, ActivityRole::Server),
        ] {
            let Some(host) = host else { continue };
            let key = ActivityKey { host, role, proto: conn.proto, port: conn.server_port };
            let c = counters.entry(key).or_insert_with(|| ActivityCounter::new(role, conn.proto));
            c.add_peer(peer);
            f(c, role);
        }
    }

    /// A connection started. `client` / `server` are its endpoints resolved
    /// through the host DB; connections between unknown endpoints are ignored.
    /// `client_role` comes from `ActivityRole::of_client()`; `server` must be
    /// `None` unless it's `Client`.
    pub fn conn_start(&mut self, conn_id: &UniqueId, proto: Protocols,
        client_role: ActivityRole, client_addr: IpAddr, server_addr: IpAddr, server_port: u16,
        client: Option<HostId>, server: Option<HostId>) {

        if client.is_none() && server.is_none() {
            return;
        }

        let conn = ActivityConn {
            proto,
            server_port,
            client_role,
            client_addr,
            server_addr,
            client,
            server,
            reported: ConntrackFlowCounters::default(),
            established: false,
        };
        Self::record(&mut self.counters, &conn, |c, _| c.new_conns += 1);
        self.conns.insert(conn_id.clone(), conn);

    }

    pub fn conn_established(&mut self, conn_id: &UniqueId) {
        if let Some(conn) = self.conns.get_mut(conn_id) {
            conn.established = true;
        }
    }

    /// A connection's running totals: what came since the previous update is
    /// new traffic.
    pub fn conn_flow(&mut self, update: &ConntrackFlowUpdate) {
        let Some(conn) = self.conns.get_mut(&update.conn_id) else { return };
        let traffic = since(&update.totals, &conn.reported);
        conn.reported = update.totals;
        Self::record(&mut self.counters, conn, |c, role| c.add_traffic(&traffic, role));
    }

    /// A connection ended with these `totals`; no flow update follows.
    pub fn conn_end(&mut self, conn_id: &UniqueId, totals: &ConntrackFlowCounters) {

        let Some(conn) = self.conns.remove(conn_id) else { return };

        let rest = since(totals, &conn.reported);
        // Only counted where the counter has them: see `ActivityCounter::new()`.
        let unanswered = totals.rev_pkts == 0;
        let refused = !unanswered && !conn.established;

        Self::record(&mut self.counters, &conn, |c, role| {
            c.add_traffic(&rest, role);
            c.add_end(unanswered, refused);
        });

    }

    /// `from` turned out to be `to`: move what the live bucket has under
    /// `from`, and point live connections at `to` so they keep recording there.
    pub fn merge_host(&mut self, from: HostId, to: HostId) {

        let keys: Vec<ActivityKey> = self.counters.keys().filter(|k| k.host == from).copied().collect();
        for key in keys {
            let c = self.counters.remove(&key).expect("activity: key just listed");
            self.counters.entry(ActivityKey { host: to, ..key })
                .or_insert_with(|| ActivityCounter::new(key.role, key.proto))
                .merge(c);
        }

        for conn in self.conns.values_mut() {
            for host in [&mut conn.client, &mut conn.server] {
                if *host == Some(from) {
                    *host = Some(to);
                }
            }
        }

    }
}


#[cfg(test)]
mod tests {

    use super::*;
    use std::net::Ipv4Addr;

    const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    const SERVER: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));

    fn at(secs: u64) -> PktTime { PktTime::from_secs(secs) }

    fn bytes(fwd: u64, rev: u64) -> ConntrackFlowCounters {
        ConntrackFlowCounters { fwd_bytes: fwd, rev_bytes: rev, fwd_pkts: (fwd > 0) as u64, rev_pkts: (rev > 0) as u64 }
    }

    fn start(a: &mut Activity, proto: Protocols, port: u16, client: Option<HostId>, server: Option<HostId>) -> UniqueId {
        let id = UniqueId::new(at(0));
        a.conn_start(&id, proto, ActivityRole::Client, CLIENT, SERVER, port, client, server);
        id
    }

    fn flow(id: &UniqueId, totals: ConntrackFlowCounters) -> ConntrackFlowUpdate {
        ConntrackFlowUpdate { conn_id: id.clone(), start: at(0), end: at(60), totals }
    }

    /// The live bucket's counter for `host` in `role` on `proto`/`port`.
    fn get(a: &Activity, host: HostId, role: ActivityRole, proto: Protocols, port: u16) -> &ActivityCounter {
        &a.counters[&ActivityKey { host, role, proto, port }]
    }

    #[test]
    fn records_both_sides_from_their_point_of_view() {
        let mut a = Activity::new(&ActivityConfig::default());
        let id = start(&mut a, Protocols::Tcp, 22, Some(1), Some(2));
        a.conn_established(&id);
        a.conn_end(&id, &bytes(100, 1000));

        let c = get(&a, 1, ActivityRole::Client, Protocols::Tcp, 22);
        assert_eq!((c.new_conns, c.refused_conns, c.bytes_out, c.bytes_in), (1, Some(0), 100, 1000));
        assert_eq!((c.pkts_out, c.pkts_in), (1, 1));
        assert_eq!(c.peers.as_slice(), &[SERVER]);

        let c = get(&a, 2, ActivityRole::Server, Protocols::Tcp, 22);
        assert_eq!((c.bytes_out, c.bytes_in), (1000, 100));
        assert_eq!(c.peers.as_slice(), &[CLIENT]);
        assert_eq!(a.counters.len(), 2);
        assert!(a.conns.is_empty());
    }

    #[test]
    fn long_connection_spreads_over_buckets() {
        let mut a = Activity::new(&ActivityConfig { interval: 300 });
        a.tick(at(0));
        let id = start(&mut a, Protocols::Tcp, 443, Some(1), None);
        a.conn_established(&id);
        a.conn_flow(&flow(&id, bytes(10, 10)));
        a.conn_flow(&flow(&id, bytes(15, 15)));
        let c = get(&a, 1, ActivityRole::Client, Protocols::Tcp, 443);
        assert_eq!((c.new_conns, c.bytes_out), (1, 15));
        assert_eq!(c.peers.as_slice(), &[SERVER]);

        // Still active in the next bucket, but not a new connection there.
        a.tick(at(300));
        assert!(a.counters.is_empty());
        a.conn_flow(&flow(&id, bytes(16, 16)));
        // The end carries totals; only what the updates missed is added.
        a.conn_end(&id, &bytes(20, 16));
        let c = get(&a, 1, ActivityRole::Client, Protocols::Tcp, 443);
        assert_eq!((c.new_conns, c.bytes_out, c.bytes_in), (0, 5, 1));
    }

    #[test]
    fn tick_publishes_once_past_the_live_bucket() {
        let mut a = Activity::new(&ActivityConfig::default());
        a.tick(at(0));
        let id = start(&mut a, Protocols::Udp, 53, Some(1), None);

        // Same bucket: kept.
        a.tick(at(30));
        assert_eq!(a.counters.len(), 1);

        // A later one: published, and the bucket holding the time is live.
        a.tick(at(130));
        assert!(a.counters.is_empty());
        assert_eq!(a.start, u64::from(at(120)));

        // What comes next lands in it, whatever its time.
        a.conn_end(&id, &bytes(40, 0));
        let c = get(&a, 1, ActivityRole::Client, Protocols::Udp, 53);
        assert_eq!((c.new_conns, c.unanswered_conns), (0, Some(1)));
    }

    #[test]
    fn unanswered_and_refused() {
        let mut a = Activity::new(&ActivityConfig::default());
        let syn = ConntrackFlowCounters { fwd_pkts: 1, ..Default::default() };
        let syn_rst = ConntrackFlowCounters { fwd_pkts: 1, rev_pkts: 1, ..Default::default() };

        // TCP: SYN then RST.
        let id = start(&mut a, Protocols::Tcp, 443, Some(1), Some(2));
        a.conn_end(&id, &syn_rst);
        // TCP: SYN with no answer.
        let id = start(&mut a, Protocols::Tcp, 443, Some(1), Some(2));
        a.conn_end(&id, &syn);
        // TCP: established.
        let id = start(&mut a, Protocols::Tcp, 443, Some(1), Some(2));
        a.conn_established(&id);
        a.conn_end(&id, &bytes(10, 10));
        // UDP: no packet back, as a one-way stream would.
        let id = start(&mut a, Protocols::Udp, 5004, Some(1), None);
        a.conn_end(&id, &bytes(40, 0));

        let row = |c: &ActivityCounter| (c.new_conns, c.unanswered_conns, c.refused_conns, c.pkts_in);
        // Counted on both sides: the client was refused, the server refused.
        assert_eq!(row(get(&a, 1, ActivityRole::Client, Protocols::Tcp, 443)), (3, Some(1), Some(1), 2));
        assert_eq!(row(get(&a, 2, ActivityRole::Server, Protocols::Tcp, 443)), (3, Some(1), Some(1), 3));
        assert_eq!(row(get(&a, 1, ActivityRole::Client, Protocols::Udp, 5004)), (1, Some(1), None, 0));
    }

    #[test]
    fn merge_host_folds_counters_and_live_conns() {
        let mut a = Activity::new(&ActivityConfig::default());
        // Same service for both hosts, plus a live one on 1.
        let id = start(&mut a, Protocols::Tcp, 443, Some(1), None);
        a.conn_end(&id, &bytes(10, 20));
        let id = start(&mut a, Protocols::Tcp, 443, Some(2), None);
        a.conn_end(&id, &bytes(1, 2));
        let live = start(&mut a, Protocols::Tcp, 443, Some(1), None);

        a.merge_host(1, 2);
        assert_eq!(a.counters.len(), 1);
        let c = get(&a, 2, ActivityRole::Client, Protocols::Tcp, 443);
        assert_eq!((c.new_conns, c.bytes_out, c.bytes_in), (3, 11, 22));
        assert_eq!(c.peers.as_slice(), &[SERVER]);

        // The live connection now ends under host 2.
        a.conn_end(&live, &bytes(5, 0));
        assert_eq!(a.counters.len(), 1);
        assert_eq!(get(&a, 2, ActivityRole::Client, Protocols::Tcp, 443).bytes_out, 16);
    }

    #[test]
    fn peers_overflow() {
        let mut a = Activity::new(&ActivityConfig::default());
        for i in 0..(MAX_PEERS as u8 + 2) {
            let id = UniqueId::new(at(0));
            a.conn_start(&id, Protocols::Tcp, ActivityRole::Client, CLIENT, IpAddr::V4(Ipv4Addr::new(1, 1, 1, i)), 80, Some(1), None);
        }
        let c = get(&a, 1, ActivityRole::Client, Protocols::Tcp, 80);
        assert_eq!(c.peers.len(), MAX_PEERS);
        assert!(c.peers_overflow);
    }

    #[test]
    fn unknown_endpoints_and_connections_are_ignored() {
        let mut a = Activity::new(&ActivityConfig::default());
        let id = start(&mut a, Protocols::Tcp, 80, None, None);
        assert!(a.conns.is_empty());

        a.conn_flow(&flow(&id, bytes(1, 1)));
        a.conn_end(&id, &bytes(1, 1));
        assert!(a.counters.is_empty());
    }

    #[test]
    fn role_from_destination() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let unicast = Some(PktLinkType::Unicast);
        let bcast = Some(PktLinkType::Broadcast);
        let mcast = Some(PktLinkType::Multicast);

        assert_eq!(ActivityRole::of_client(&ip("10.0.0.2"), unicast), ActivityRole::Client);
        assert_eq!(ActivityRole::of_client(&ip("10.0.0.2"), None), ActivityRole::Client);
        // Directed broadcast: only the MAC tells.
        assert_eq!(ActivityRole::of_client(&ip("192.168.1.255"), bcast), ActivityRole::Broadcast);
        assert_eq!(ActivityRole::of_client(&ip("192.168.1.255"), None), ActivityRole::Client);
        assert_eq!(ActivityRole::of_client(&ip("255.255.255.255"), None), ActivityRole::Broadcast);
        assert_eq!(ActivityRole::of_client(&ip("224.0.0.251"), mcast), ActivityRole::Multicast);
        assert_eq!(ActivityRole::of_client(&ip("ff02::fb"), mcast), ActivityRole::Multicast);
        // Multicast sent to a unicast MAC (e.g. converted by a WiFi AP).
        assert_eq!(ActivityRole::of_client(&ip("239.255.255.250"), unicast), ActivityRole::Multicast);
    }

    #[test]
    fn broadcast_only_on_sender() {
        let mut a = Activity::new(&ActivityConfig::default());
        let group = IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251));
        let id = UniqueId::new(at(0));
        a.conn_start(&id, Protocols::Udp, ActivityRole::Multicast, CLIENT, group, 5353, Some(1), None);
        a.conn_end(&id, &bytes(60, 0));

        assert_eq!(a.counters.len(), 1);
        let c = get(&a, 1, ActivityRole::Multicast, Protocols::Udp, 5353);
        assert_eq!((c.new_conns, c.unanswered_conns, c.refused_conns, c.bytes_out, c.bytes_in), (1, None, None, 60, 0));
        assert_eq!(c.peers.as_slice(), &[group]);
    }

    #[test]
    fn event_leaves_out_what_does_not_apply() {
        let mut a = Activity::new(&ActivityConfig::default());
        start(&mut a, Protocols::Tcp, 22, Some(1), None);
        start(&mut a, Protocols::Udp, 53, Some(1), None);
        let id = UniqueId::new(at(0));
        a.conn_start(&id, Protocols::Udp, ActivityRole::Broadcast, CLIENT, IpAddr::V4(Ipv4Addr::BROADCAST), 67, Some(1), None);

        let events = a.take_activities();
        assert!(a.counters.is_empty());
        assert_eq!(events.len(), 1);
        let json = serde_json::to_value(&events[0]).unwrap();
        assert_eq!(json["host"], 1);
        let svc = |role: &str, port: u64| json["services"].as_array().unwrap().iter()
            .find(|s| s["role"] == role && s["port"] == port).unwrap().as_object().unwrap().clone();

        let tcp = svc("client", 22);
        assert_eq!(tcp["proto"], "tcp");
        assert!(tcp.contains_key("unanswered_conns") && tcp.contains_key("refused_conns"));
        let udp = svc("client", 53);
        assert!(udp.contains_key("unanswered_conns") && !udp.contains_key("refused_conns"));
        let bcast = svc("broadcast", 67);
        assert!(!bcast.contains_key("unanswered_conns") && !bcast.contains_key("refused_conns"));
        assert!(!bcast.contains_key("peers_overflow"));
    }
}
