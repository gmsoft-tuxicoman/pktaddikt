use crate::packet::PktTime;
use crate::proto::ethernet::EthernetMac;
use crate::proto::arp::NetArpReply;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use serde::{Deserialize, Serialize};
use ipnet::IpNet;
use smallvec::SmallVec;
use tracing::trace;


#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HostDbConfig {
    /// How long an ARP-learned MAC <-> IPv4 binding stays valid, in seconds. ARP
    /// replies carry no TTL of their own, so the validity window is a policy choice.
    pub arp_timeout: u64,
    /// How long a host is retained after it was last seen, in seconds, bounding
    /// memory. A host and its stable identity (MAC) outlive its
    /// individual bindings on purpose: a machine returning after downtime —
    /// overnight, a weekend — re-correlates to the same HostId instead of looking
    /// brand new. `None` (config `null`) disables eviction and retains forever.
    pub host_timeout: Option<u64>,
    /// Minimum seconds of capture-time between idle-host sweeps. Eviction is
    /// O(hosts), so on a large network a coarser interval trades eviction
    /// promptness for less scan overhead. Ignored when `host_timeout` is disabled.
    pub sweep_interval: u64,
}

impl Default for HostDbConfig {
    fn default() -> Self {
        Self {
            // 4h — the default Cisco ARP cache timeout.
            arp_timeout: 4 * 3600,
            // ~1 month: long enough to survive a vacation so a returning host
            // keeps its identity. Set to null in config to retain indefinitely.
            host_timeout: Some(30 * 24 * 3600),
            sweep_interval: 600,
        }
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum HostIdentifier {
    Ip(IpAddr),
    Mac(EthernetMac),
}


#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub enum HostIdentifierSrc {
    Traffic,
    Arp,
    Ndp,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HostIdentifierEntry {
    pub id: HostIdentifier,
    pub source: HostIdentifierSrc,
    /// End of the binding's validity; `None` for one learned from traffic,
    /// which holds until something contradicts it.
    pub expires: Option<PktTime>,
}

#[derive(Debug)]
struct Host {
    ids: SmallVec<[HostIdentifierEntry; 4]>,
    first_seen: PktTime,
    last_seen: PktTime,
}

impl Host {
    /// Whether ARP placed this host on our segment: only ARP binds a MAC.
    fn has_mac(&self) -> bool {
        self.ids.iter().any(|e| matches!(e.id, HostIdentifier::Mac(_)))
    }
}


/// Canonical identifier for a host entry. Every concrete identity (MAC, IP)
/// resolves to one of these through the identifier index.
pub type HostId = usize;

/// Two hosts found to be the same machine: `from` was folded into `to` and no
/// longer exists. Whatever was recorded under `from` belongs to `to` now.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HostMerge {
    pub from: HostId,
    pub to: HostId,
}


#[derive(Debug)]
pub struct HostDb {
    next_id: HostId,
    hosts: HashMap<HostId, Host>,
    by_ident: HashMap<HostIdentifier, HostId>,
    arp_timeout: Duration,
    host_timeout: Option<Duration>,
    /// Only addresses in these resolve to hosts.
    local_nets: Vec<IpNet>,
}

impl HostDb {

    pub fn new(cfg: &HostDbConfig, local_nets: &[IpNet]) -> Self {
        Self {
            next_id: 0,
            hosts: HashMap::new(),
            by_ident: HashMap::new(),
            arp_timeout: Duration::from_secs(cfg.arp_timeout),
            host_timeout: cfg.host_timeout.map(Duration::from_secs),
            local_nets: local_nets.to_vec(),
        }
    }

    /// Record the MAC <-> IPv4 binding announced by an ARP reply. The reply's
    /// sender fields are the authoritative "sender_ip is reachable at
    /// sender_mac" claim; the target fields just echo the requester.
    /// Returns the merge it made if the reply showed two hosts to be one.
    pub fn evt_arp_reply(&mut self, msg: &NetArpReply, ts: PktTime) -> Option<HostMerge> {

        // A usable binding needs both a sender MAC and a sender IP.
        if msg.sender_ip == Ipv4Addr::UNSPECIFIED || msg.sender_mac == EthernetMac([0u8; 6]) {
            return None;
        }

        let expires = Some(ts + PktTime::from(self.arp_timeout));

        // The MAC is the stable identity for an ARP-learned host. A host so far
        // only known from traffic on that IP is the same machine: adopt it so
        // it keeps its HostId, or if the MAC already has a host, fold it in.
        let ip = IpAddr::V4(msg.sender_ip);
        let owner = self.lookup(&HostIdentifier::Mac(msg.sender_mac), ts);
        let traffic_only = self.lookup(&HostIdentifier::Ip(ip), ts)
            .filter(|id| !self.hosts[id].has_mac());
        let mut merge = None;
        let id = match (owner, traffic_only) {
            (Some(id), Some(from)) => {
                self.merge(from, id);
                merge = Some(HostMerge { from, to: id });
                id
            }
            (Some(id), None) => id,
            (None, Some(id)) => id,
            (None, None) => self.new_host(ts),
        };
        self.hosts.get_mut(&id).expect("hostdb: index points at a missing host").last_seen = ts;

        self.attach(id, HostIdentifier::Mac(msg.sender_mac), HostIdentifierSrc::Arp, expires);
        self.attach(id, HostIdentifier::Ip(ip), HostIdentifierSrc::Arp, expires);

        merge

    }

    /// Fold host `from` into `to`: its identifiers and time span move over and
    /// `from` is removed.
    fn merge(&mut self, from: HostId, to: HostId) {

        let src = self.hosts.remove(&from).expect("hostdb: index points at a missing host");
        trace!("hostdb: merging host {} into host {}", from, to);

        let dst = self.hosts.get_mut(&to).expect("hostdb: index points at a missing host");
        dst.first_seen = dst.first_seen.min(src.first_seen);
        dst.last_seen = dst.last_seen.max(src.last_seen);

        // The index gives each identifier a single owner, so `to` can't
        // already hold any of `from`'s.
        for e in src.ids {
            assert!(dst.ids.iter().all(|d| d.id != e.id), "hostdb: identifier bound to two hosts");
            self.by_ident.insert(e.id, to);
            dst.ids.push(e);
        }

    }

    /// The host using `ip` at `ts`, for any address in the local networks;
    /// `None` for every other address. `mac` is the source MAC of a packet
    /// from `ip`, if known.
    ///
    /// An IP binding is confirmed by ARP until its ARP expiry; the first time
    /// the IP is seen after that, it carries on as a `Traffic` binding. A
    /// `Traffic` binding doesn't expire: silence proves nothing, so it holds
    /// until ARP or the MAC check shows another machine on the IP, or the host
    /// is evicted as idle.
    ///
    /// Traffic never binds or confirms a MAC: routed packets carry the router's.
    /// `mac` only serves to spot a change of hands: if ARP placed `ip` on our
    /// segment (its host has a MAC, which only ARP binds) its packets carry its
    /// own MAC, so a different one means another machine now has the IP.
    pub fn host_for_ip(&mut self, ip: &IpAddr, mac: Option<EthernetMac>, ts: PktTime) -> Option<HostId> {

        if !self.local_nets.iter().any(|n| n.contains(ip)) {
            return None;
        }

        let ident = HostIdentifier::Ip(*ip);

        if let Some(id) = self.lookup(&ident, ts) {
            let host = self.hosts.get_mut(&id).expect("hostdb: index points at a missing host");

            let owns_mac = |m| host.ids.iter().any(|e| e.id == HostIdentifier::Mac(m));
            if let Some(mac) = mac.filter(|&m| host.has_mac() && !owns_mac(m)) {
                trace!("hostdb: {:?} seen from {}, not host {}'s MAC: changed hands", ident, mac, id);
                self.by_ident.remove(&ident);
                self.detach(id, &ident);
            } else {
                let e = host.ids.iter_mut().find(|e| e.id == ident).expect("hostdb: indexed identifier missing from its host");
                if e.source == HostIdentifierSrc::Arp && e.expires.is_some_and(|x| x < ts) {
                    trace!("hostdb: host {} binding {:?} now from traffic", id, ident);
                    e.source = HostIdentifierSrc::Traffic;
                    e.expires = None;
                }
                host.last_seen = host.last_seen.max(ts);
                return Some(id);
            }
        }

        let id = self.new_host(ts);
        self.attach(id, ident, HostIdentifierSrc::Traffic, None);
        Some(id)

    }

    /// The host `ident` is bound to at `ts`. One idle past `host_timeout` is
    /// evicted on the spot, as the next sweep would, and doesn't count.
    fn lookup(&mut self, ident: &HostIdentifier, ts: PktTime) -> Option<HostId> {
        let id = *self.by_ident.get(ident)?;
        let host = self.hosts.get(&id).expect("hostdb: index points at a missing host");
        if self.is_idle(host, ts) {
            trace!("hostdb: evicting idle host {} at {}", id, ts);
            self.remove_host(id);
            return None;
        }
        Some(id)
    }

    /// Whether `host` has been idle past `host_timeout` at `now`.
    fn is_idle(&self, host: &Host, now: PktTime) -> bool {
        self.host_timeout.is_some_and(|t| now - host.last_seen > PktTime::from(t))
    }

    fn new_host(&mut self, ts: PktTime) -> HostId {
        let id = self.next_id;
        self.next_id += 1;
        self.hosts.insert(id, Host { ids: SmallVec::new(), first_seen: ts, last_seen: ts });
        trace!("hostdb: created host {}", id);
        id
    }

    /// Bind one identity to a host: point the index at `id` and record it
    /// on the Host. If the identity was owned by another host, detach it there.
    fn attach(&mut self, id: HostId, ident: HostIdentifier, src: HostIdentifierSrc, expires: Option<PktTime>) {

        if let Some(prev) = self.by_ident.insert(ident, id) {
            if prev != id {
                trace!("hostdb: {:?} reassigned from host {} to host {}", ident, prev, id);
                self.detach(prev, &ident);
            }
        }

        // One entry per identifier, carrying whatever confirmed it last.
        let host = self.hosts.get_mut(&id).expect("hostdb: index points at a missing host");
        match host.ids.iter_mut().find(|e| e.id == ident) {
            Some(e) => {
                e.source = src;
                e.expires = expires;
            }
            None => {
                trace!("hostdb: host {} bound {:?} (source {:?})", id, ident, src);
                host.ids.push(HostIdentifierEntry { id: ident, source: src, expires });
            }
        }

    }

    /// Drop an identity from a host; if that leaves it unreachable by any index,
    /// remove the host entirely and scrub its remaining index entries.
    fn detach(&mut self, id: HostId, ident: &HostIdentifier) {

        let host = self.hosts.get_mut(&id).expect("hostdb: index points at a missing host");
        let before = host.ids.len();
        host.ids.retain(|e| &e.id != ident);
        if host.ids.len() != before {
            trace!("hostdb: host {} unbound {:?}", id, ident);
        }

        if host.ids.is_empty() {
            self.remove_host(id);
        }

    }

    /// Remove a host and every index entry that still points at it.
    fn remove_host(&mut self, id: HostId) {

        let host = match self.hosts.remove(&id) { Some(h) => h, None => return };
        trace!("hostdb: removed host {}", id);

        for e in &host.ids {
            if self.by_ident.get(&e.id) == Some(&id) {
                self.by_ident.remove(&e.id);
            }
        }

    }

    /// Read-only snapshot of every known host and all the identities we've bound
    /// to it (with their source and expiry). This is how the identifiers get
    /// surfaced — they're learned internally but otherwise not observable.
    pub fn hosts(&self) -> impl Iterator<Item = HostView<'_>> {
        self.hosts.iter().map(|(&id, h)| HostView {
            id,
            first_seen: h.first_seen,
            last_seen: h.last_seen,
            identifiers: &h.ids,
        })
    }

    /// Evict hosts idle longer than the configured retention, bounding memory.
    /// Host identity is deliberately decoupled from binding freshness: a host
    /// outlives its individual bindings so a machine returning after downtime
    /// re-correlates to the same HostId. `now` is capture time, like everything
    /// else here. A `None` retention (disabled) evicts nothing.
    pub fn evict_idle(&mut self, now: PktTime) {

        let stale: Vec<HostId> = self.hosts.iter()
            .filter(|(_, h)| self.is_idle(h, now))
            .map(|(&id, _)| id)
            .collect();

        for id in stale {
            trace!("hostdb: evicting idle host {} at {}", id, now);
            self.remove_host(id);
        }

    }
}

/// A read-only view of one host and every way it's been identified.
#[derive(Debug, Serialize)]
pub struct HostView<'a> {
    pub id: HostId,
    pub first_seen: PktTime,
    pub last_seen: PktTime,
    pub identifiers: &'a [HostIdentifierEntry],
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::proto::arp::NetArpReply;

    fn local_nets() -> Vec<IpNet> {
        vec!["10.0.0.0/8".parse().unwrap(), "192.168.0.0/16".parse().unwrap()]
    }

    fn arp_reply(mac: EthernetMac, ip: Ipv4Addr) -> NetArpReply {
        NetArpReply {
            sender_mac: mac,
            sender_ip: ip,
            target_mac: EthernetMac([0u8; 6]),
            target_ip: Ipv4Addr::new(10, 0, 0, 254),
        }
    }

    #[test]
    fn host_retention_evicts_idle_host() {
        let mut db = HostDb::new(&HostDbConfig::default(), &local_nets()); // 30-day default
        db.evt_arp_reply(&arp_reply(EthernetMac([1, 2, 3, 4, 5, 6]), Ipv4Addr::new(10, 0, 0, 1)), PktTime::from_secs(0));
        assert_eq!(db.hosts().count(), 1);

        // Still within the retention window: kept.
        db.evict_idle(PktTime::from_secs(29 * 24 * 3600));
        assert_eq!(db.hosts().count(), 1);

        // Idle past the window: evicted.
        db.evict_idle(PktTime::from_secs(31 * 24 * 3600));
        assert_eq!(db.hosts().count(), 0);
    }

    #[test]
    fn host_retention_disabled_retains_forever() {
        let cfg = HostDbConfig { host_timeout: None, ..HostDbConfig::default() };
        let mut db = HostDb::new(&cfg, &local_nets());
        db.evt_arp_reply(&arp_reply(EthernetMac([1, 2, 3, 4, 5, 6]), Ipv4Addr::new(10, 0, 0, 1)), PktTime::from_secs(0));

        // A year later, nothing is evicted when retention is disabled.
        db.evict_idle(PktTime::from_secs(365 * 24 * 3600));
        assert_eq!(db.hosts().count(), 1);
    }

    #[test]
    fn host_retention_refreshed_by_activity() {
        let mut db = HostDb::new(&HostDbConfig::default(), &local_nets());
        let mac = EthernetMac([1, 2, 3, 4, 5, 6]);
        let ip = Ipv4Addr::new(10, 0, 0, 1);

        db.evt_arp_reply(&arp_reply(mac, ip), PktTime::from_secs(0));
        // Seen again near the edge of the window — last_seen moves forward.
        db.evt_arp_reply(&arp_reply(mac, ip), PktTime::from_secs(29 * 24 * 3600));

        // 31 days from the *first* sighting, but only 2 since the last: retained.
        db.evict_idle(PktTime::from_secs(31 * 24 * 3600));
        assert_eq!(db.hosts().count(), 1);
    }

    fn ip_entry(db: &HostDb, id: HostId, ip: IpAddr) -> HostIdentifierEntry {
        let host = db.hosts().find(|h| h.id == id).unwrap();
        host.identifiers.iter().find(|e| e.id == HostIdentifier::Ip(ip)).unwrap().clone()
    }

    #[test]
    fn host_for_ip_only_resolves_local_nets() {
        let mut db = HostDb::new(&HostDbConfig::default(), &local_nets());
        assert!(db.host_for_ip(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), None, PktTime::from_secs(0)).is_none());
        assert!(db.host_for_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), None, PktTime::from_secs(0)).is_some());
        assert_eq!(db.hosts().count(), 1);
    }

    #[test]
    fn traffic_binding_holds_until_host_evicted() {
        let mut db = HostDb::new(&HostDbConfig::default(), &local_nets());
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        let id = db.host_for_ip(&ip, None, PktTime::from_secs(0)).unwrap();
        let e = ip_entry(&db, id, ip);
        assert_eq!((e.source, e.expires), (HostIdentifierSrc::Traffic, None));

        // Silence doesn't end it: still the same host just short of host_timeout.
        let timeout = HostDbConfig::default().host_timeout.unwrap();
        let ts = PktTime::from_secs(timeout);
        assert_eq!(db.host_for_ip(&ip, None, ts), Some(id));
        assert_eq!(db.hosts().next().unwrap().last_seen, ts);

        // Idle past host_timeout, the host is gone with its binding: a new one.
        let later = PktTime::from_secs(2 * timeout + 1);
        let new = db.host_for_ip(&ip, None, later).unwrap();
        assert_ne!(new, id);
        assert_eq!(db.hosts().count(), 1);
    }

    #[test]
    fn arp_binding_moves_to_traffic_once_expired() {
        let arp = HostDbConfig::default().arp_timeout;
        let mut db = HostDb::new(&HostDbConfig::default(), &local_nets());
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        db.evt_arp_reply(&arp_reply(EthernetMac([1, 2, 3, 4, 5, 6]), ip), PktTime::from_secs(0));
        let ip = IpAddr::V4(ip);

        // Confirmed by ARP: traffic leaves the binding alone.
        let id = db.host_for_ip(&ip, None, PktTime::from_secs(arp)).unwrap();
        let e = ip_entry(&db, id, ip);
        assert_eq!((e.source, e.expires), (HostIdentifierSrc::Arp, Some(PktTime::from_secs(arp))));

        // Seen after it expired, however long after: same host, from traffic now.
        assert_eq!(db.host_for_ip(&ip, None, PktTime::from_secs(100 * arp)), Some(id));
        let e = ip_entry(&db, id, ip);
        assert_eq!((e.source, e.expires), (HostIdentifierSrc::Traffic, None));
    }

    #[test]
    fn mac_change_on_arp_placed_ip_starts_new_host() {
        let mut db = HostDb::new(&HostDbConfig::default(), &local_nets());
        let (old_mac, new_mac) = (EthernetMac([1, 2, 3, 4, 5, 6]), EthernetMac([6, 5, 4, 3, 2, 1]));
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        db.evt_arp_reply(&arp_reply(old_mac, ip), PktTime::from_secs(0));
        let ip = IpAddr::V4(ip);

        // Same MAC: same host.
        let id = db.host_for_ip(&ip, Some(old_mac), PktTime::from_secs(10)).unwrap();
        // Another MAC: the IP moved to another machine.
        let new = db.host_for_ip(&ip, Some(new_mac), PktTime::from_secs(20)).unwrap();
        assert_ne!(new, id);
        assert_eq!(ip_entry(&db, new, ip).source, HostIdentifierSrc::Traffic);
        assert!(db.hosts().find(|h| h.id == id).unwrap().identifiers.iter().all(|e| e.id != HostIdentifier::Ip(ip)));
        // And sticks there: the new host has no MAC, so the hint is moot.
        assert_eq!(db.host_for_ip(&ip, Some(old_mac), PktTime::from_secs(30)), Some(new));

        // ARP for the new MAC adopts it.
        db.evt_arp_reply(&arp_reply(new_mac, Ipv4Addr::new(10, 0, 0, 1)), PktTime::from_secs(40));
        assert_eq!(db.host_for_ip(&ip, Some(new_mac), PktTime::from_secs(50)), Some(new));
    }

    #[test]
    fn mac_ignored_without_arp() {
        // No ARP for the IP: it may be routed, the MAC the router's.
        let mut db = HostDb::new(&HostDbConfig::default(), &local_nets());
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let id = db.host_for_ip(&ip, Some(EthernetMac([1, 2, 3, 4, 5, 6])), PktTime::from_secs(0)).unwrap();
        assert_eq!(db.host_for_ip(&ip, Some(EthernetMac([6, 5, 4, 3, 2, 1])), PktTime::from_secs(10)), Some(id));
        assert!(db.hosts().next().unwrap().identifiers.iter().all(|e| !matches!(e.id, HostIdentifier::Mac(_))));
    }

    #[test]
    fn arp_merges_traffic_host_back_on_new_ip() {
        // Known as MAC M on A, comes back on B and talks before any ARP.
        let mut db = HostDb::new(&HostDbConfig::default(), &local_nets());
        let mac = EthernetMac([1, 2, 3, 4, 5, 6]);
        let (a, b) = (Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2));
        db.evt_arp_reply(&arp_reply(mac, a), PktTime::from_secs(0));
        let h = db.host_for_ip(&IpAddr::V4(a), None, PktTime::from_secs(0)).unwrap();
        let t = db.host_for_ip(&IpAddr::V4(b), None, PktTime::from_secs(100)).unwrap();
        assert_ne!(h, t);

        let merge = db.evt_arp_reply(&arp_reply(mac, b), PktTime::from_secs(200));
        assert_eq!(merge, Some(HostMerge { from: t, to: h }));
        assert_eq!(db.hosts().count(), 1);
        assert_eq!(db.host_for_ip(&IpAddr::V4(b), None, PktTime::from_secs(300)), Some(h));
        let host = db.hosts().next().unwrap();
        assert_eq!(host.first_seen, PktTime::from_secs(0));
        assert_eq!(ip_entry(&db, h, IpAddr::V4(b)).source, HostIdentifierSrc::Arp);
    }

    #[test]
    fn arp_for_another_machine_moves_ip_without_merge() {
        // A host with its own MAC isn't folded into another: the IP just moves.
        let mut db = HostDb::new(&HostDbConfig::default(), &local_nets());
        let (m1, m2) = (EthernetMac([1, 2, 3, 4, 5, 6]), EthernetMac([6, 5, 4, 3, 2, 1]));
        let (a, b) = (Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2));
        db.evt_arp_reply(&arp_reply(m1, a), PktTime::from_secs(0));
        db.evt_arp_reply(&arp_reply(m2, b), PktTime::from_secs(0));

        assert_eq!(db.evt_arp_reply(&arp_reply(m2, a), PktTime::from_secs(10)), None);
        assert_eq!(db.hosts().count(), 2);
    }

    #[test]
    fn arp_for_idle_host_starts_new_one() {
        let timeout = HostDbConfig::default().host_timeout.unwrap();
        let mut db = HostDb::new(&HostDbConfig::default(), &local_nets());
        let mac = EthernetMac([1, 2, 3, 4, 5, 6]);
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        db.evt_arp_reply(&arp_reply(mac, ip), PktTime::from_secs(0));
        let id = db.host_for_ip(&IpAddr::V4(ip), None, PktTime::from_secs(0)).unwrap();

        // No sweep ran, but the host is past host_timeout: evicted, not reused.
        db.evt_arp_reply(&arp_reply(mac, ip), PktTime::from_secs(timeout + 1));
        assert_eq!(db.hosts().count(), 1);
        assert_ne!(db.hosts().next().unwrap().id, id);
    }

    #[test]
    fn arp_adopts_traffic_only_host() {
        let mut db = HostDb::new(&HostDbConfig::default(), &local_nets());
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        let id = db.host_for_ip(&IpAddr::V4(ip), None, PktTime::from_secs(0)).unwrap();

        let mac = EthernetMac([1, 2, 3, 4, 5, 6]);
        db.evt_arp_reply(&arp_reply(mac, ip), PktTime::from_secs(10));

        assert_eq!(db.hosts().count(), 1);
        let host = db.hosts().next().unwrap();
        assert_eq!(host.id, id);
        assert!(host.identifiers.iter().any(|e| e.id == HostIdentifier::Mac(mac)));
        // One entry for the IP, now confirmed by ARP.
        assert_eq!(ip_entry(&db, id, IpAddr::V4(ip)).source, HostIdentifierSrc::Arp);
        assert_eq!(host.identifiers.len(), 2);
    }

    #[test]
    fn arp_reply_populates_host_ids() {
        let mut db = HostDb::new(&HostDbConfig::default(), &local_nets());

        let mac = EthernetMac([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let ip = Ipv4Addr::new(192, 168, 1, 10);
        let ts = PktTime::from_secs(1000);

        db.evt_arp_reply(&NetArpReply {
            sender_mac: mac,
            sender_ip: ip,
            target_mac: EthernetMac([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]),
            target_ip: Ipv4Addr::new(192, 168, 1, 1),
        }, ts);

        let hosts: Vec<_> = db.hosts().collect();
        assert_eq!(hosts.len(), 1);

        // Both the MAC and the IPv4 identity are recorded, sourced from ARP.
        let idents = hosts[0].identifiers;
        assert_eq!(idents.len(), 2);
        assert!(idents.iter().all(|e| e.source == HostIdentifierSrc::Arp));
        assert!(idents.iter().any(|e| e.id == HostIdentifier::Mac(mac)));
        assert!(idents.iter().any(|e| e.id == HostIdentifier::Ip(IpAddr::V4(ip))));

        let expires = Some(ts + PktTime::from_secs(HostDbConfig::default().arp_timeout));
        assert!(idents.iter().all(|e| e.expires == expires));
    }
}
