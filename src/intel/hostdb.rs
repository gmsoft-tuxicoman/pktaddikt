use crate::packet::PktTime;
use crate::proto::ethernet::EthernetMac;
use crate::proto::arp::NetArpReply;

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use serde::{Deserialize, Serialize};
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


#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum HostIdentifier {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
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
    pub expires: PktTime
}

#[derive(Debug)]
struct Host {
    ids: SmallVec<[HostIdentifierEntry; 4]>,
    first_seen: PktTime,
    last_seen: PktTime,
}


/// Canonical identifier for a host entry. Every concrete identity (MAC, IPv4,
/// IPv6) resolves to one of these through the index maps below.
pub type HostId = usize;


#[derive(Debug)]
pub struct HostDb {
    next_id: HostId,
    hosts: HashMap<HostId, Host>,
    by_mac: HashMap<EthernetMac, HostId>,
    by_v4: HashMap<Ipv4Addr, HostId>,
    by_v6: HashMap<Ipv6Addr, HostId>,
    arp_timeout: Duration,
    host_timeout: Option<Duration>,
}

pub type HostDbRef = Arc<Mutex<HostDb>>;

impl HostDb {

    pub fn new(cfg: &HostDbConfig) -> Self {
        Self {
            next_id: 0,
            hosts: HashMap::new(),
            by_mac: HashMap::new(),
            by_v4: HashMap::new(),
            by_v6: HashMap::new(),
            arp_timeout: Duration::from_secs(cfg.arp_timeout),
            host_timeout: cfg.host_timeout.map(Duration::from_secs),
        }
    }

    /// Record the MAC <-> IPv4 binding announced by an ARP reply. The reply's
    /// sender fields are the authoritative "sender_ip is reachable at
    /// sender_mac" claim; the target fields just echo the requester.
    pub fn evt_arp_reply(&mut self, msg: &NetArpReply, ts: PktTime) {

        // A usable binding needs both a sender MAC and a sender IP.
        if msg.sender_ip == Ipv4Addr::UNSPECIFIED || msg.sender_mac == EthernetMac([0u8; 6]) {
            return;
        }

        let expires = ts + PktTime::from(self.arp_timeout);

        // The MAC is the stable identity for an ARP-learned host.
        let id = self.host_for_mac(msg.sender_mac, ts);
        if let Some(h) = self.hosts.get_mut(&id) {
            h.last_seen = ts;
        }

        self.attach(id, HostIdentifier::Mac(msg.sender_mac), HostIdentifierSrc::Arp, expires);
        self.attach(id, HostIdentifier::V4(msg.sender_ip), HostIdentifierSrc::Arp, expires);

    }

    /// Return the HostId for `mac`, creating a fresh host if we've not seen it.
    fn host_for_mac(&mut self, mac: EthernetMac, ts: PktTime) -> HostId {

        if let Some(&id) = self.by_mac.get(&mac) {
            return id;
        }

        let id = self.next_id;
        self.next_id += 1;
        self.hosts.insert(id, Host { ids: SmallVec::new(), first_seen: ts, last_seen: ts });
        trace!("hostdb: created host {} (first mac {})", id, mac);
        id

    }

    /// Bind one identity to a host: point the concrete index at `id` and record it
    /// on the Host. If the identity was owned by another host, detach it there.
    fn attach(&mut self, id: HostId, ident: HostIdentifier, src: HostIdentifierSrc, expires: PktTime) {

        let prev = match &ident {
            HostIdentifier::Mac(m) => self.by_mac.insert(*m, id),
            HostIdentifier::V4(ip) => self.by_v4.insert(*ip, id),
            HostIdentifier::V6(ip) => self.by_v6.insert(*ip, id),
        };
        if let Some(prev) = prev {
            if prev != id {
                trace!("hostdb: {:?} reassigned from host {} to host {}", ident, prev, id);
                self.detach(prev, &ident);
            }
        }

        if let Some(host) = self.hosts.get_mut(&id) {
            match host.ids.iter_mut().find(|e| e.id == ident && e.source == src) {
                Some(e) => e.expires = expires,
                None => {
                    trace!("hostdb: host {} bound {:?} (source {:?})", id, ident, src);
                    host.ids.push(HostIdentifierEntry { id: ident.clone(), source: src, expires });
                }
            }
        }

    }

    /// Drop an identity from a host; if that leaves it unreachable by any index,
    /// remove the host entirely and scrub its remaining index entries.
    fn detach(&mut self, id: HostId, ident: &HostIdentifier) {

        let now_empty = match self.hosts.get_mut(&id) {
            Some(host) => {
                let before = host.ids.len();
                host.ids.retain(|e| &e.id != ident);
                if host.ids.len() != before {
                    trace!("hostdb: host {} unbound {:?}", id, ident);
                }
                host.ids.is_empty()
            }
            None => false,
        };

        if now_empty {
            self.remove_host(id);
        }

    }

    /// Remove a host and every index entry that still points at it.
    fn remove_host(&mut self, id: HostId) {

        let host = match self.hosts.remove(&id) { Some(h) => h, None => return };
        trace!("hostdb: removed host {}", id);

        for e in &host.ids {
            match &e.id {
                HostIdentifier::Mac(m) => { if self.by_mac.get(m) == Some(&id) { self.by_mac.remove(m); } }
                HostIdentifier::V4(ip) => { if self.by_v4.get(ip) == Some(&id) { self.by_v4.remove(ip); } }
                HostIdentifier::V6(ip) => { if self.by_v6.get(ip) == Some(&id) { self.by_v6.remove(ip); } }
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

        let timeout = match self.host_timeout {
            Some(t) => PktTime::from(t),
            None => return,
        };

        let stale: Vec<HostId> = self.hosts.iter()
            .filter(|(_, h)| now - h.last_seen > timeout)
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
        let mut db = HostDb::new(&HostDbConfig::default()); // 30-day default
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
        let mut db = HostDb::new(&cfg);
        db.evt_arp_reply(&arp_reply(EthernetMac([1, 2, 3, 4, 5, 6]), Ipv4Addr::new(10, 0, 0, 1)), PktTime::from_secs(0));

        // A year later, nothing is evicted when retention is disabled.
        db.evict_idle(PktTime::from_secs(365 * 24 * 3600));
        assert_eq!(db.hosts().count(), 1);
    }

    #[test]
    fn host_retention_refreshed_by_activity() {
        let mut db = HostDb::new(&HostDbConfig::default());
        let mac = EthernetMac([1, 2, 3, 4, 5, 6]);
        let ip = Ipv4Addr::new(10, 0, 0, 1);

        db.evt_arp_reply(&arp_reply(mac, ip), PktTime::from_secs(0));
        // Seen again near the edge of the window — last_seen moves forward.
        db.evt_arp_reply(&arp_reply(mac, ip), PktTime::from_secs(29 * 24 * 3600));

        // 31 days from the *first* sighting, but only 2 since the last: retained.
        db.evict_idle(PktTime::from_secs(31 * 24 * 3600));
        assert_eq!(db.hosts().count(), 1);
    }

    #[test]
    fn arp_reply_populates_host_ids() {
        let mut db = HostDb::new(&HostDbConfig::default());

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
        assert!(idents.iter().any(|e| e.id == HostIdentifier::V4(ip)));

        let expires = ts + PktTime::from_secs(HostDbConfig::default().arp_timeout);
        assert!(idents.iter().all(|e| e.expires == expires));
    }
}
