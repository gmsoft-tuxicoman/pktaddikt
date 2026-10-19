use crate::packet::PktTime;
use crate::proto::ethernet::EthernetMac;
use crate::proto::dhcp::{NetDhcpMessage, NetDhcpOptions};

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use serde::Deserialize;
use smallvec::SmallVec;


#[derive(Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct HostDbConfig {
    /// Time for arp reply
    pub arp_timeout: Duration,
}


#[derive(Debug, Clone, PartialEq)]
enum HostIdentifier {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
    Mac(EthernetMac),
    DhcpId(Box<[u8]>)
}


#[derive(Debug, Clone, Copy, PartialEq)]
enum HostIdentifierSrc {
    Traffic,
    Arp,
    Ndp,
    Dhcp
}

#[derive(Debug, Clone, PartialEq)]
struct HostIdentifierEntry {
    id: HostIdentifier,
    source: HostIdentifierSrc,
    expires: PktTime
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
}

pub type HostDbRef = Arc<Mutex<HostDb>>;

impl HostDb {

    pub fn new() -> Self {
        Self {
            next_id: 0,
            hosts: HashMap::new(),
            by_mac: HashMap::new(),
            by_v4: HashMap::new(),
            by_v6: HashMap::new(),
        }
    }

    /// Record the authoritative MAC <-> IPv4 binding from a DHCP ACK.
    pub fn evt_dhcp_ack(&mut self, msg: &NetDhcpMessage, ts: PktTime) {

        // A usable ACK binding needs both a client MAC and an assigned address.
        if msg.yiaddr == Ipv4Addr::UNSPECIFIED || msg.chaddr == EthernetMac([0u8; 6]) {
            return;
        }

        // Lease time is mandatory in an ACK. Without it there's no valid expiry,
        // so ignore the message rather than guessing a TTL.
        let mut lease_secs: Option<u32> = None;
        for opt in &msg.options {
            if let NetDhcpOptions::LeaseTime(secs) = opt {
                lease_secs = Some(*secs);
            }
        }
        let ttl = match lease_secs {
            Some(secs) => PktTime::from_secs(u64::from(secs)),
            None => return,
        };
        let expires = ts + ttl;

        // The MAC is the stable identity for a DHCP-learned host.
        let id = self.host_for_mac(msg.chaddr, ts);
        if let Some(h) = self.hosts.get_mut(&id) {
            h.last_seen = ts;
        }

        // Bind each applicable identity to this host (index maps + Host.ids).
        self.attach(id, HostIdentifier::Mac(msg.chaddr), HostIdentifierSrc::Dhcp, expires);
        self.attach(id, HostIdentifier::V4(msg.yiaddr), HostIdentifierSrc::Dhcp, expires);

    }

    /// Return the HostId for `mac`, creating a fresh host if we've not seen it.
    fn host_for_mac(&mut self, mac: EthernetMac, ts: PktTime) -> HostId {

        if let Some(&id) = self.by_mac.get(&mac) {
            return id;
        }

        let id = self.next_id;
        self.next_id += 1;
        self.hosts.insert(id, Host { ids: SmallVec::new(), first_seen: ts, last_seen: ts });
        id

    }

    /// Bind one identity to a host: point the concrete index at `id` and record it
    /// on the Host. If the identity was owned by another host, detach it there.
    fn attach(&mut self, id: HostId, ident: HostIdentifier, src: HostIdentifierSrc, expires: PktTime) {

        match &ident {
            HostIdentifier::Mac(m) => {
                if let Some(prev) = self.by_mac.insert(*m, id) { if prev != id { self.detach(prev, &ident); } }
            }
            HostIdentifier::V4(ip) => {
                if let Some(prev) = self.by_v4.insert(*ip, id) { if prev != id { self.detach(prev, &ident); } }
            }
            HostIdentifier::V6(ip) => {
                if let Some(prev) = self.by_v6.insert(*ip, id) { if prev != id { self.detach(prev, &ident); } }
            }
            HostIdentifier::DhcpId(_) => {} // no dedicated index for DHCP client-id
        }

        if let Some(host) = self.hosts.get_mut(&id) {
            match host.ids.iter_mut().find(|e| e.id == ident && e.source == src) {
                Some(e) => e.expires = expires,
                None => host.ids.push(HostIdentifierEntry { id: ident.clone(), source: src, expires }),
            }
        }

    }

    /// Drop an identity from a host; if that leaves it unreachable by any index,
    /// remove the host entirely and scrub its remaining index entries.
    fn detach(&mut self, id: HostId, ident: &HostIdentifier) {

        let now_empty = match self.hosts.get_mut(&id) {
            Some(host) => { host.ids.retain(|e| &e.id != ident); host.ids.is_empty() }
            None => false,
        };

        if now_empty {
            self.remove_host(id);
        }

    }

    /// Remove a host and every index entry that still points at it.
    fn remove_host(&mut self, id: HostId) {

        let host = match self.hosts.remove(&id) { Some(h) => h, None => return };

        for e in &host.ids {
            match &e.id {
                HostIdentifier::Mac(m) => { if self.by_mac.get(m) == Some(&id) { self.by_mac.remove(m); } }
                HostIdentifier::V4(ip) => { if self.by_v4.get(ip) == Some(&id) { self.by_v4.remove(ip); } }
                HostIdentifier::V6(ip) => { if self.by_v6.get(ip) == Some(&id) { self.by_v6.remove(ip); } }
                HostIdentifier::DhcpId(_) => {}
            }
        }

    }
}
