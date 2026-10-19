use crate::packet::PktTime;
use crate::proto::ethernet::EthernetMac;
use crate::proto::dhcp::{NetDhcpMessage, NetDhcpOptions};
use crate::proto::arp::NetArpReply;

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;


#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HostDbConfig {
    /// How long an ARP-learned MAC <-> IPv4 binding stays valid. ARP replies
    /// carry no TTL of their own, so the validity window is a policy choice.
    pub arp_timeout: Duration,
}

impl Default for HostDbConfig {
    fn default() -> Self {
        Self {
            // 4h — the default Cisco ARP cache timeout.
            arp_timeout: Duration::from_secs(4 * 3600),
        }
    }
}


#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum HostIdentifier {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
    Mac(EthernetMac),
    DhcpId(Box<[u8]>)
}


#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub enum HostIdentifierSrc {
    Traffic,
    Arp,
    Ndp,
    Dhcp
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
    by_dhcpid: HashMap<Box<[u8]>, HostId>,
    arp_timeout: Duration,
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
            by_dhcpid: HashMap::new(),
            arp_timeout: cfg.arp_timeout,
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
        let mut client_id: Option<Box<[u8]>> = None;
        for opt in &msg.options {
            match opt {
                NetDhcpOptions::LeaseTime(secs) => lease_secs = Some(*secs),
                NetDhcpOptions::ClientId(bytes) => client_id = Some(bytes.clone().into_boxed_slice()),
                _ => {}
            }
        }
        let ttl = match lease_secs {
            Some(secs) => PktTime::from_secs(u64::from(secs)),
            None => return,
        };
        let expires = ts + ttl;

        // The client-id (option 61) is the most stable identity: wireless clients
        // randomize their MAC, so the same client reappears under a new MAC. Match
        // on client-id first and treat the MAC as a mutable attribute of the host;
        // only fall back to MAC keying when no client-id is present.
        let matched = client_id.as_ref().and_then(|cid| self.by_dhcpid.get(cid).copied());
        let id = matched.unwrap_or_else(|| self.host_for_mac(msg.chaddr, ts));
        if let Some(h) = self.hosts.get_mut(&id) {
            h.last_seen = ts;
        }

        // Bind each applicable identity to this host. Attaching the address
        // migrates it off whichever host held it before (`attach` detaches the
        // V4 identity from the previous owner): that old host keeps its MAC and
        // client-id and only loses the address, so it survives on its own MAC
        // binding until that expires.
        self.attach(id, HostIdentifier::Mac(msg.chaddr), HostIdentifierSrc::Dhcp, expires);
        if let Some(cid) = client_id {
            // Only a real option-61 client-id is worth recording; without one the
            // MAC is already the identity and a copy of it would just be noise.
            self.attach(id, HostIdentifier::DhcpId(cid), HostIdentifierSrc::Dhcp, expires);
        }
        self.attach(id, HostIdentifier::V4(msg.yiaddr), HostIdentifierSrc::Dhcp, expires);

        // When we matched by client-id, the MAC and assigned address in this ACK
        // supersede whatever this client had before — a randomized-MAC rotation
        // and, from a server that keys on MAC, a fresh lease too. Drop the host's
        // earlier DHCP-learned MAC and IPv4 bindings that differ from this ACK so
        // dead values stop resolving to it. Bindings from other sources (ARP/NDP)
        // are left to expire on their own timers rather than be nuked by DHCP.
        if matched.is_some() {
            let stale: Vec<HostIdentifier> = self.hosts.get(&id).map_or_else(Vec::new, |h| {
                h.ids.iter().filter(|e| e.source == HostIdentifierSrc::Dhcp).filter_map(|e| match &e.id {
                    HostIdentifier::Mac(m) if *m != msg.chaddr => Some(e.id.clone()),
                    HostIdentifier::V4(ip) if *ip != msg.yiaddr => Some(e.id.clone()),
                    _ => None,
                }).collect()
            });
            for ident in stale {
                self.drop_identity(id, &ident);
            }
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
            HostIdentifier::DhcpId(c) => {
                if let Some(prev) = self.by_dhcpid.insert(c.clone(), id) { if prev != id { self.detach(prev, &ident); } }
            }
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
                HostIdentifier::DhcpId(c) => { if self.by_dhcpid.get(c) == Some(&id) { self.by_dhcpid.remove(c); } }
            }
        }

    }

    /// Fully remove one identity from a host: scrub its index entry and drop it
    /// from the host. Unlike `detach` — which assumes the identity is being
    /// reassigned to another host and leaves the index fixup to `attach`'s
    /// insert — this also clears the index. Removes the host if nothing is left.
    fn drop_identity(&mut self, id: HostId, ident: &HostIdentifier) {

        match ident {
            HostIdentifier::Mac(m) => { if self.by_mac.get(m) == Some(&id) { self.by_mac.remove(m); } }
            HostIdentifier::V4(ip) => { if self.by_v4.get(ip) == Some(&id) { self.by_v4.remove(ip); } }
            HostIdentifier::V6(ip) => { if self.by_v6.get(ip) == Some(&id) { self.by_v6.remove(ip); } }
            HostIdentifier::DhcpId(c) => { if self.by_dhcpid.get(c) == Some(&id) { self.by_dhcpid.remove(c); } }
        }

        self.detach(id, ident);

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
    use crate::proto::dhcp::{NetDhcpMessage, ProtoDhcpMessageType};
    use crate::base::UniqueId;

    fn dhcp_ack(chaddr: EthernetMac, yiaddr: Ipv4Addr, client_id: Option<Vec<u8>>, lease: u32, ts: PktTime) -> NetDhcpMessage {
        let mut options = vec![NetDhcpOptions::LeaseTime(lease)];
        if let Some(c) = client_id {
            options.push(NetDhcpOptions::ClientId(c));
        }
        NetDhcpMessage {
            conn_id: UniqueId::new(ts),
            client_ip: Ipv4Addr::UNSPECIFIED,
            client_port: 68,
            server_ip: Ipv4Addr::UNSPECIFIED,
            server_port: 67,
            r#type: ProtoDhcpMessageType::DHCPACK,
            hops: 0,
            xid: 0,
            secs: 0,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr,
            sname: None,
            file: None,
            options,
        }
    }

    #[test]
    fn dhcp_ack_ip_migration_keeps_old_host() {
        let mut db = HostDb::new(&HostDbConfig::default());

        let ip = Ipv4Addr::new(192, 168, 1, 50);
        let mac_a = EthernetMac([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let mac_b = EthernetMac([0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB]);

        // Client A leases the IP.
        db.evt_dhcp_ack(&dhcp_ack(mac_a, ip, Some(vec![1, 2, 3]), 3600, PktTime::from_secs(0)), PktTime::from_secs(0));
        assert_eq!(db.hosts().count(), 1);

        // A different client takes the same IP. The address migrates to B, but
        // A's host survives on its MAC binding — it just no longer holds the IP.
        db.evt_dhcp_ack(&dhcp_ack(mac_b, ip, Some(vec![9, 9, 9]), 3600, PktTime::from_secs(10)), PktTime::from_secs(10));

        let hosts: Vec<_> = db.hosts().collect();
        assert_eq!(hosts.len(), 2);

        // The IP now belongs to B.
        let owner = hosts.iter().find(|h| h.identifiers.iter().any(|e| e.id == HostIdentifier::V4(ip))).unwrap();
        assert!(owner.identifiers.iter().any(|e| e.id == HostIdentifier::Mac(mac_b)));

        // A is still around via its MAC, but no longer holds the address.
        let old = hosts.iter().find(|h| h.identifiers.iter().any(|e| e.id == HostIdentifier::Mac(mac_a))).unwrap();
        assert!(!old.identifiers.iter().any(|e| e.id == HostIdentifier::V4(ip)));
    }

    #[test]
    fn dhcp_ack_mac_and_ip_rotation_replaces_old_bindings() {
        let mut db = HostDb::new(&HostDbConfig::default());

        let cid = vec![1, 2, 3];
        let mac1 = EthernetMac([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let mac2 = EthernetMac([0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB]);
        let ip1 = Ipv4Addr::new(10, 0, 0, 5);
        let ip2 = Ipv4Addr::new(10, 0, 0, 6);

        db.evt_dhcp_ack(&dhcp_ack(mac1, ip1, Some(cid.clone()), 3600, PktTime::from_secs(0)), PktTime::from_secs(0));
        // Same client-id reappears on a new MAC *and* a new lease — the common
        // case when the server keys on MAC and treats the randomized client as new.
        db.evt_dhcp_ack(&dhcp_ack(mac2, ip2, Some(cid.clone()), 3600, PktTime::from_secs(10)), PktTime::from_secs(10));

        // Still one logical host, now bound to the new MAC and IP; both old
        // DHCP-learned bindings are dropped rather than left dangling.
        let hosts: Vec<_> = db.hosts().collect();
        assert_eq!(hosts.len(), 1);
        let idents = hosts[0].identifiers;
        assert!(idents.iter().any(|e| e.id == HostIdentifier::Mac(mac2)));
        assert!(!idents.iter().any(|e| e.id == HostIdentifier::Mac(mac1)));
        assert!(idents.iter().any(|e| e.id == HostIdentifier::V4(ip2)));
        assert!(!idents.iter().any(|e| e.id == HostIdentifier::V4(ip1)));
        assert!(idents.iter().any(|e| e.id == HostIdentifier::DhcpId(Box::from(cid.as_slice()))));
    }

    #[test]
    fn dhcp_ack_renewal_keeps_host() {
        let mut db = HostDb::new(&HostDbConfig::default());

        let ip = Ipv4Addr::new(192, 168, 1, 50);
        let mac = EthernetMac([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        // Same client-id renewing the same IP must not evict and recreate itself.
        db.evt_dhcp_ack(&dhcp_ack(mac, ip, Some(vec![1, 2, 3]), 3600, PktTime::from_secs(0)), PktTime::from_secs(0));
        db.evt_dhcp_ack(&dhcp_ack(mac, ip, Some(vec![1, 2, 3]), 3600, PktTime::from_secs(10)), PktTime::from_secs(10));

        let hosts: Vec<_> = db.hosts().collect();
        assert_eq!(hosts.len(), 1);
        // One entry per identity, not duplicated across the two ACKs.
        assert_eq!(hosts[0].identifiers.len(), 3);
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

        let expires = ts + PktTime::from(HostDbConfig::default().arp_timeout);
        assert!(idents.iter().all(|e| e.expires == expires));
    }
}
