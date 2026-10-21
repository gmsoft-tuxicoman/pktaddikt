
use crate::intel::hostdb::{HostDb, HostDbConfig, HostDbRef};
use crate::messagebus::{MessageBus, MessageTxChannel, MessageRxChannel, Message};
use crate::event::{EventKind, EventPayload};
use crate::packet::PktTime;

use serde::Deserialize;
use ipnet::IpNet;

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use crossbeam_channel;

pub mod hostdb;

static INTEL: OnceLock<Intel> = OnceLock::new();

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IntelConfig {

    /// Networks to treat as local (CIDR, IPv4 and IPv6).
    /// Defaults to the RFC 1918 private ranges plus the IPv6 unique local range.
    pub local_nets: Vec<IpNet>,
    /// Host DB configuration
    #[serde(default)]
    pub hostdb: Option<HostDbConfig>,
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
            hostdb: None
        }
    }
}

#[derive(Debug)]
pub struct Intel {
    runner: Option<IntelRunner>
}

impl Intel {

    pub fn new() -> Self {
        Self {
            runner: Some(IntelRunner::new())
        }
    }

    pub fn init() {
        INTEL.set(Self::new()).unwrap();
    }

/*
    /// Shared handle other threads use to read/mutate the host table.
    pub fn hosts() -> Option<HostDbRef> {
        INTEL.get().and_then(|intel| intel.runner.as_ref()).map(|r| r.hostdb())
    }
*/
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
    db: HostDbRef,
    tx: MessageTxChannel,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl IntelRunner {

    fn new() -> Self {

        let (tx, rx) = crossbeam_channel::unbounded();

        // Intel — not HostDb — owns the event subscription. Add more kinds here
        // as NDP/etc. learning is wired up.
        MessageBus::event_subscribe_kind(EventKind::NetDhcpMessage, &tx);
        MessageBus::event_subscribe_kind(EventKind::NetArpReply, &tx);

        let hostdb_cfg = crate::config::Config::get().intel.hostdb.clone().unwrap_or_default();
        let sweep_interval = Duration::from_secs(hostdb_cfg.sweep_interval);
        let db: HostDbRef = Arc::new(Mutex::new(HostDb::new(&hostdb_cfg)));
        let worker_db = db.clone();

        let thread = std::thread::spawn(move || {
            Self::run(worker_db, rx, sweep_interval);
        });

        Self { db, tx, thread: Mutex::new(Some(thread)) }

    }

    fn run(db: HostDbRef, rx: MessageRxChannel, sweep_interval: Duration) {

        // Eviction is O(hosts), so sweep for idle hosts at most once per
        // `sweep_interval` of capture time rather than on every event.
        let sweep_interval = PktTime::from(sweep_interval);
        let mut next_sweep: Option<PktTime> = None;

        for msg in rx {
            match msg {
                Message::Shutdown => break,
                Message::Event(evt) => {
                    IntelRunner::dispatch(&db, &evt);

                    if next_sweep.map_or(true, |due| evt.ts >= due) {
                        db.lock().unwrap().evict_idle(evt.ts);
                        next_sweep = Some(evt.ts + sweep_interval);
                    }
                }
                _ => {}
            }
        }

    }

    fn dispatch(db: &HostDbRef, evt: &crate::event::EventRef) {

        match &evt.payload {
            EventPayload::NetDhcpMessage(dhcp) => {
                // Only the DHCP ACK is an authoritative MAC <-> IP binding.
                if dhcp.r#type != crate::proto::dhcp::ProtoDhcpMessageType::DHCPACK { return; }
                db.lock().unwrap().evt_dhcp_ack(dhcp, evt.ts);
            }
            EventPayload::NetArpReply(arp) => {
                db.lock().unwrap().evt_arp_reply(arp, evt.ts);
            }
            _ => {}
        }

    }

/*
    fn hostdb(&self) -> HostDbRef {
        self.db.clone()
    }
*/
    fn join(&self) {

        self.tx.send(Message::Shutdown).ok();

        if let Some(thread) = self.thread.lock().unwrap().take() {
            thread.join().unwrap();
        }

    }

}
