use crate::packet::PktTime;
use crate::proto::ethernet::EthernetMac;
use crate::messagebus::{MessageBus, MessageRxChannel, MessageTxChannel, Message};
use crate::event::{EventRef, EventKind, EventPayload, EventStr};

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use serde::Deserialize;
use smallvec::SmallVec;
use crossbeam_channel;


#[derive(Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct HostDbConfig {
    /// Time for arp reply
    pub arp_timeout: Duration,
}


enum HostIdentifier {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
    Mac(EthernetMac),
    DhcpId(Box<[u8]>)
}


enum HostIdentifierSrc {
    Traffic,
    Arp,
    Ndp,
    Dhcp
}

struct HostIdentifierEntry {
    id: HostIdentifier,
    source: HostIdentifierSrc,
    expires: PktTime
}

struct Host {
    ids: SmallVec<[HostIdentifierEntry; 4]>,
    first_seen: PktTime,
    last_seen: PktTime,
}


#[derive(Debug)]
pub struct HostDb {

}

pub type HostDbRef = Arc<Mutex<HostDb>>;

impl HostDb {

    fn run(db: HostDbRef, rx: MessageRxChannel) {

        for msg in rx {
            match msg {
                Message::Shutdown => break,
                _ => {
                    let _hostdb = db.lock().unwrap();
                    // TODO: apply event to the host table
                }
            }
        }

    }
}


#[derive(Debug)]
pub struct HostDbRunner {
    db: HostDbRef,
    tx: MessageTxChannel,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl HostDbRunner {

    pub fn new() -> Self {

        let (tx, rx) = crossbeam_channel::unbounded();

        MessageBus::event_subscribe_kind(EventKind::NetDhcpMessage, &tx);

        let db: HostDbRef = Arc::new(Mutex::new(HostDb {}));
        let worker_db = db.clone();

        let thread = std::thread::spawn(move || {
            HostDb::run(worker_db, rx);
        });

        Self { db, tx, thread: Mutex::new(Some(thread)) }

    }

    pub fn db(&self) -> HostDbRef {
        self.db.clone()
    }

    /// Ask the worker to stop and join its thread. Callable through a shared
    /// reference (e.g. from the global Intel): the handle is taken out here, so
    /// no ownership of `self` is required. Idempotent — a second call just hits a
    /// disconnected channel and does nothing.
    pub fn join(&self) {

        self.tx.send(Message::Shutdown).ok();

        if let Some(thread) = self.thread.lock().unwrap().take() {
            thread.join().unwrap();
        }

    }
}
