
use crate::packet::PktTime;

use std::fmt::Debug;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, OnceLock};
use strum::{EnumCount, IntoEnumIterator};
use strum_macros::{EnumString, AsRefStr, EnumCount, EnumIter, IntoStaticStr};
use crossbeam_channel;
use serde::Serialize;
use tracing::{debug, trace};


static EVENT_BUS: OnceLock<EventBus> = OnceLock::new();
static EVENT_ID_COUNTER: AtomicU16 = AtomicU16::new(0);


#[derive(Debug, Serialize)]
pub struct SysShutdown {}

#[repr(usize)]
#[derive(Debug, Copy, Clone, PartialEq, EnumString, AsRefStr, EnumCount, EnumIter, IntoStaticStr)]
pub enum EventKind {

    #[strum(serialize = "sys.shutdown")]
    SysShutdown,
    #[strum(serialize = "net.tcp.connection.start")]
    NetTcpConnectionStart,
    #[strum(serialize = "net.tcp.connection.end")]
    NetTcpConnectionEnd,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum EventPayload {

    SysShutdown(SysShutdown),
    NetTcpConnectionStart(crate::proto::tcp::conntrack::NetTcpConnectionStart),
    NetTcpConnectionEnd(crate::proto::tcp::conntrack::NetTcpConnectionEnd),

}

impl EventPayload {
    fn kind(&self) -> EventKind {
        match self {
            EventPayload::SysShutdown(_) => EventKind::SysShutdown,
            EventPayload::NetTcpConnectionStart(_) => EventKind::NetTcpConnectionStart,
            EventPayload::NetTcpConnectionEnd(_) => EventKind::NetTcpConnectionEnd,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct EventId {
    id: String,
}

impl EventId {
    pub fn new(ts: PktTime) -> EventId {

        let counter = EVENT_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
        let val: u128 = ((u64::from(ts) as u128) << 16) | counter as u128;
        EventId {
            id: base62::encode(val)
        }
    }
}


pub type EventTxChannel = crossbeam_channel::Sender<EventRef>;
pub type EventRxChannel = crossbeam_channel::Receiver<EventRef>;

#[derive(Debug)]
pub struct EventBus {
    subscribers: Vec<Vec<EventTxChannel>>,
}

impl EventBus {

    pub fn new() -> Self {
        let mut subscribers = Vec::with_capacity(EventKind::COUNT);

        for _ in 0..EventKind::COUNT {
            subscribers.push(Vec::new());
        }

        EventBus {
            subscribers,
        }

    }

    pub fn init(self) {
        EVENT_BUS.set(self).unwrap();
    }

    pub fn subscribe_glob(&mut self, evt_glob: &str, tx: &EventTxChannel) {

        for evt in EventKind::iter() {
            let id = evt as usize;
            let name = evt.as_ref();

            if ! Self::match_glob(evt_glob, name) {
                continue;
            }

            debug!("Adding one subscriber to event {} ({})", name, id);
            self.subscribers[id].push(tx.clone());
        }
    }

    fn match_glob(evt_glob: &str, evt_name: &str) -> bool {

        if evt_glob == "*" {
            return true; // Catch all
        }

        let g_parts: Vec<&str> = evt_glob.split('.').collect();
        let n_parts: Vec<&str> = evt_name.split('.').collect();

        for (i, p) in g_parts.iter().enumerate() {
            // Check each part

            if *p == "*" {
                // We got a wildcard
                return true;
            }

            if i >= n_parts.len() || p != &n_parts[i] {
                // More parts in our glob
                // Or part in our glob doesn't match the event name part
                return false;
            }

        }

        // Everything matched and we have the same number of parts
        g_parts.len() == n_parts.len()

    }

    #[cfg(test)]
    pub fn publish(evt: Event) {
        trace!("Got event {:?}", evt.kind());
    }

    #[cfg(not(test))]
    pub fn publish(evt: Event) {

        trace!("Got event {:?}", evt.kind());
        let evt_bus = EVENT_BUS.get().unwrap();

        let id = evt.kind() as usize;

        let evt_ref = Arc::new(evt);

        for sub in &evt_bus.subscribers[id] {
            sub.send(evt_ref.clone()).unwrap();
        }

    }
}


pub type EventRef = Arc<Event>;

#[derive(Debug, Serialize)]
pub struct Event {

    #[serde(flatten)]
    id: EventId,
    #[serde(serialize_with = "PktTime::serialize")]
    ts: PktTime,
    kind: &'static str,

    #[serde(flatten)]
    payload: EventPayload,

}


impl Event {

    pub fn new(ts: PktTime, payload: EventPayload) -> Self {
        let kind = payload.kind();
        Event {
            id: EventId::new(ts),
            ts: ts,
            kind: kind.into(),
            payload: payload,
        }
    }

    pub fn send(self) {

        EventBus::publish(self);

    }

    pub fn kind(&self) -> EventKind {
        self.payload.kind()
    }

}
