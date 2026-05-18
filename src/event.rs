
use crate::packet::PktTime;
use crate::base::UniqueId;

use std::fmt::Debug;
use std::sync::{Arc, OnceLock};
use strum::{EnumCount, IntoEnumIterator};
use strum_macros::{EnumString, AsRefStr, EnumCount, EnumIter, IntoStaticStr};
use crossbeam_channel;
use serde::{Serialize, Serializer};
use tracing::{debug, trace};
use std::ops::Deref;
use std::borrow::Cow;


static EVENT_BUS: OnceLock<EventBus> = OnceLock::new();


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
    #[strum(serialize = "net.udp.connection.start")]
    NetUdpConnectionStart,
    #[strum(serialize = "net.udp.connection.end")]
    NetUdpConnectionEnd,
    #[strum(serialize = "net.http.request.basic")]
    NetHttpRequestBasic,
    #[strum(serialize = "net.http.response.basic")]
    NetHttpResponseBasic,
    #[strum(serialize = "net.dns.message")]
    NetDnsMessage,
    #[strum(serialize = "net.tls.clienthello")]
    NetTlsClientHello,
    #[strum(serialize = "net.nfs.exchange_id.call")]
    NetNfsExchangeIdCall,
    #[strum(serialize = "net.nfs.exchange_id.reply")]
    NetNfsExchangeIdReply,
    #[strum(serialize = "net.nfs.create_session.call")]
    NetNfsCreateSessionCall,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum EventPayload {

    SysShutdown(SysShutdown),
    NetTcpConnectionStart(crate::proto::tcp::conntrack::NetTcpConnectionStart),
    NetTcpConnectionEnd(crate::proto::tcp::conntrack::NetTcpConnectionEnd),
    NetUdpConnectionStart(crate::proto::udp::NetUdpConnectionStart),
    NetUdpConnectionEnd(crate::proto::udp::NetUdpConnectionEnd),
    NetHttpRequestBasic(crate::proto::http::NetHttpRequestBasic),
    NetHttpResponseBasic(crate::proto::http::NetHttpResponseBasic),
    NetDnsMessage(crate::proto::dns::NetDnsMessage),
    NetTlsClientHello(crate::proto::tls::NetTlsClientHello),
    NetNfsExchangeIdCall(crate::proto::sunrpc::nfs::NetNfsExchangeIdCall),
    NetNfsExchangeIdReply(crate::proto::sunrpc::nfs::NetNfsExchangeIdReply),
    NetNfsCreateSessionCall(crate::proto::sunrpc::nfs::NetNfsCreateSessionCall),
}

impl EventPayload {
    fn kind(&self) -> EventKind {
        match self {
            EventPayload::SysShutdown(_) => EventKind::SysShutdown,
            EventPayload::NetTcpConnectionStart(_) => EventKind::NetTcpConnectionStart,
            EventPayload::NetTcpConnectionEnd(_) => EventKind::NetTcpConnectionEnd,
            EventPayload::NetUdpConnectionStart(_) => EventKind::NetUdpConnectionStart,
            EventPayload::NetUdpConnectionEnd(_) => EventKind::NetUdpConnectionEnd,
            EventPayload::NetHttpRequestBasic(_) => EventKind::NetHttpRequestBasic,
            EventPayload::NetHttpResponseBasic(_) => EventKind::NetHttpResponseBasic,
            EventPayload::NetDnsMessage(_) => EventKind::NetDnsMessage,
            EventPayload::NetTlsClientHello(_) => EventKind::NetTlsClientHello,
            EventPayload::NetNfsExchangeIdCall(_) => EventKind::NetNfsExchangeIdCall,
            EventPayload::NetNfsExchangeIdReply(_) => EventKind::NetNfsExchangeIdReply,
            EventPayload::NetNfsCreateSessionCall(_) => EventKind::NetNfsCreateSessionCall,
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

    pub fn subscribe_glob(&mut self, evt_glob: &str, tx: &EventTxChannel) -> Result<(), ()> {

        let mut found = false;

        for evt in EventKind::iter() {
            let id = evt as usize;
            let name = evt.as_ref();

            if ! Self::match_glob(evt_glob, name) {
                continue;
            }

            found = true;

            debug!("Adding one subscriber to event {} ({})", name, id);
            self.subscribers[id].push(tx.clone());
        }

        if found {
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn subscribe_kind(&mut self, evt_kind: EventKind, tx: &EventTxChannel) {

        let evt_id = evt_kind as usize;
        self.subscribers[evt_id].push(tx.clone());

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

    pub fn has_subscribers(evt_kind: EventKind) -> bool {
        let id = evt_kind as usize;
        let Some(evt_bus) = EVENT_BUS.get() else {
            // Happens during test when event bus is not initialized
            // So pretend there is a subscriber so that parsing etc is done
            return true;
        };

        evt_bus.subscribers[id].len() > 0
    }

    #[cfg(test)]
    pub fn publish(evt: Event) {
        trace!("Publishing event {:?}", evt.kind());
    }

    #[cfg(not(test))]
    pub fn publish(evt: Event) {

        trace!("Publishing event {:?}", evt.kind());
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

    pub event_id: UniqueId,
    pub ts: PktTime,
    pub kind: &'static str,

    #[serde(flatten)]
    pub payload: EventPayload,

}


impl Event {

    pub fn new(ts: PktTime, payload: EventPayload) -> Self {
        let kind = payload.kind();
        Event {
            event_id: UniqueId::new(ts),
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

/// String stored as Vec<u8> and serialized to string
/// This allow quick storage in parsing process
/// And slower deserialization in output process
#[derive(Debug)]
pub struct EventStr(Vec<u8>);

impl Serialize for EventStr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&String::from_utf8_lossy(&self.0))
    }
}

impl Deref for EventStr {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Vec<u8>> for EventStr {
    fn from(v: Vec<u8>) -> Self {
        EventStr(v)
    }
}

impl From<&[u8]> for EventStr {
    fn from(s: &[u8]) -> Self {
        EventStr(s.to_vec())
    }
}

impl From<Cow<'_, [u8]>> for EventStr {
    fn from(cow: Cow<'_, [u8]>) -> Self {
        match cow {
            Cow::Borrowed(bytes) => EventStr::from(bytes),
            Cow::Owned(vec) => EventStr::from(vec),
        }
    }
}
