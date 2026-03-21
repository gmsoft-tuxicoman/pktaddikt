
use crate::packet::PktTime;

use std::fmt::Debug;
use std::sync::atomic::{AtomicU16, Ordering};
use strum_macros::{EnumString, AsRefStr};


static EVENT_ID_COUNTER: AtomicU16 = AtomicU16::new(0);

#[repr(u32)]
#[derive(Debug, EnumString, AsRefStr)]
pub enum EventKind {

    #[strum(serialize = "net.tcp.connection.start")]
    NetTcpConnectionStart,
    #[strum(serialize = "net.tcp.connection.end")]
    NetTcpConnectionEnd,
}

#[derive(Debug)]
pub enum EventPayload {

    NetTcpConnectionStart(crate::proto::tcp::conntrack::NetTcpConnectionStart),
    NetTcpConnectionEnd(crate::proto::tcp::conntrack::NetTcpConnectionEnd),

}

#[derive(Debug,Clone)]
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

#[derive(Debug)]
pub struct Event {

    id: EventId,
    ts: PktTime,
    payload: EventPayload,

}

impl Event {

    pub fn new(ts: PktTime, payload: EventPayload) -> Self {
        Event {
            id: EventId::new(ts),
            ts: ts,
            payload: payload,
        }
    }

    pub fn send(&self) {
        println!("Got event {:?}", self);
    }

    pub fn kind(&self) -> EventKind {
        match self.payload {
            EventPayload::NetTcpConnectionStart(_) => EventKind::NetTcpConnectionStart,
            EventPayload::NetTcpConnectionEnd(_) => EventKind::NetTcpConnectionEnd,
        }
    }

}
