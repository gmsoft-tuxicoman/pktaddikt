
use crate::packet::PktTime;
use crate::base::UniqueId;
use crate::messagebus::MessageBus;

use std::fmt::Debug;
use strum_macros::{EnumString, AsRefStr, EnumCount, EnumIter, IntoStaticStr};
use serde::{Serialize, Serializer};
use std::ops::Deref;
use std::borrow::Cow;

#[repr(usize)]
#[derive(Debug, Copy, Clone, PartialEq, EnumString, AsRefStr, EnumCount, EnumIter, IntoStaticStr)]
pub enum EventKind {

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

        MessageBus::publish_event(self);

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
