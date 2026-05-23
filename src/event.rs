use crate::packet::PktTime;
use crate::base::UniqueId;

use std::fmt::Debug;
use strum_macros::{EnumString, AsRefStr, EnumCount, EnumIter, IntoStaticStr};
use serde::{Serialize, Serializer};
use std::ops::Deref;
use std::borrow::Cow;
use std::sync::Arc;

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
    #[strum(serialize = "net.nfsv3.call.write")]
    NetNfsV3CallWrite,
    #[strum(serialize = "net.nfsv3.call.create")]
    NetNfsV3CallCreate,
    #[strum(serialize = "net.nfsv3.reply.create")]
    NetNfsV3ReplyCreate,
    #[strum(serialize = "net.nfsv4.call.exchange_id")]
    NetNfsV4CallExchangeId,
    #[strum(serialize = "net.nfsv4.reply.exchange_id")]
    NetNfsV4ReplyExchangeId,
    #[strum(serialize = "net.nfsv4.call.create_session")]
    NetNfsV4CallCreateSession,
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
    NetNfsV3CallCreate(crate::proto::sunrpc::nfsv3::NetNfsV3CallCreate),
    NetNfsV3ReplyCreate(crate::proto::sunrpc::nfsv3::NetNfsV3ReplyCreate),
    NetNfsV3CallWrite(crate::proto::sunrpc::nfsv3::NetNfsV3CallWrite),
    NetNfsV4CallExchangeId(crate::proto::sunrpc::nfsv4::NetNfsV4CallExchangeId),
    NetNfsV4ReplyExchangeId(crate::proto::sunrpc::nfsv4::NetNfsV4ReplyExchangeId),
    NetNfsV4CallCreateSession(crate::proto::sunrpc::nfsv4::NetNfsV4CallCreateSession),
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
            EventPayload::NetNfsV4CallExchangeId(_) => EventKind::NetNfsV4CallExchangeId,
            EventPayload::NetNfsV4ReplyExchangeId(_) => EventKind::NetNfsV4ReplyExchangeId,
            EventPayload::NetNfsV4CallCreateSession(_) => EventKind::NetNfsV4CallCreateSession,
            EventPayload::NetNfsV3CallWrite(_) => EventKind::NetNfsV3CallWrite,
            EventPayload::NetNfsV3CallCreate(_) => EventKind::NetNfsV3CallCreate,
            EventPayload::NetNfsV3ReplyCreate(_) => EventKind::NetNfsV3ReplyCreate,
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

    pub fn new(ts: PktTime, payload: EventPayload) -> EventRef {
        let kind = payload.kind();
        Arc::new(Event {
            event_id: UniqueId::new(ts),
            ts: ts,
            kind: kind.into(),
            payload: payload,
        })
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
