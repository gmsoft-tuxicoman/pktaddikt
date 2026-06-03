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
    #[strum(serialize = "net.dhcp.message")]
    NetDhcpMessage,
    #[strum(serialize = "net.tls.clienthello")]
    NetTlsClientHello,
    #[strum(serialize = "net.portmap.call.getport")]
    NetPortmapCallGetport,
    #[strum(serialize = "net.portmap.reply.getport")]
    NetPortmapReplyGetport,
    #[strum(serialize = "net.mount.call.mnt")]
    NetMountCallMnt,
    #[strum(serialize = "net.mount.reply.mnt")]
    NetMountReplyMnt,
    #[strum(serialize = "net.nfsv3.call.lookup")]
    NetNfsV3CallLookup,
    #[strum(serialize = "net.nfsv3.reply.lookup")]
    NetNfsV3ReplyLookup,
    #[strum(serialize = "net.nfsv3.call.read")]
    NetNfsV3CallRead,
    #[strum(serialize = "net.nfsv3.reply.read")]
    NetNfsV3ReplyRead,
    #[strum(serialize = "net.nfsv3.call.write")]
    NetNfsV3CallWrite,
    #[strum(serialize = "net.nfsv3.call.create")]
    NetNfsV3CallCreate,
    #[strum(serialize = "net.nfsv3.reply.create")]
    NetNfsV3ReplyCreate,
    #[strum(serialize = "net.nfsv3.call.mkdir")]
    NetNfsV3CallMkdir,
    #[strum(serialize = "net.nfsv3.reply.mkdir")]
    NetNfsV3ReplyMkdir,
    #[strum(serialize = "net.nfsv3.call.symlink")]
    NetNfsV3CallSymlink,
    #[strum(serialize = "net.nfsv3.reply.symlink")]
    NetNfsV3ReplySymlink,
    #[strum(serialize = "net.nfsv3.call.remove")]
    NetNfsV3CallRemove,
    #[strum(serialize = "net.nfsv3.reply.remove")]
    NetNfsV3ReplyRemove,
    #[strum(serialize = "net.nfsv3.call.rmdir")]
    NetNfsV3CallRmdir,
    #[strum(serialize = "net.nfsv3.reply.rmdir")]
    NetNfsV3ReplyRmdir,
    #[strum(serialize = "net.nfsv3.call.rename")]
    NetNfsV3CallRename,
    #[strum(serialize = "net.nfsv3.reply.rename")]
    NetNfsV3ReplyRename,
    #[strum(serialize = "net.nfsv3.call.link")]
    NetNfsV3CallLink,
    #[strum(serialize = "net.nfsv3.reply.link")]
    NetNfsV3ReplyLink,
    #[strum(serialize = "net.nfsv3.call.readdirplus")]
    NetNfsV3CallReaddirplus,
    #[strum(serialize = "net.nfsv3.reply.readdirplus")]
    NetNfsV3ReplyReaddirplus,
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
    NetDhcpMessage(crate::proto::dhcp::NetDhcpMessage),
    NetTlsClientHello(crate::proto::tls::NetTlsClientHello),
    NetPortmapCallGetport(crate::proto::sunrpc::portmap::NetPortmapCallGetport),
    NetPortmapReplyGetport(crate::proto::sunrpc::portmap::NetPortmapReplyGetport),
    NetMountCallMnt(crate::proto::sunrpc::mount::NetMountCallMnt),
    NetMountReplyMnt(crate::proto::sunrpc::mount::NetMountReplyMnt),
    NetNfsV3CallLookup(crate::proto::sunrpc::nfsv3::NetNfsV3CallLookup),
    NetNfsV3ReplyLookup(crate::proto::sunrpc::nfsv3::NetNfsV3ReplyLookup),
    NetNfsV3CallRead(crate::proto::sunrpc::nfsv3::NetNfsV3CallRead),
    NetNfsV3ReplyRead(crate::proto::sunrpc::nfsv3::NetNfsV3ReplyRead),
    NetNfsV3CallWrite(crate::proto::sunrpc::nfsv3::NetNfsV3CallWrite),
    NetNfsV3CallCreate(crate::proto::sunrpc::nfsv3::NetNfsV3CallCreate),
    NetNfsV3ReplyCreate(crate::proto::sunrpc::nfsv3::NetNfsV3ReplyCreate),
    NetNfsV3CallMkdir(crate::proto::sunrpc::nfsv3::NetNfsV3CallMkdir),
    NetNfsV3ReplyMkdir(crate::proto::sunrpc::nfsv3::NetNfsV3ReplyMkdir),
    NetNfsV3CallSymlink(crate::proto::sunrpc::nfsv3::NetNfsV3CallSymlink),
    NetNfsV3ReplySymlink(crate::proto::sunrpc::nfsv3::NetNfsV3ReplySymlink),
    NetNfsV3CallRemove(crate::proto::sunrpc::nfsv3::NetNfsV3CallRemove),
    NetNfsV3ReplyRemove(crate::proto::sunrpc::nfsv3::NetNfsV3ReplyRemove),
    NetNfsV3CallRmdir(crate::proto::sunrpc::nfsv3::NetNfsV3CallRmdir),
    NetNfsV3ReplyRmdir(crate::proto::sunrpc::nfsv3::NetNfsV3ReplyRmdir),
    NetNfsV3CallRename(crate::proto::sunrpc::nfsv3::NetNfsV3CallRename),
    NetNfsV3ReplyRename(crate::proto::sunrpc::nfsv3::NetNfsV3ReplyRename),
    NetNfsV3CallLink(crate::proto::sunrpc::nfsv3::NetNfsV3CallLink),
    NetNfsV3ReplyLink(crate::proto::sunrpc::nfsv3::NetNfsV3ReplyLink),
    NetNfsV3CallReaddirplus(crate::proto::sunrpc::nfsv3::NetNfsV3CallReaddirplus),
    NetNfsV3ReplyReaddirplus(crate::proto::sunrpc::nfsv3::NetNfsV3ReplyReaddirplus),
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
            EventPayload::NetDhcpMessage(_) => EventKind::NetDhcpMessage,
            EventPayload::NetTlsClientHello(_) => EventKind::NetTlsClientHello,
            EventPayload::NetPortmapCallGetport(_) => EventKind::NetPortmapCallGetport,
            EventPayload::NetPortmapReplyGetport(_) => EventKind::NetPortmapReplyGetport,
            EventPayload::NetMountCallMnt(_) => EventKind::NetMountCallMnt,
            EventPayload::NetMountReplyMnt(_) => EventKind::NetMountReplyMnt,
            EventPayload::NetNfsV3CallLookup(_) => EventKind::NetNfsV3CallLookup,
            EventPayload::NetNfsV3ReplyLookup(_) => EventKind::NetNfsV3ReplyLookup,
            EventPayload::NetNfsV3CallRead(_) => EventKind::NetNfsV3CallRead,
            EventPayload::NetNfsV3ReplyRead(_) => EventKind::NetNfsV3ReplyRead,
            EventPayload::NetNfsV3CallWrite(_) => EventKind::NetNfsV3CallWrite,
            EventPayload::NetNfsV3CallCreate(_) => EventKind::NetNfsV3CallCreate,
            EventPayload::NetNfsV3ReplyCreate(_) => EventKind::NetNfsV3ReplyCreate,
            EventPayload::NetNfsV3CallMkdir(_) => EventKind::NetNfsV3CallMkdir,
            EventPayload::NetNfsV3ReplyMkdir(_) => EventKind::NetNfsV3ReplyMkdir,
            EventPayload::NetNfsV3CallSymlink(_) => EventKind::NetNfsV3CallSymlink,
            EventPayload::NetNfsV3ReplySymlink(_) => EventKind::NetNfsV3ReplySymlink,
            EventPayload::NetNfsV3CallRemove(_) => EventKind::NetNfsV3CallRemove,
            EventPayload::NetNfsV3ReplyRemove(_) => EventKind::NetNfsV3ReplyRemove,
            EventPayload::NetNfsV3CallRmdir(_) => EventKind::NetNfsV3CallRmdir,
            EventPayload::NetNfsV3ReplyRmdir(_) => EventKind::NetNfsV3ReplyRmdir,
            EventPayload::NetNfsV3CallRename(_) => EventKind::NetNfsV3CallRename,
            EventPayload::NetNfsV3ReplyRename(_) => EventKind::NetNfsV3ReplyRename,
            EventPayload::NetNfsV3CallLink(_) => EventKind::NetNfsV3CallLink,
            EventPayload::NetNfsV3ReplyLink(_) => EventKind::NetNfsV3ReplyLink,
            EventPayload::NetNfsV3CallReaddirplus(_) => EventKind::NetNfsV3CallReaddirplus,
            EventPayload::NetNfsV3ReplyReaddirplus(_) => EventKind::NetNfsV3ReplyReaddirplus,
            EventPayload::NetNfsV4CallExchangeId(_) => EventKind::NetNfsV4CallExchangeId,
            EventPayload::NetNfsV4ReplyExchangeId(_) => EventKind::NetNfsV4ReplyExchangeId,
            EventPayload::NetNfsV4CallCreateSession(_) => EventKind::NetNfsV4CallCreateSession,
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
#[derive(Debug, Clone)]
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
