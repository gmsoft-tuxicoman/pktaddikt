use crate::base::{Parser, ParseErr};
use crate::packet::PktConnInfo;
use crate::base::UniqueId;
use crate::proto::sunrpc::xdr::*;
use crate::event::{EventRef, EventKind, EventStr, Event, EventPayload};
use crate::messagebus::MessageBus;

use tracing::{debug, trace};
use std::net::IpAddr;
use serde::Serialize;


#[derive(Debug, Serialize)]
pub struct NetMountCallMnt {
    pub conn_id: UniqueId,
    pub client_addr: IpAddr,
    pub client_port: u16,
    pub server_addr: IpAddr,
    pub server_port: u16,
    pub path: EventStr,
}

#[derive(Debug, Serialize)]
pub struct NetMountReplyMnt {
    pub conn_id: UniqueId,
    pub client_addr: IpAddr,
    pub client_port: u16,
    pub server_addr: IpAddr,
    pub server_port: u16,
    pub status: u32,
    pub path: EventStr,
    pub filehandle: Option<Vec<u8>>,
}


pub struct ProtoMount {

    conn_id: UniqueId,
    conn_info: PktConnInfo

}

impl ProtoMount {

    pub fn new(conn_id: &UniqueId, conn_info: PktConnInfo, version: u32) -> Option<Self> {

        if version > 3 {
            debug!("Only support for Mount version up to 3 for now ... patch welcome");
            return None;
        }

        Some(Self {
            conn_id: conn_id.clone(),
            conn_info: conn_info.clone()
        })
    }

    pub fn parse_call<T: Parser>(&self, xid: u32, proc: u32, parser: &mut T) -> Result<Option<EventRef>, ParseErr> {

        match proc {
            1 => self.mnt_call(xid, parser),
            3 => self.umnt_call(xid, parser),
            _ => Err(ParseErr::Invalid("Unknown MOUNT procedure called"))
        }
    }

    pub fn parse_reply<T: Parser>(&self, xid: u32, proc: u32, parser: &mut T, event: Option<EventRef>) -> Result<(), ParseErr> {

        match proc {
            1 => self.mnt_reply(xid, parser, event),
            3 => Ok(()), // UMNT
            _ => Err(ParseErr::Invalid("Unknown MOUNT procedure reply")),
        }
    }

    fn mnt_call<T: Parser>(&self, _xid: u32, parser: &mut T) -> Result<Option<EventRef>, ParseErr> {

        if ! MessageBus::event_has_subscribers(EventKind::NetMountCallMnt) &&
           ! MessageBus::event_has_subscribers(EventKind::NetMountReplyMnt) {
               return Ok(None);
        }

        let timestamp = parser.timestamp();
        let path = read_opaque(parser)?;
        trace!("Requesting mount {}", String::from_utf8_lossy(&path));
        let evt_pload = NetMountCallMnt {
            conn_id: self.conn_id.clone(),
            client_addr: self.conn_info.src_host.unwrap(),
            client_port: self.conn_info.src_port.unwrap(),
            server_addr: self.conn_info.dst_host.unwrap(),
            server_port: self.conn_info.dst_port.unwrap(),
            path: path.into(),
        };

        let evt = Event::new(timestamp, EventPayload::NetMountCallMnt(evt_pload));
        MessageBus::publish_event(evt.clone());
        Ok(Some(evt))
    }

    fn mnt_reply<T: Parser>(&self, _xid: u32, parser: &mut T, call_evt: Option<EventRef>) -> Result<(), ParseErr> {

        if ! MessageBus::event_has_subscribers(EventKind::NetMountReplyMnt) {
            return Ok(());
        }

        let EventPayload::NetMountCallMnt(ref call_pload) = call_evt.as_ref().unwrap().as_ref().payload else { unreachable!(); };

        let timestamp = parser.timestamp();
        let status = parser.read_u32_be()?;
        let mut filehandle: Option<Vec<u8>> = None;
        if status == 0 {
            filehandle = Some(read_opaque(parser)?);
        }

        let evt_pload = NetMountReplyMnt {
            status,
            conn_id: self.conn_id.clone(),
            client_addr: call_pload.client_addr,
            client_port: call_pload.client_port,
            server_addr: call_pload.server_addr,
            server_port: call_pload.server_port,
            path: call_pload.path.clone(),
            filehandle,
        };

        let evt = Event::new(timestamp, EventPayload::NetMountReplyMnt(evt_pload));
        MessageBus::publish_event(evt);

        Ok(())
    }

    fn umnt_call<T: Parser>(&self, _xid: u32, parser: &mut T) -> Result<Option<EventRef>, ParseErr> {
        let path = read_opaque(parser)?;
        trace!("Requesting umount {}", String::from_utf8_lossy(&path));
        Ok(None)
    }
}
