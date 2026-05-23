use crate::base::{Parser, ParseErr};
use crate::event::{EventStr, EventKind, Event, EventPayload};
use crate::messagebus::MessageBus;
use crate::base::UniqueId;
use crate::packet::PktConnInfo;
use crate::proto::sunrpc::xdr::*;
use crate::blob::Blob;

use tracing::{debug, trace};
use serde::Serialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;


#[derive(Debug, Serialize)]
pub struct NetNfsV3Base {

    pub conn_id: UniqueId,
    pub client: Option<IpAddr>,
    pub server: Option<IpAddr>,
    pub xid: u32,

}

#[derive(Debug, Serialize)]
pub struct NetNfsV3CallWrite {

    #[serde(flatten)]
    pub base: NetNfsV3Base,
    pub filehandle: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub struct NetNfsV3CallCreate {

    #[serde(flatten)]
    pub base: NetNfsV3Base,
    pub parent: Vec<u8>,
    pub filename: EventStr,
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct NetNfsV3ReplyCreate {

    #[serde(flatten)]
    pub base: NetNfsV3Base,
    pub status: u32,
    pub filehandle: Option<Vec<u8>>,
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub ctime: Option<Duration>,
}

pub struct ProtoNfsV3 {

    conn_id: UniqueId,
    conn_info: PktConnInfo,
    blobs: HashMap<Vec<u8>, Blob>,
    server: Option<IpAddr>,
    client: Option<IpAddr>,

}


impl ProtoNfsV3 {

    pub fn new(conn_id: &UniqueId, conn_info: PktConnInfo) -> Self {

        Self {
            conn_id: conn_id.clone(),
            conn_info: conn_info.clone(),
            blobs: HashMap::new(),
            server: None,
            client: None,
        }
    }

    pub fn parse_call<T: Parser>(&mut self, xid: u32, proc: u32, parser: &mut T) -> Result<(), ParseErr> {

        if self.server.is_none() {
            // ConnInfo will be in the right direction for the first call/reply
            self.client = self.conn_info.src_host.clone();
            self.server = self.conn_info.dst_host.clone();
        }

        match proc {
            1 => Ok(()), // GETATTR
            2 => Ok(()), // SETATTR
            3 => Ok(()), // LOOKUP
            4 => Ok(()), // ACCESS
            5 => Ok(()), // READLINK
            6 => Ok(()), // READ
            7 => self.write_call(xid, parser),
            8 => self.create_call(xid, parser),
            9 => Ok(()), // MKDIR
            10 => Ok(()), // SYMLINK
            12 => Ok(()), // REMOVE
            13 => Ok(()), // RMDIR
            14 => Ok(()), // RENAME
            15 => Ok(()), // LINK
            16 => Ok(()), // READDIR
            18 => Ok(()), // FSSTAT
            19 => Ok(()), // FSINFO
            20 => Ok(()), // PATHCONF
            _ => Err(ParseErr::Invalid("Unknown NFSv3 procedure called"))
        }
    }

    pub fn parse_reply<T: Parser>(&mut self, xid: u32, proc: u32, parser: &mut T) -> Result<(), ParseErr> {

        if self.server.is_none() {
            // ConnInfo will be in the right direction for the first call/reply
            self.client = self.conn_info.dst_host.clone();
            self.server = self.conn_info.src_host.clone();
        }

        match proc {
            1 => Ok(()), // GETATTR
            2 => Ok(()), // SETATTR
            3 => Ok(()), // LOOKUP
            4 => Ok(()), // ACCESS
            5 => Ok(()), // READLINK
            6 => Ok(()), // READ
            7 => Ok(()), // WRITE
            8 => self.create_reply(xid, parser),
            9 => Ok(()), // MKDIR
            10 => Ok(()), // SYMLINK
            12 => Ok(()), // REMOVE
            13 => Ok(()), // RMDIR
            14 => Ok(()), // RENAME
            15 => Ok(()), // LINK
            16 => Ok(()), // READDIR
            18 => Ok(()), // FSSTAT
            19 => Ok(()), // FSINFO
            20 => Ok(()), // PATHCONF
            _ => Err(ParseErr::Invalid("Unknown NFSv3 procedure replied"))
        }
    }

    fn event_base(&self, xid: u32) -> NetNfsV3Base {
        NetNfsV3Base {
            conn_id: self.conn_id.clone(),
            server: self.server.clone(),
            client: self.client.clone(),
            xid,
        }
    }

    fn create_call<T: Parser>(&mut self, xid: u32, parser: &mut T) -> Result<(), ParseErr> {

        if ! MessageBus::event_has_subscribers(EventKind::NetNfsV3CallCreate) {
            return Ok(());
        }

        let timestamp = parser.timestamp();
        let parent = read_opaque(parser)?;
        let name = read_opaque(parser)?;
        let mut mode: Option<u32> = None;
        let mut uid: Option<u32> = None;
        let mut gid: Option<u32> = None;

        if parser.read_u32_be()? < 2 { // obj_attribute only present for UNCHECKED and GUARDED
            if parser.read_u32_be()? == 1 { // mode
                mode = Some(parser.read_u32_be()?);
            }
            if parser.read_u32_be()? == 1 { // uid
                uid = Some(parser.read_u32_be()?);
            }
            if parser.read_u32_be()? == 1 { // gid
                gid = Some(parser.read_u32_be()?);
            }

        }

        let evt_pload = NetNfsV3CallCreate {
            base: self.event_base(xid),
            parent,
            filename: name.into(),
            mode,
            uid,
            gid,
        };

        let evt = Event::new(timestamp, EventPayload::NetNfsV3CallCreate(evt_pload));
        MessageBus::publish_event(evt.clone());

        Ok(())
    }

    fn create_reply<T: Parser>(&mut self, xid: u32, parser: &mut T) -> Result<(), ParseErr> {

        if ! MessageBus::event_has_subscribers(EventKind::NetNfsV3ReplyCreate) {
            return Ok(());
        }

        let timestamp = parser.timestamp();
        let status = parser.read_u32_be()?;

        let mut filehandle: Option<Vec<u8>> = None;
        let mut mode: Option<u32> = None;
        let mut uid: Option<u32> = None;
        let mut gid: Option<u32> = None;
        let mut ctime: Option<Duration> = None;
        if status == 0 {
            if parser.read_u32_be()? == 1 {
                filehandle = Some(read_opaque(parser)?);
            }

            if parser.read_u32_be()? == 1 { // attributes_follow
                parser.skip_u32()?; // file type
                mode = Some(parser.read_u32_be()?);
                parser.skip_u32()?; // nlink
                uid = Some(parser.read_u32_be()?);
                gid = Some(parser.read_u32_be()?);
                parser.skip_u64s(5)?; // size, used, specdata, fsid, fileid, atime, mtime

                let ctime_sec = parser.read_u32_be()?;
                let ctime_nsec = parser.read_u32_be()?;
                ctime = Some(Duration::new(ctime_sec as u64, ctime_nsec));
            }

        }

        let evt_pload = NetNfsV3ReplyCreate {
            base: self.event_base(xid),
            status,
            filehandle,
            mode,
            uid,
            gid,
            ctime,
        };

        let evt = Event::new(timestamp, EventPayload::NetNfsV3ReplyCreate(evt_pload));
        MessageBus::publish_event(evt.clone());

        Ok(())
    }
    fn write_call<T: Parser>(&mut self, xid: u32, parser: &mut T) -> Result<(), ParseErr> {

        if ! MessageBus::event_has_subscribers(EventKind::NetNfsV3CallWrite) &&
           ! MessageBus::blob_has_subscribers() {
            // Nobody is listening to this
            return Ok(());
        }

        let timestamp = parser.timestamp();
        let file = read_opaque(parser)?;
        let offset = parser.read_u64_be()?;
        parser.skip_u32s(2)?; // count, stable
        let len = parser.read_u32_be()?;

        let data = parser.sub_packet(len)?;

        let evt_pload = NetNfsV3CallWrite {
            base: self.event_base(xid),
            filehandle: file.clone(),
        };

        let evt = Event::new(timestamp, EventPayload::NetNfsV3CallWrite(evt_pload));
        MessageBus::publish_event(evt.clone());

        let blob = self.blobs.entry(file).or_insert_with(|| Blob::new(timestamp, Some(evt)));
        blob.data(offset, data);

        Ok(())

    }
}
