use crate::base::{Parser, ParseErr};
use crate::event::{EventStr, EventKind, Event, EventPayload, EventRef};
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
    pub size: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct NetNfsV3ReplyCreate {

    #[serde(flatten)]
    pub base: NetNfsV3Base,
    pub status: u32,
    pub parent: Vec<u8>,
    pub filename: EventStr,
    pub filehandle: Option<Vec<u8>>,
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub size: Option<u64>,
    pub ctime: Option<Duration>,
}

#[derive(Debug, Serialize)]
pub struct NetNfsV3CallMkdir {

    #[serde(flatten)]
    pub base: NetNfsV3Base,
    pub parent: Vec<u8>,
    pub dirname: EventStr,
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,

}

#[derive(Debug, Serialize)]
pub struct NetNfsV3ReplyMkdir {

    #[serde(flatten)]
    pub base: NetNfsV3Base,
    pub status: u32,
    pub parent: Vec<u8>,
    pub dirhandle: Option<Vec<u8>>,
    pub dirname: EventStr,
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub ctime: Option<Duration>,
}

#[derive(Debug, Serialize)]
pub struct NetNfsV3CallRename {

    #[serde(flatten)]
    pub base: NetNfsV3Base,
    pub from_fh: Vec<u8>,
    pub from_name: EventStr,
    pub to_fh: Vec<u8>,
    pub to_name: EventStr,

}

#[derive(Debug, Serialize)]
pub struct NetNfsV3ReplyRename {

    #[serde(flatten)]
    pub base: NetNfsV3Base,
    pub status: u32,
    pub from_fh: Vec<u8>,
    pub from_name: EventStr,
    pub to_fh: Vec<u8>,
    pub to_name: EventStr,

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

    pub fn parse_call<T: Parser>(&mut self, xid: u32, proc: u32, parser: &mut T) -> Result<Option<EventRef>, ParseErr> {

        if self.server.is_none() {
            // ConnInfo will be in the right direction for the first call/reply
            self.client = self.conn_info.src_host.clone();
            self.server = self.conn_info.dst_host.clone();
        }

        match proc {
            1 => Ok(None), // GETATTR
            2 => Ok(None), // SETATTR
            3 => Ok(None), // LOOKUP
            4 => Ok(None), // ACCESS
            5 => Ok(None), // READLINK
            6 => Ok(None), // READ
            7 => self.write_call(xid, parser),
            8 => self.create_call(xid, parser),
            9 => self.mkdir_call(xid, parser),
            10 => Ok(None), // SYMLINK
            12 => Ok(None), // REMOVE
            13 => Ok(None), // RMDIR
            14 => self.rename_call(xid, parser),
            15 => Ok(None), // LINK
            16 => Ok(None), // READDIR
            18 => Ok(None), // FSSTAT
            19 => Ok(None), // FSINFO
            20 => Ok(None), // PATHCONF
            _ => Err(ParseErr::Invalid("Unknown NFSv3 procedure called"))
        }
    }

    pub fn parse_reply<T: Parser>(&mut self, xid: u32, proc: u32, parser: &mut T, event: Option<EventRef>) -> Result<(), ParseErr> {

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
            8 => self.create_reply(xid, parser, event),
            9 => self.mkdir_reply(xid, parser, event),
            10 => Ok(()), // SYMLINK
            12 => Ok(()), // REMOVE
            13 => Ok(()), // RMDIR
            14 => self.rename_reply(xid, parser, event),
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

    fn create_call<T: Parser>(&mut self, xid: u32, parser: &mut T) -> Result<Option<EventRef>, ParseErr> {

        if ! MessageBus::event_has_subscribers(EventKind::NetNfsV3CallCreate) &&
           ! MessageBus::event_has_subscribers(EventKind::NetNfsV3ReplyCreate) {
            return Ok(None);
        }

        let timestamp = parser.timestamp();
        let parent = read_opaque(parser)?;
        let name = read_opaque(parser)?;
        let mut mode: Option<u32> = None;
        let mut uid: Option<u32> = None;
        let mut gid: Option<u32> = None;
        let mut size: Option<u64> = None;

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
            if parser.read_u32_be()? == 1 { // size
                size = Some(parser.read_u64_be()?);
            }

        }

        let evt_pload = NetNfsV3CallCreate {
            base: self.event_base(xid),
            parent,
            filename: name.into(),
            mode,
            uid,
            gid,
            size,
        };

        let evt = Event::new(timestamp, EventPayload::NetNfsV3CallCreate(evt_pload));
        MessageBus::publish_event(evt.clone());

        Ok(Some(evt))
    }

    fn create_reply<T: Parser>(&mut self, xid: u32, parser: &mut T, call_evt: Option<EventRef>) -> Result<(), ParseErr> {

        if ! MessageBus::event_has_subscribers(EventKind::NetNfsV3ReplyCreate) {
            return Ok(());
        }

        let EventPayload::NetNfsV3CallCreate(ref call_pload) = call_evt.as_ref().unwrap().as_ref().payload else { unreachable!(); };

        let timestamp = parser.timestamp();
        let status = parser.read_u32_be()?;

        let mut filehandle: Option<Vec<u8>> = None;
        let mut mode: Option<u32> = None;
        let mut uid: Option<u32> = None;
        let mut gid: Option<u32> = None;
        let mut size: Option<u64> = None;
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
                size = Some(parser.read_u64_be()?);
                parser.skip_u64s(4)?; // size, used, specdata, fsid, fileid, atime, mtime

                let ctime_sec = parser.read_u32_be()?;
                let ctime_nsec = parser.read_u32_be()?;
                ctime = Some(Duration::new(ctime_sec as u64, ctime_nsec));
            }

        }

        let evt_pload = NetNfsV3ReplyCreate {
            base: self.event_base(xid),
            parent: call_pload.parent.clone(),
            filename: call_pload.filename.clone(),
            status,
            filehandle,
            mode,
            uid,
            gid,
            size,
            ctime,
        };

        let evt = Event::new(timestamp, EventPayload::NetNfsV3ReplyCreate(evt_pload));
        MessageBus::publish_event(evt);

        Ok(())
    }
    fn write_call<T: Parser>(&mut self, xid: u32, parser: &mut T) -> Result<Option<EventRef>, ParseErr> {

        if ! MessageBus::event_has_subscribers(EventKind::NetNfsV3CallWrite) &&
           ! MessageBus::blob_has_subscribers() {
            // Nobody is listening to this
            return Ok(None);
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

        Ok(None)

    }

    fn mkdir_call<T: Parser>(&mut self, xid: u32, parser: &mut T) -> Result<Option<EventRef>, ParseErr> {

        if ! MessageBus::event_has_subscribers(EventKind::NetNfsV3CallMkdir) &&
           ! MessageBus::event_has_subscribers(EventKind::NetNfsV3ReplyMkdir) {
            return Ok(None);
        }

        let timestamp = parser.timestamp();
        let parent = read_opaque(parser)?;
        let dirname = read_opaque(parser)?;

        let mut mode: Option<u32> = None;
        let mut uid: Option<u32> = None;
        let mut gid: Option<u32> = None;

        if parser.read_u32_be()? == 1 {
            mode = Some(parser.read_u32_be()?);
        }
        if parser.read_u32_be()? == 1 {
            uid = Some(parser.read_u32_be()?);
        }
        if parser.read_u32_be()? == 1 {
            gid = Some(parser.read_u32_be()?);
        }

        let evt_pload = NetNfsV3CallMkdir {
            base: self.event_base(xid),
            parent,
            dirname: dirname.into(),
            mode,
            uid,
            gid,
        };

        let evt = Event::new(timestamp, EventPayload::NetNfsV3CallMkdir(evt_pload));
        MessageBus::publish_event(evt.clone());

        Ok(Some(evt))
    }

    fn mkdir_reply<T: Parser>(&mut self, xid: u32, parser: &mut T, call_evt: Option<EventRef>) -> Result<(), ParseErr> {

        if ! MessageBus::event_has_subscribers(EventKind::NetNfsV3ReplyMkdir) {
            return Ok(());
        }

        let EventPayload::NetNfsV3CallMkdir(ref call_pload) = call_evt.as_ref().unwrap().as_ref().payload else { unreachable!(); };

        let timestamp = parser.timestamp();
        let status = parser.read_u32_be()?;

        let mut dirhandle: Option<Vec<u8>> = None;
        let mut mode: Option<u32> = None;
        let mut uid: Option<u32> = None;
        let mut gid: Option<u32> = None;
        let mut ctime: Option<Duration> = None;

        if status == 0 {
            if parser.read_u32_be()? == 1 {
                dirhandle = Some(read_opaque(parser)?);
            }

            if parser.read_u32_be()? == 1 { // attributes_follow
                parser.skip_u32()?; // type, always directory
                mode = Some(parser.read_u32_be()?);
                parser.skip_u32()?; // nlink
                uid = Some(parser.read_u32_be()?);
                gid = Some(parser.read_u32_be()?);
                parser.skip_u64s(7)?; // size, used, rdev, fsid, fileid, atime, mtime

                let ctime_sec = parser.read_u32_be()?;
                let ctime_nsec = parser.read_u32_be()?;
                ctime = Some(Duration::new(ctime_sec as u64, ctime_nsec));

            }
        }

        let evt_pload = NetNfsV3ReplyMkdir {
            base: self.event_base(xid),
            status,
            parent: call_pload.parent.clone(),
            dirhandle,
            dirname: call_pload.dirname.clone(),
            mode,
            uid,
            gid,
            ctime,
        };

        let evt = Event::new(timestamp, EventPayload::NetNfsV3ReplyMkdir(evt_pload));
        MessageBus::publish_event(evt);

        Ok(())
    }
    fn rename_call<T: Parser>(&mut self, xid: u32, parser: &mut T) -> Result<Option<EventRef>, ParseErr> {

        if ! MessageBus::event_has_subscribers(EventKind::NetNfsV3CallRename) &&
           ! MessageBus::event_has_subscribers(EventKind::NetNfsV3ReplyRename) {
            return Ok(None);
        }

        let timestamp = parser.timestamp();
        let from_fh = read_opaque(parser)?;
        let from_name = read_opaque(parser)?;
        let to_fh = read_opaque(parser)?;
        let to_name = read_opaque(parser)?;

        let evt_pload = NetNfsV3CallRename {
            base: self.event_base(xid),
            from_fh,
            from_name: from_name.into(),
            to_fh,
            to_name: to_name.into(),
        };

        let evt = Event::new(timestamp, EventPayload::NetNfsV3CallRename(evt_pload));
        MessageBus::publish_event(evt.clone());

        Ok(Some(evt))
    }

    fn rename_reply<T: Parser>(&mut self, xid: u32, parser: &mut T, call_evt: Option<EventRef>) -> Result<(), ParseErr> {

        if ! MessageBus::event_has_subscribers(EventKind::NetNfsV3ReplyRename) {
            return Ok(());
        }

        let EventPayload::NetNfsV3CallRename(ref call_pload) = call_evt.as_ref().unwrap().as_ref().payload else { unreachable!(); };

        let timestamp = parser.timestamp();
        let status = parser.read_u32_be()?;

        let evt_pload = NetNfsV3ReplyRename {
            base: self.event_base(xid),
            status,
            from_fh: call_pload.from_fh.clone(),
            from_name: call_pload.from_name.clone(),
            to_fh: call_pload.to_fh.clone(),
            to_name: call_pload.to_name.clone(),
        };

        let evt = Event::new(timestamp, EventPayload::NetNfsV3ReplyRename(evt_pload));
        MessageBus::publish_event(evt);

        Ok(())
    }
}
