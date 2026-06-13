use crate::base::{Parser, ParseErr};
use crate::event::{EventStr, EventKind, Event, EventPayload, EventRef};
use crate::messagebus::MessageBus;
use crate::base::UniqueId;
use crate::packet::PktConnInfo;
use crate::proto::sunrpc::xdr::*;
use crate::blob::Blob;

use tracing::debug;
use serde::Serialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;


#[derive(Debug, Serialize)]
pub struct NetNfsV3Base {

    pub conn_id: UniqueId,
    pub client_addr: IpAddr,
    pub client_port: u16,
    pub server_addr: IpAddr,
    pub server_port: u16,
    pub xid: u32,

}

#[derive(Debug, Serialize)]
pub struct NetNfsV3CallLookup {

    #[serde(flatten)]
    pub base: NetNfsV3Base,
    pub parent: Vec<u8>,
    pub name: EventStr,

}

#[derive(Debug, Serialize)]
pub struct NetNfsV3ReplyLookup {

    #[serde(flatten)]
    pub base: NetNfsV3Base,
    pub parent: Vec<u8>,
    pub name: EventStr,
    pub status: u32,
    pub filehandle: Option<Vec<u8>>,
    pub fattr: Option<ProtoNfsV3Fattr>,

}

#[derive(Debug, Serialize)]
pub struct NetNfsV3CallRead {

    #[serde(flatten)]
    pub base: NetNfsV3Base,
    pub filehandle: Vec<u8>,
    pub offset: u64,
    pub count: u32,
}

#[derive(Debug, Serialize)]
pub struct NetNfsV3ReplyRead {

    #[serde(flatten)]
    pub base: NetNfsV3Base,
    pub status: u32,
    pub filehandle: Vec<u8>,
    pub offset: u64,
    pub fattr: Option<ProtoNfsV3Fattr>,
    pub count: Option<u32>,
    pub eof: Option<bool>,

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
    pub fattr: Option<ProtoNfsV3Fattr>,
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
pub struct NetNfsV3CallSymlink {

    #[serde(flatten)]
    pub base: NetNfsV3Base,
    pub parent: Vec<u8>,
    pub linkname: EventStr,
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub to: EventStr,

}

#[derive(Debug, Serialize)]
pub struct NetNfsV3ReplySymlink {

    #[serde(flatten)]
    pub base: NetNfsV3Base,
    pub status: u32,
    pub parent: Vec<u8>,
    pub linkname: EventStr,
    pub filehandle: Option<Vec<u8>>,
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub ctime: Option<Duration>,
    pub to: EventStr,

}

#[derive(Debug, Serialize)]
pub struct NetNfsV3CallRemove {

    #[serde(flatten)]
    pub base: NetNfsV3Base,
    pub parent: Vec<u8>,
    pub name: EventStr,
}

#[derive(Debug, Serialize)]
pub struct NetNfsV3ReplyRemove {

    #[serde(flatten)]
    pub base: NetNfsV3Base,
    pub status: u32,
    pub parent: Vec<u8>,
    pub name: EventStr,
}

#[derive(Debug, Serialize)]
pub struct NetNfsV3CallRmdir {

    #[serde(flatten)]
    pub base: NetNfsV3Base,
    pub parent: Vec<u8>,
    pub name: EventStr,
}

#[derive(Debug, Serialize)]
pub struct NetNfsV3ReplyRmdir {

    #[serde(flatten)]
    pub base: NetNfsV3Base,
    pub status: u32,
    pub parent: Vec<u8>,
    pub name: EventStr,
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

#[derive(Debug, Serialize)]
pub struct NetNfsV3CallLink {

    #[serde(flatten)]
    pub base: NetNfsV3Base,
    pub filehandle: Vec<u8>,
    pub dst_parent: Vec<u8>,
    pub dst_name: EventStr,

}

#[derive(Debug, Serialize)]
pub struct NetNfsV3ReplyLink {

    #[serde(flatten)]
    pub base: NetNfsV3Base,
    pub status: u32,
    pub filehandle: Vec<u8>,
    pub dst_parent: Vec<u8>,
    pub dst_name: EventStr,

}

#[derive(Debug, Serialize)]
pub struct NetNfsV3CallReaddirplus {

    #[serde(flatten)]
    pub base: NetNfsV3Base,
    pub dirhandle: Vec<u8>,

}

#[derive(Debug, Serialize)]
pub struct NetNfsV3ReaddirplusEntry {
    pub name: EventStr,
    pub fattr: Option<ProtoNfsV3Fattr>,
    pub filehandle: Option<Vec<u8>>,

}

#[derive(Debug, Serialize)]
pub struct NetNfsV3ReplyReaddirplus {

    #[serde(flatten)]
    pub base: NetNfsV3Base,
    pub status: u32,
    pub dirhandle: Vec<u8>,
    pub dirattr: Option<ProtoNfsV3Fattr>,
    pub entries: Vec<NetNfsV3ReaddirplusEntry>,

}

pub struct ProtoNfsV3 {

    conn_id: UniqueId,
    conn_info: PktConnInfo,
    blobs: HashMap<Vec<u8>, Blob>,
    server_addr: Option<IpAddr>,
    server_port: Option<u16>,
    client_addr: Option<IpAddr>,
    client_port: Option<u16>,

}

#[derive(Debug, Serialize)]
pub struct ProtoNfsV3Fattr {
    pub r#type: u32,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub used: u64,
    pub atime: Duration,
    pub mtime: Duration,
    pub ctime: Duration,
}

impl ProtoNfsV3 {

    pub fn new(conn_id: &UniqueId, conn_info: PktConnInfo) -> Self {

        Self {
            conn_id: conn_id.clone(),
            conn_info: conn_info.clone(),
            blobs: HashMap::new(),
            server_addr: None,
            server_port: None,
            client_addr: None,
            client_port: None,
        }
    }

    pub fn parse_call<T: Parser>(&mut self, xid: u32, proc: u32, parser: &mut T) -> Result<Option<EventRef>, ParseErr> {

        if self.server_addr.is_none() {
            // ConnInfo will be in the right direction for the first call/reply
            self.client_addr = self.conn_info.src_host;
            self.client_port = self.conn_info.src_port;
            self.server_addr = self.conn_info.dst_host;
            self.server_port = self.conn_info.dst_port;
        }

        match proc {
            1 => Ok(None), // GETATTR
            2 => Ok(None), // SETATTR
            3 => self.lookup_call(xid, parser),
            4 => Ok(None), // ACCESS
            5 => Ok(None), // READLINK
            6 => self.read_call(xid, parser),
            7 => self.write_call(xid, parser),
            8 => self.create_call(xid, parser),
            9 => self.mkdir_call(xid, parser),
            10 => self.symlink_call(xid, parser),
            11 => Ok(None), // MKNOD
            12 => self.remove_call(xid, parser),
            13 => self.rmdir_call(xid, parser),
            14 => self.rename_call(xid, parser),
            15 => self.link_call(xid, parser),
            16 => Ok(None), // READDIR
            17 => self.readdirplus_call(xid, parser),
            18 => Ok(None), // FSSTAT
            19 => Ok(None), // FSINFO
            20 => Ok(None), // PATHCONF
            21 => Ok(None), // COMMIT
            _ => {
                debug!("Unknown NFSv3 procedure called");
                Ok(None)
            }
        }
    }

    pub fn parse_reply<T: Parser>(&mut self, xid: u32, proc: u32, parser: &mut T, event: Option<EventRef>) -> Result<(), ParseErr> {

        if self.server_addr.is_none() {
            // ConnInfo will be in the right direction for the first call/reply
            self.client_addr = self.conn_info.dst_host;
            self.client_port = self.conn_info.dst_port;
            self.server_addr = self.conn_info.src_host;
            self.server_port = self.conn_info.src_port;
        }

        match proc {
            1 => Ok(()), // GETATTR
            2 => Ok(()), // SETATTR
            3 => self.lookup_reply(xid, parser, event),
            4 => Ok(()), // ACCESS
            5 => Ok(()), // READLINK
            6 => self.read_reply(xid, parser, event),
            7 => Ok(()), // WRITE
            8 => self.create_reply(xid, parser, event),
            9 => self.mkdir_reply(xid, parser, event),
            10 => self.symlink_reply(xid, parser, event),
            11 => Ok(()), // MKNOD
            12 => self.remove_reply(xid, parser, event),
            13 => self.rmdir_reply(xid, parser, event),
            14 => self.rename_reply(xid, parser, event),
            15 => self.link_reply(xid, parser, event),
            16 => Ok(()), // READDIR
            17 => self.readdirplus_reply(xid, parser, event),
            18 => Ok(()), // FSSTAT
            19 => Ok(()), // FSINFO
            20 => Ok(()), // PATHCONF
            21 => Ok(()), // COMMIT
            _ => {
                debug!("Unknown NFSv3 procedure replied");
                Ok(())
            }
        }
    }

    fn event_base(&self, xid: u32) -> NetNfsV3Base {
        NetNfsV3Base {
            conn_id: self.conn_id.clone(),
            client_addr: self.client_addr.unwrap(),
            client_port: self.client_port.unwrap(),
            server_addr: self.server_addr.unwrap(),
            server_port: self.server_port.unwrap(),
            xid,
        }
    }

    fn parse_fattr<T: Parser>(parser: &mut T) -> Result<ProtoNfsV3Fattr, ParseErr> {

        let r#type = parser.read_u32_be()?;
        let mode = parser.read_u32_be()?;
        parser.skip_u32()?; // nlink
        let uid = parser.read_u32_be()?;
        let gid = parser.read_u32_be()?;
        let size = parser.read_u64_be()?;
        let used = parser.read_u64_be()?;
        parser.skip_u64s(3)?; // rdev, fsid, fileid

        let atime_sec = parser.read_u32_be()?;
        let atime_nsec = parser.read_u32_be()?;
        let atime = Duration::new(atime_sec as u64, atime_nsec);

        let mtime_sec = parser.read_u32_be()?;
        let mtime_nsec = parser.read_u32_be()?;
        let mtime = Duration::new(mtime_sec as u64, mtime_nsec);

        let ctime_sec = parser.read_u32_be()?;
        let ctime_nsec = parser.read_u32_be()?;
        let ctime = Duration::new(ctime_sec as u64, ctime_nsec);

        Ok(ProtoNfsV3Fattr {
            r#type,
            mode,
            uid,
            gid,
            size,
            used,
            atime,
            mtime,
            ctime,
        })

    }

    fn lookup_call<T: Parser>(&mut self, xid: u32, parser: &mut T) -> Result<Option<EventRef>, ParseErr> {

        if ! MessageBus::event_has_subscribers(EventKind::NetNfsV3CallLookup) &&
           ! MessageBus::event_has_subscribers(EventKind::NetNfsV3ReplyLookup) {
            return Ok(None);
        }

        let timestamp = parser.timestamp();
        let parent = read_opaque(parser)?;
        let name = read_opaque(parser)?;

        let evt_pload = NetNfsV3CallLookup {
            base: self.event_base(xid),
            parent,
            name: name.into(),
        };

        let evt = Event::new(timestamp, EventPayload::NetNfsV3CallLookup(evt_pload));
        MessageBus::publish_event(evt.clone());

        Ok(Some(evt))
    }

    fn lookup_reply<T: Parser>(&mut self, xid: u32, parser: &mut T, call_evt: Option<EventRef>) -> Result<(), ParseErr> {

        if ! MessageBus::event_has_subscribers(EventKind::NetNfsV3ReplyLookup) {
            return Ok(());
        }

        let EventPayload::NetNfsV3CallLookup(ref call_pload) = call_evt.as_ref().unwrap().as_ref().payload else { unreachable!(); };

        let timestamp = parser.timestamp();
        let status = parser.read_u32_be()?;

        let mut filehandle: Option<Vec<u8>> = None;
        let mut fattr: Option<ProtoNfsV3Fattr> = None;

        if status == 0 {

            filehandle = Some(read_opaque(parser)?);

            if parser.read_u32_be()? == 1 { // attributes_follow
                fattr = Some(Self::parse_fattr(parser)?);
            }
        }


        let evt_pload = NetNfsV3ReplyLookup {
            base: self.event_base(xid),
            status,
            parent: call_pload.parent.clone(),
            name: call_pload.name.clone(),
            filehandle,
            fattr,
        };
        let evt = Event::new(timestamp, EventPayload::NetNfsV3ReplyLookup(evt_pload));
        MessageBus::publish_event(evt.clone());

        Ok(())
    }

    fn read_call<T: Parser>(&mut self, xid: u32, parser: &mut T) -> Result<Option<EventRef>, ParseErr> {

        if ! MessageBus::event_has_subscribers(EventKind::NetNfsV3CallRead) &&
           ! MessageBus::event_has_subscribers(EventKind::NetNfsV3ReplyRead) &&
           ! MessageBus::blob_has_subscribers() {
            return Ok(None);
        }

        let timestamp = parser.timestamp();
        let filehandle = read_opaque(parser)?;
        let offset = parser.read_u64_be()?;
        let count = parser.read_u32_be()?;

        let evt_pload = NetNfsV3CallRead {
            base: self.event_base(xid),
            filehandle,
            offset,
            count,
        };

        let evt = Event::new(timestamp, EventPayload::NetNfsV3CallRead(evt_pload));
        MessageBus::publish_event(evt.clone());

        Ok(Some(evt))
    }

    fn read_reply<T: Parser>(&mut self, xid: u32, parser: &mut T, call_evt: Option<EventRef>) -> Result<(), ParseErr> {

        if ! MessageBus::event_has_subscribers(EventKind::NetNfsV3ReplyRead) &&
           ! MessageBus::blob_has_subscribers() {
            return Ok(());
        }

        let EventPayload::NetNfsV3CallRead(ref call_pload) = call_evt.as_ref().unwrap().as_ref().payload else { unreachable!(); };

        let timestamp = parser.timestamp();
        let status = parser.read_u32_be()?;

        let mut fattr: Option<ProtoNfsV3Fattr> = None;
        let mut count: Option<u32> = None;
        let mut eof: Option<bool> = None;


        if parser.read_u32_be()? == 1 { // attributes_follow
            fattr = Some(ProtoNfsV3::parse_fattr(parser)?);
        }

        if status == 0 {
            count = Some(parser.read_u32_be()?);
            eof = Some(parser.read_u32_be()? == 1);
        }


        let evt_pload = NetNfsV3ReplyRead {
            base: self.event_base(xid),
            status,
            filehandle: call_pload.filehandle.clone(),
            offset: call_pload.offset,
            fattr,
            count,
            eof,
        };
        let evt = Event::new(timestamp, EventPayload::NetNfsV3ReplyRead(evt_pload));
        MessageBus::publish_event(evt.clone());

        if status == 0 {
            let len = parser.read_u32_be()?;
            let data = parser.sub_packet(len)?;

            if eof.unwrap() {
                // Try to fetch the blob if it exists
                let mut blob = if let Some(blob) = self.blobs.remove(&call_pload.filehandle) {
                    blob
                } else {
                    // If not create a new one but don't insert it
                    Blob::new(timestamp, Some(evt))
                };
                blob.data(call_pload.offset, data);
            } else {
                // Not eof, create a new one if need and insert it
                let blob = self.blobs.entry(call_pload.filehandle.clone()).or_insert_with(|| Blob::new(timestamp, Some(evt)));
                blob.data(call_pload.offset, data);
            }
        }

        Ok(())

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
        let mut fattr: Option<ProtoNfsV3Fattr> = None;
        if status == 0 {
            if parser.read_u32_be()? == 1 {
                filehandle = Some(read_opaque(parser)?);
            }

            if parser.read_u32_be()? == 1 { // attributes_follow
                fattr = Some(Self::parse_fattr(parser)?);
            }

        }

        let evt_pload = NetNfsV3ReplyCreate {
            base: self.event_base(xid),
            parent: call_pload.parent.clone(),
            filename: call_pload.filename.clone(),
            status,
            filehandle,
            fattr,
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

    fn symlink_call<T: Parser>(&mut self, xid: u32, parser: &mut T) -> Result<Option<EventRef>, ParseErr> {

        if ! MessageBus::event_has_subscribers(EventKind::NetNfsV3CallSymlink) &&
           ! MessageBus::event_has_subscribers(EventKind::NetNfsV3ReplySymlink) {
            return Ok(None);
        }

        let timestamp = parser.timestamp();
        let parent = read_opaque(parser)?;
        let linkname = read_opaque(parser)?;

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
        if parser.read_u32_be()? == 1 {
            parser.skip_u64()?; // size
        }
        if parser.read_u32_be()? == 1 {
            parser.skip_u64()?; // atime
        }
        if parser.read_u32_be()? == 1 {
            parser.skip_u64()?; // mtime
        }

        let to = read_opaque(parser)?;

        let evt_pload = NetNfsV3CallSymlink {
            base: self.event_base(xid),
            parent,
            linkname: linkname.into(),
            mode,
            uid,
            gid,
            to: to.into(),
        };
        let evt = Event::new(timestamp, EventPayload::NetNfsV3CallSymlink(evt_pload));
        MessageBus::publish_event(evt.clone());

        Ok(Some(evt))
    }

    fn symlink_reply<T: Parser>(&mut self, xid: u32, parser: &mut T, call_evt: Option<EventRef>) -> Result<(), ParseErr> {

        if ! MessageBus::event_has_subscribers(EventKind::NetNfsV3ReplySymlink) {
            return Ok(());
        }

        let EventPayload::NetNfsV3CallSymlink(ref call_pload) = call_evt.as_ref().unwrap().as_ref().payload else { unreachable!(); };

        let timestamp = parser.timestamp();
        let status = parser.read_u32_be()?;

        let mut filehandle: Option<Vec<u8>> = None;
        let mut mode: Option<u32> = None;
        let mut uid: Option<u32> = None;
        let mut gid: Option<u32> = None;
        let mut ctime: Option<Duration> = None;

        if parser.read_u32_be()? == 1 { // handle_follows
            filehandle = Some(read_opaque(parser)?);
        }

        if parser.read_u32_be()? == 1 { //attributes_follows
            parser.skip_u32()?; // type, always symlink

            mode = Some(parser.read_u32_be()?);
            parser.skip_u32()?; // nlink
            uid = Some(parser.read_u32_be()?);
            gid = Some(parser.read_u32_be()?);
            parser.skip_u64s(7)?; // size, used, rdev, fsid, fileid, atime, mtime

            let ctime_sec = parser.read_u32_be()?;
            let ctime_nsec = parser.read_u32_be()?;
            ctime = Some(Duration::new(ctime_sec as u64, ctime_nsec));
        }

        let evt_pload = NetNfsV3ReplySymlink {
            base: self.event_base(xid),
            status,
            parent: call_pload.parent.clone(),
            linkname: call_pload.linkname.clone(),
            filehandle,
            mode,
            uid,
            gid,
            ctime,
            to: call_pload.to.clone(),
        };

        let evt = Event::new(timestamp, EventPayload::NetNfsV3ReplySymlink(evt_pload));
        MessageBus::publish_event(evt.clone());


        Ok(())
    }

    fn remove_call<T: Parser>(&mut self, xid: u32, parser: &mut T) -> Result<Option<EventRef>, ParseErr> {

        if ! MessageBus::event_has_subscribers(EventKind::NetNfsV3CallRemove) &&
           ! MessageBus::event_has_subscribers(EventKind::NetNfsV3ReplyRemove) {
            return Ok(None);
        }

        let timestamp = parser.timestamp();
        let parent = read_opaque(parser)?;
        let name = read_opaque(parser)?;

        let evt_pload = NetNfsV3CallRemove {
            base: self.event_base(xid),
            parent,
            name: name.into(),
        };

        let evt = Event::new(timestamp, EventPayload::NetNfsV3CallRemove(evt_pload));
        MessageBus::publish_event(evt.clone());

        Ok(Some(evt))
    }

    fn remove_reply<T: Parser>(&mut self, xid: u32, parser: &mut T, call_evt: Option<EventRef>) -> Result<(), ParseErr> {

        if ! MessageBus::event_has_subscribers(EventKind::NetNfsV3ReplyRemove) {
            return Ok(());
        }

        let EventPayload::NetNfsV3CallRemove(ref call_pload) = call_evt.as_ref().unwrap().as_ref().payload else { unreachable!(); };

        let timestamp = parser.timestamp();
        let status = parser.read_u32_be()?;

        let evt_pload = NetNfsV3ReplyRemove {
            base: self.event_base(xid),
            status,
            parent: call_pload.parent.clone(),
            name: call_pload.name.clone(),
        };

        let evt = Event::new(timestamp, EventPayload::NetNfsV3ReplyRemove(evt_pload));
        MessageBus::publish_event(evt.clone());

        Ok(())
    }

    fn rmdir_call<T: Parser>(&mut self, xid: u32, parser: &mut T) -> Result<Option<EventRef>, ParseErr> {

        if ! MessageBus::event_has_subscribers(EventKind::NetNfsV3CallRmdir) &&
           ! MessageBus::event_has_subscribers(EventKind::NetNfsV3ReplyRmdir) {
            return Ok(None);
        }

        let timestamp = parser.timestamp();
        let parent = read_opaque(parser)?;
        let name = read_opaque(parser)?;

        let evt_pload = NetNfsV3CallRmdir {
            base: self.event_base(xid),
            parent,
            name: name.into(),
        };

        let evt = Event::new(timestamp, EventPayload::NetNfsV3CallRmdir(evt_pload));
        MessageBus::publish_event(evt.clone());

        Ok(Some(evt))
    }

    fn rmdir_reply<T: Parser>(&mut self, xid: u32, parser: &mut T, call_evt: Option<EventRef>) -> Result<(), ParseErr> {

        if ! MessageBus::event_has_subscribers(EventKind::NetNfsV3ReplyRmdir) {
            return Ok(());
        }

        let EventPayload::NetNfsV3CallRmdir(ref call_pload) = call_evt.as_ref().unwrap().as_ref().payload else { unreachable!(); };

        let timestamp = parser.timestamp();
        let status = parser.read_u32_be()?;

        let evt_pload = NetNfsV3ReplyRmdir {
            base: self.event_base(xid),
            status,
            parent: call_pload.parent.clone(),
            name: call_pload.name.clone(),
        };

        let evt = Event::new(timestamp, EventPayload::NetNfsV3ReplyRmdir(evt_pload));
        MessageBus::publish_event(evt.clone());

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

    fn link_call<T: Parser>(&mut self, xid: u32, parser: &mut T) -> Result<Option<EventRef>, ParseErr> {

        if ! MessageBus::event_has_subscribers(EventKind::NetNfsV3CallLink) &&
           ! MessageBus::event_has_subscribers(EventKind::NetNfsV3ReplyLink) {
            return Ok(None);
        }

        let timestamp = parser.timestamp();
        let filehandle = read_opaque(parser)?;
        let dst_parent = read_opaque(parser)?;
        let dst_name = read_opaque(parser)?;

        let evt_pload = NetNfsV3CallLink {
            base: self.event_base(xid),
            filehandle,
            dst_parent,
            dst_name: dst_name.into(),
        };

        let evt = Event::new(timestamp, EventPayload::NetNfsV3CallLink(evt_pload));
        MessageBus::publish_event(evt.clone());

        Ok(Some(evt))
    }

    fn link_reply<T: Parser>(&mut self, xid: u32, parser: &mut T, call_evt: Option<EventRef>) -> Result<(), ParseErr> {

        if ! MessageBus::event_has_subscribers(EventKind::NetNfsV3ReplyLink) {
            return Ok(());
        }

        let EventPayload::NetNfsV3CallLink(ref call_pload) = call_evt.as_ref().unwrap().as_ref().payload else { unreachable!(); };

        let timestamp = parser.timestamp();
        let status = parser.read_u32_be()?;

        let evt_pload = NetNfsV3ReplyLink {
            base: self.event_base(xid),
            status,
            filehandle: call_pload.filehandle.clone(),
            dst_parent: call_pload.dst_parent.clone(),
            dst_name: call_pload.dst_name.clone(),
        };

        let evt = Event::new(timestamp, EventPayload::NetNfsV3ReplyLink(evt_pload));
        MessageBus::publish_event(evt);

        Ok(())
    }
    fn readdirplus_call<T: Parser>(&mut self, xid: u32, parser: &mut T) -> Result<Option<EventRef>, ParseErr> {

        if ! MessageBus::event_has_subscribers(EventKind::NetNfsV3CallReaddirplus) &&
           ! MessageBus::event_has_subscribers(EventKind::NetNfsV3ReplyReaddirplus) {
            return Ok(None);
        }

        let timestamp = parser.timestamp();
        let dirhandle = read_opaque(parser)?;

        let evt_pload = NetNfsV3CallReaddirplus {
            base: self.event_base(xid),
            dirhandle,
        };

        let evt = Event::new(timestamp, EventPayload::NetNfsV3CallReaddirplus(evt_pload));
        MessageBus::publish_event(evt.clone());

        Ok(Some(evt))

    }

    fn readdirplus_reply<T: Parser>(&mut self, xid: u32, parser: &mut T, call_evt: Option<EventRef>) -> Result<(), ParseErr> {

        if ! MessageBus::event_has_subscribers(EventKind::NetNfsV3ReplyReaddirplus) {
            return Ok(());
        }

        let EventPayload::NetNfsV3CallReaddirplus(ref call_pload) = call_evt.as_ref().unwrap().as_ref().payload else { unreachable!(); };

        let timestamp = parser.timestamp();
        let status = parser.read_u32_be()?;

        let mut dirattr: Option<ProtoNfsV3Fattr> = None;

        if parser.read_u32_be()? == 1 { // attribute_follows
            dirattr = Some(ProtoNfsV3::parse_fattr(parser)?);
        }

        parser.skip_u64()?; // verifier

        let mut entries: Vec<NetNfsV3ReaddirplusEntry> = Vec::new();
        while parser.read_u32_be()? == 1 { // value follows

            parser.skip_u64()?; // fileid
            let name = read_opaque(parser)?;
            parser.skip_u64()?; // cookie

            let mut fattr: Option<ProtoNfsV3Fattr> = None;
            if parser.read_u32_be()? == 1 { // attribute follows
                fattr = Some(Self::parse_fattr(parser)?);
            }

            let mut filehandle: Option<Vec<u8>> = None;

            if parser.read_u32_be()? == 1 { // value follows
                filehandle = Some(read_opaque(parser)?);
            }

            let entry = NetNfsV3ReaddirplusEntry {
                name: name.into(),
                fattr,
                filehandle,
            };

            entries.push(entry);
        }

        let evt_pload = NetNfsV3ReplyReaddirplus {
            base: self.event_base(xid),
            status,
            dirhandle: call_pload.dirhandle.clone(),
            dirattr,
            entries,
        };

        let evt = Event::new(timestamp, EventPayload::NetNfsV3ReplyReaddirplus(evt_pload));
        MessageBus::publish_event(evt.clone());

        Ok(())
    }
}
