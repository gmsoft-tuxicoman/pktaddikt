use crate::base::{Parser, ParseErr};
use crate::packet::PktConnInfo;
use crate::event::EventId;
use crate::proto::sunrpc::xdr::*;

use tracing::{debug, trace};



pub struct ProtoMount {

    conn_id: EventId,
    conn_info: PktConnInfo

}

impl ProtoMount {

    pub fn new(conn_id: &EventId, conn_info: PktConnInfo, version: u32) -> Option<Self> {

        if version > 3 {
            debug!("Only support for Mount version up to 3 for now ... patch welcome");
            return None;
        }

        Some(Self {
            conn_id: conn_id.clone(),
            conn_info: conn_info.clone()
        })
    }

    pub fn parse_call<T: Parser>(&self, xid: u32, proc: u32, parser: &mut T) -> Result<(), ParseErr> {

        match proc {
            1 => self.mnt_call(xid, parser),
            3 => self.umnt_call(xid, parser),
            _ => Err(ParseErr::Invalid("Unknown MOUNT procedure called"))
        }
    }

    pub fn parse_reply<T: Parser>(&self, xid: u32, proc: u32, parser: &mut T) -> Result<(), ParseErr> {

        match proc {
            1 => self.mnt_reply(xid, parser),
            3 => Ok(()), // UMNT
            _ => Err(ParseErr::Invalid("Unknown MOUNT procedure reply")),
        }
    }

    fn mnt_call<T: Parser>(&self, _xid: u32, parser: &mut T) -> Result<(), ParseErr> {

        let path = read_opaque(parser)?;
        trace!("Requesting mount {}", String::from_utf8_lossy(&path));
        Ok(())
    }

    fn mnt_reply<T: Parser>(&self, _xid: u32, _parser: &mut T) -> Result<(), ParseErr> {
        // No need to parse for now
        Ok(())
    }

    fn umnt_call<T: Parser>(&self, _xid: u32, parser: &mut T) -> Result<(), ParseErr> {
        let path = read_opaque(parser)?;
        trace!("Requesting umount {}", String::from_utf8_lossy(&path));
        Ok(())
    }
}
