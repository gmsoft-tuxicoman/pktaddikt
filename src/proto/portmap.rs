use crate::base::{Parser, ParseErr};
use crate::packet::PktConnInfo;
use crate::event::EventId;
use crate::proto::nfs::ProtoNfs;

use tracing::{debug, trace};



pub struct ProtoPortmap {

    conn_id: EventId,
    conn_info: PktConnInfo

}

impl ProtoPortmap {

    pub fn new(conn_id: &EventId, conn_info: PktConnInfo, version: u32) -> Option<Self> {
        if version != 3 {
            debug!("Only support for Portmap version 3 for now ... patch welcome");
            return None;
        }

        Some(Self {
            conn_id: conn_id.clone(),
            conn_info: conn_info.clone()
        })
    }

    pub fn parse_call<T: Parser>(&self, xid: u32, proc: u32, parser: &mut T) -> Result<(), ParseErr> {

        match proc {
            3 => self.getaddr_call(xid, parser),
            _ => Err(ParseErr::Invalid("Unknown PORTMAP procedure called"))
        }
    }

    pub fn parse_reply<T: Parser>(&self, xid: u32, proc: u32, parser: &mut T) -> Result<(), ParseErr> {

        match proc {
            3 => self.getaddr_reply(xid, parser),
            _ => Err(ParseErr::Invalid("Unknown PORTMAP procedure reply")),
        }
    }

    fn getaddr_call<T: Parser>(&self, _xid: u32, parser: &mut T) -> Result<(), ParseErr> {

        let r_prog = parser.read_u32_be()?;
        let r_vers = parser.read_u32_be()?;
        let r_netid = ProtoNfs::read_opaque(parser)?;
        ProtoNfs::skip_opaque(parser)?; // r_addr
        ProtoNfs::skip_opaque(parser)?; // r_owner
        trace!("Requesting program {} version {} over {}", r_prog, r_vers, String::from_utf8_lossy(&r_netid));
        Ok(())
    }

    fn getaddr_reply<T: Parser>(&self, _xid: u32, parser: &mut T) -> Result<(), ParseErr> {
        let addr = ProtoNfs::read_opaque(parser)?;
        trace!("Found program at address {}", String::from_utf8_lossy(&addr));
        Ok(())
    }

}
