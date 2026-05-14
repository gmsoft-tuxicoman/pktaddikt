use crate::base::{Parser, ParseErr};
use crate::packet::PktConnInfo;
use crate::event::EventId;
use crate::proto::Protocols;
use crate::base::atoi;
use crate::expectation::{ExpectationTable, ExpectationEntry, ExpectationType};
use crate::proto::sunrpc::xdr::*;

use tracing::{debug, trace};
use std::net::Ipv4Addr;
use std::time::Duration;



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
        let r_netid = read_opaque(parser)?;
        skip_opaque(parser)?; // r_addr
        skip_opaque(parser)?; // r_owner
        trace!("Requesting program {} version {} over {}", r_prog, r_vers, String::from_utf8_lossy(&r_netid));
        Ok(())
    }

    fn getaddr_reply<T: Parser>(&self, _xid: u32, parser: &mut T) -> Result<(), ParseErr> {
        let addr = read_opaque(parser)?;

        let addr_str = String::from_utf8_lossy(&addr);
        let parts_vec  = addr_str.rsplitn(3, '.').collect::<Vec<_>>();
        let parts = parts_vec.as_slice();

        if parts.len() != 3 {
            return Err(ParseErr::Invalid("Invalid or unknown universal address format"));
        }

        let port_low = atoi(parts[0].as_bytes());
        let port_high = atoi(parts[1].as_bytes());
        let port = match (port_low, port_high) {
            (Some(l), Some(h)) => (h << 8) + l,
            _ => return Err(ParseErr::Invalid("Could not parse universal address port")),
        };

        let Ok(dst): Result<Ipv4Addr, _> = parts[2].parse() else {
            return Err(ParseErr::Invalid("Could not parse universal address ip part"));
        };

        // Build the expectation
        let expt = ExpectationEntry::new(Protocols::SunRpc, true)
                    .add(ExpectationType::Udp{ dport: port as u16, sport: None })
                    .add(ExpectationType::Ipv4{ daddr: dst, saddr: None });

        // FIXME add config for duration length
        ExpectationTable::add(Protocols::Udp, expt, parser.timestamp(), Duration::from_secs(60));

        trace!("Found program at address {} and port {}", parts[2], port);
        Ok(())
    }

}
