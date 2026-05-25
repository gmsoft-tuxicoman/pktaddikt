use crate::base::{Parser, ParseErr, UniqueId, atoi};
use crate::packet::PktConnInfo;
use crate::proto::Protocols;
use crate::expectation::{ExpectationTable, ExpectationEntry, ExpectationType};
use crate::proto::sunrpc::xdr::*;
use crate::event::{EventRef, Event, EventPayload};
use crate::messagebus::MessageBus;

use tracing::{debug, trace};
use std::net::{Ipv4Addr, IpAddr};
use std::time::Duration;
use serde::Serialize;


#[derive(Debug, Serialize)]
pub struct NetPortmapCallGetport {

    pub conn_id: UniqueId,
    pub client: Option<IpAddr>,
    pub server: Option<IpAddr>,
    pub program: u32,
    pub version: u32,
    pub protocol: u32,
    pub port: u32,

}

#[derive(Debug, Serialize)]
pub struct NetPortmapReplyGetport {

    pub conn_id: UniqueId,
    pub client: Option<IpAddr>,
    pub server: Option<IpAddr>,
    pub program: u32,
    pub version: u32,
    pub protocol: u32,
    pub port: u32,

}

pub struct ProtoPortmap {

    conn_id: UniqueId,
    conn_info: PktConnInfo,
    client: Option<IpAddr>,
    server: Option<IpAddr>,
    version: u32,

}

impl ProtoPortmap {

    pub fn new(conn_id: &UniqueId, conn_info: PktConnInfo, version: u32) -> Option<Self> {
        if version != 2 && version != 3 {
            debug!("Invalid portmap version");
            return None;
        }

        Some(Self {
            conn_id: conn_id.clone(),
            conn_info: conn_info.clone(),
            version,
            client: None,
            server: None,
        })
    }

    pub fn parse_call<T: Parser>(&mut self, xid: u32, proc: u32, parser: &mut T) -> Result<Option<EventRef>, ParseErr> {

        if self.server.is_none() {
            self.client = self.conn_info.src_host.clone();
            self.server = self.conn_info.dst_host.clone();
        }

        match self.version {
            2 => match proc {
                3 => self.getport_call(xid, parser),
                _ => Err(ParseErr::Invalid("Unknown PORTMAP procedure called"))
            },
            3 => match proc {
                3 => self.getaddr_call(xid, parser),
                _ => Err(ParseErr::Invalid("Unknown RPCBIND procedure called"))
            },
            _ => unreachable!()
        }
    }

    pub fn parse_reply<T: Parser>(&mut self, xid: u32, proc: u32, parser: &mut T, event: Option<EventRef>) -> Result<(), ParseErr> {

        if self.server.is_none() {
            self.client = self.conn_info.dst_host.clone();
            self.server = self.conn_info.src_host.clone();
        }

        match self.version {

            2 => match proc {
                3 => self.getport_reply(xid, parser, event),
                _ => Err(ParseErr::Invalid("Unknown PORTMAP procedure replied"))
            },
            3 => match proc {
                3 => self.getaddr_reply(xid, parser, event),
                _ => Err(ParseErr::Invalid("Unknown PORTMAP procedure reply")),
            },
            _ => unreachable!()
        }
    }

    fn getport_call<T: Parser>(&self, _xid: u32, parser: &mut T) -> Result<Option<EventRef>, ParseErr> {

        // We don't check if the event is being listened to because we need to add the expectation
        // in the reply anyway

        let timestamp = parser.timestamp();
        let program = parser.read_u32_be()?;
        let version = parser.read_u32_be()?;
        let protocol = parser.read_u32_be()?;
        let port = parser.read_u32_be()?;

        let evt_pload = NetPortmapCallGetport {
            conn_id: self.conn_id.clone(),
            client: self.client.clone(),
            server: self.server.clone(),
            program,
            version,
            protocol,
            port
        };

        let evt = Event::new(timestamp, EventPayload::NetPortmapCallGetport(evt_pload));
        MessageBus::publish_event(evt.clone());

        Ok(Some(evt))
    }

    fn getport_reply<T: Parser>(&self, _xid: u32, parser: &mut T, event: Option<EventRef>) -> Result<(), ParseErr> {

        let EventPayload::NetPortmapCallGetport(ref pload) = event.as_ref().unwrap().as_ref().payload else { unreachable!(); };

        let Some(IpAddr::V4(server)) = self.server else { return Ok(()); };

        let timestamp = parser.timestamp();
        let port = parser.read_u32_be()?;

        let evt_pload = NetPortmapReplyGetport {
            conn_id: self.conn_id.clone(),
            client: self.client.clone(),
            server: self.server.clone(),
            program: pload.program,
            version: pload.version,
            protocol: pload.protocol,
            port,
        };

        let evt = Event::new(timestamp, EventPayload::NetPortmapReplyGetport(evt_pload));
        MessageBus::publish_event(evt);

        let proto_expt = match pload.protocol {
            6 => ExpectationType::Tcp{ dport: port as u16, sport: None },
            17 => ExpectationType::Udp{ dport: port as u16, sport: None },
            _ => return Err(ParseErr::Invalid("Invalid protocol"))
        };

        // Build the expectation
        let expt = ExpectationEntry::new(Protocols::SunRpc, true)
                    .add(proto_expt)
                    .add(ExpectationType::Ipv4{ daddr: server, saddr: None });

        // FIXME add config for duration length
        ExpectationTable::add(Protocols::Udp, expt, parser.timestamp(), Duration::from_secs(60));

        Ok(())
    }

    fn getaddr_call<T: Parser>(&self, _xid: u32, parser: &mut T) -> Result<Option<EventRef>, ParseErr> {

        let r_prog = parser.read_u32_be()?;
        let r_vers = parser.read_u32_be()?;
        let r_netid = read_opaque(parser)?;
        skip_opaque(parser)?; // r_addr
        skip_opaque(parser)?; // r_owner
        trace!("Requesting program {} version {} over {}", r_prog, r_vers, String::from_utf8_lossy(&r_netid));
        Ok(None)
    }

    fn getaddr_reply<T: Parser>(&self, _xid: u32, parser: &mut T, _event: Option<EventRef>) -> Result<(), ParseErr> {
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
