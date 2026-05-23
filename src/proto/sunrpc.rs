pub mod xdr;
pub mod portmap;
pub mod nfsv3;
pub mod nfsv4;
pub mod mount;

use crate::base::{Parser, ParseErr};
use crate::proto::ProtoPktProcessor;
use crate::stream::{PktStreamProcessor, PktStreamParser};
use crate::packet::{Packet, PktInfoStack, PktConnInfo};
use crate::conntrack::{ConntrackDirection, ConntrackTableUnique};
use crate::proto::sunrpc::nfsv3::ProtoNfsV3;
use crate::proto::sunrpc::nfsv4::ProtoNfsV4;
use crate::proto::sunrpc::portmap::ProtoPortmap;
use crate::proto::sunrpc::mount::ProtoMount;
use crate::base::UniqueId;
use crate::config::Config;


use serde::Deserialize;
use tracing::{debug, trace};
use smallvec::SmallVec;

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SunRpcConfig {
    pub max_call_queue: usize,
}

impl Default for SunRpcConfig {
    fn default() -> Self {
        Self {
            max_call_queue: 8,
        }
    }
}

struct ProtoSunRpcCall {
    xid: u32,
    proc: u32,
}

#[derive(PartialEq)]
enum ProtoSunRpcTcpState {
    Header,
    Body,
}

pub struct ProtoSunRpc {

    conn_id: UniqueId,
    conn_info: PktConnInfo,
    prog: Option<ProtoSunRpcProg>,
    version: Option<u32>,
    calls: SmallVec<[ProtoSunRpcCall; 8]>,
    prog_id: u32,
}

enum ProtoSunRpcProg {
    NfsV3(ProtoNfsV3),
    NfsV4(ProtoNfsV4),
    Portmap(ProtoPortmap),
    Mount(ProtoMount),
}

impl ProtoSunRpc {

    pub fn new(infos: &PktInfoStack) -> Self {
        Self {
            prog: None,
            version: None,
            calls: SmallVec::new(),
            conn_id: infos.get_conn_id().unwrap().clone(),
            conn_info: infos.get_conn_info(),
            prog_id: 0,
        }
    }

    fn parse_call<T: Parser>(&mut self, xid: u32, mut parser: T) -> Result<(), ParseErr> {
        
        // We must parse starting the RPC version

        let version = parser.read_u32_be()?;

        if version != 2 {
            return Err(ParseErr::Invalid("Invalid RPC version"));
        }

        let program = parser.read_u32_be()?;
        let prog_version = parser.read_u32_be()?;


        // First time
        if self.prog_id == 0 {
            self.prog_id = program;
            self.prog = match program {
                100000 => match ProtoPortmap::new(&self.conn_id, self.conn_info, prog_version) {
                    Some(p) => Some(ProtoSunRpcProg::Portmap(p)),
                    None => None,
                },
                100003 => match prog_version {
                    3 => Some(ProtoSunRpcProg::NfsV3(ProtoNfsV3::new(&self.conn_id, self.conn_info))),
                    4 => Some(ProtoSunRpcProg::NfsV4(ProtoNfsV4::new(&self.conn_id, self.conn_info))),
                    _ => return Err(ParseErr::Invalid("Invalid NFS version")),
                },

                100005 => match ProtoMount::new(&self.conn_id, self.conn_info, prog_version) {
                    Some(p) => Some(ProtoSunRpcProg::Mount(p)),
                    None => None,
                }
                _ => {
                    debug!("RPC program not supported");
                    return Err(ParseErr::Stop);
                }
            }
        }
        let mut prog = match &mut self.prog {
            Some(p) => p,
            None => return Err(ParseErr::Stop)
        };

        let prog_version = match self.version {
            Some(old_ver) => {
                if old_ver != prog_version {
                    return Err(ParseErr::Invalid("Program version different than earlier version"));
                }
                old_ver
            },
            None => {
                self.version = Some(prog_version);
                prog_version
            }
        };

        let proc = parser.read_u32_be()?;

        parser.skip_u32()?; // auth_type
        let auth_len = parser.read_u32_be()?;
        parser.skip(auth_len)?; // auth_pload

        parser.skip_u32()?; // verif_type
        let verif_len = parser.read_u32_be()?;
        parser.skip(verif_len)?;

        let call = ProtoSunRpcCall {
            xid,
            proc,
        };

        self.calls.push(call);

        let cfg = Config::get();
        if self.calls.len() > cfg.proto.sunrpc.max_call_queue {
            debug!("RPC call queue length bigger than  {}. Dropping last call.", cfg.proto.sunrpc.max_call_queue);
            self.calls.pop();
        }

        trace!("Call with {} payload for XID {:x}, prog {}, version {}, proc {}", parser.remaining_len(), xid, program, prog_version, proc);

        if parser.remaining_len() > 0 {
            match &mut prog {
                ProtoSunRpcProg::Portmap(p) => p.parse_call(xid, proc, &mut parser),
                ProtoSunRpcProg::NfsV3(p) => p.parse_call(xid, proc, &mut parser),
                ProtoSunRpcProg::NfsV4(p) => p.parse_call(xid, proc, &mut parser),
                ProtoSunRpcProg::Mount(p) => p.parse_call(xid, proc, &mut parser),
            }
        } else {
            Ok(())
        }
    }


    fn parse_reply<T: Parser>(&mut self, xid: u32, mut parser: T) -> Result<(), ParseErr> {

        let call;

        // Find corresponding RPC call
        if let Some(pos) = self.calls.iter().position(|c| c.xid == xid) {
            call = self.calls.swap_remove(pos);
        } else {
            debug!("XID {} for RPC call not found", xid);
            return Err(ParseErr::Invalid("Matching RPC call not found base on XID"));
        }

        let mut prog = match &mut self.prog {
            Some(p) => p,
            None => return Err(ParseErr::Stop),
        };


        let state = parser.read_u32_be()?;

        match state {
            0 => { // ACCEPTED
                parser.skip_u32()?; // verif
                let verif_len = parser.read_u32_be()?;
                parser.skip(verif_len)?;
                let accept_state = parser.read_u32_be()?;

                match accept_state {
                    0 => {}, // SUCCESS
                    _ => { return Err(ParseErr::Stop); } // Stop parsing for now
                }
                trace!("Reply accepted for XID {:x}", xid);


                if parser.remaining_len() > 0 {
                    match &mut prog {
                        ProtoSunRpcProg::Portmap(p) => p.parse_reply(xid, call.proc, &mut parser),
                        ProtoSunRpcProg::NfsV3(p) => p.parse_reply(xid, call.proc, &mut parser),
                        ProtoSunRpcProg::NfsV4(p) => p.parse_reply(xid, call.proc, &mut parser),
                        ProtoSunRpcProg::Mount(p) => p.parse_reply(xid, call.proc, &mut parser),
                    }
                } else {
                    return Ok(());
                }

            },
            1 => { // DENIED
                Err(ParseErr::Stop)
            },
            _ => {
                Err(ParseErr::Invalid("Invalid RPC reply state"))
            },
        }
        
    }


    pub fn process_message<T: Parser>(&mut self, mut parser: T) -> Result<(), ParseErr> {

        let xid = parser.read_u32_be()?;
        let msg_type = parser.read_u32_be()?;


        // This should not fail since we checked with has_len() earlier
        match msg_type {
            0 => { self.parse_call(xid, parser) },
            1 => { self.parse_reply(xid, parser) },
            _ => {
                Err(ParseErr::Invalid("Unknown RPC message type"))
            }
        }
    }
}

pub struct ProtoSunRpcUdp {

    ct: ConntrackTableUnique,
}

impl ProtoPktProcessor for ProtoSunRpcUdp {

    fn new() -> Self {
        Self {
            ct: ConntrackTableUnique::new()
        }
    }

    // SunRPC over UDP
    fn process(&mut self, pkt: &mut Packet, infos: &mut PktInfoStack) -> Result<(), ParseErr> {

        let info = infos.proto_last();
        let (ce, _) = self.ct.get(info.parent_ce().unwrap());

        let mut ce_locked = ce.lock().unwrap();
        let rpc = ce_locked.get_or_insert_with(|| Box::new(ProtoSunRpc::new(infos))).downcast_mut::<ProtoSunRpc>().unwrap();


        rpc.process_message(pkt.to_parser())

    }

}

pub struct ProtoSunRpcTcp {
    rpc: ProtoSunRpc,
    state: ProtoSunRpcTcpState,
    frag_len: u32,
}

impl PktStreamProcessor for ProtoSunRpcTcp {


    fn new(infos: &PktInfoStack) -> Self {
        Self {
            rpc: ProtoSunRpc::new(infos),
            state: ProtoSunRpcTcpState::Header,
            frag_len: 0,
        }
    }


    // SUN RPC over TCP
    fn process(&mut self, _dir: ConntrackDirection, mut parser: PktStreamParser) -> Result<(), ParseErr> {
        
        if self.state == ProtoSunRpcTcpState::Header {
            self.frag_len = parser.read_u32_be()? & 0x7fffffff;
            self.state = ProtoSunRpcTcpState::Body;
        }

        if self.frag_len < 24 { 
            return Err(ParseErr::Invalid("Fragment length too small"));
        }

        // Make sure the fragment is complete
        let msg_parser = parser.sub_packet(self.frag_len)?;

        self.state = ProtoSunRpcTcpState::Header;
        self.frag_len = 0;

        self.rpc.process_message(msg_parser)

    }
}

