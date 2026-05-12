use crate::base::{Parser, ParseErr};
use crate::proto::ProtoPktProcessor;
use crate::stream::{PktStreamProcessor, PktStreamParser};
use crate::packet::{Packet, PktInfoStack, PktConnInfo};
use crate::conntrack::{ConntrackDirection, ConntrackTableUnique};
use crate::proto::nfs::ProtoNfs;
use crate::event::EventId;


use tracing::{debug, trace};
use smallvec::SmallVec;

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

    conn_id: EventId,
    conn_info: PktConnInfo,
    prog_nfs: Option<ProtoNfs>,
    nfs_version: Option<u32>,
    nfs_calls: SmallVec<[ProtoSunRpcCall; 8]>,
}

impl ProtoSunRpc {

    pub fn new(infos: &PktInfoStack) -> Self {
        Self {
            prog_nfs: None,
            nfs_version: None,
            nfs_calls: SmallVec::new(),
            conn_id: infos.get_conn_id().unwrap().clone(),
            conn_info: infos.get_conn_info(),
        }
    }

    fn parse_call<T: Parser>(&mut self, xid: u32, mut parser: T) -> Result<(), ParseErr> {
        
        // We must parse starting the RPC version

        let version = parser.read_u32_be()?;

        if version != 2 {
            return Err(ParseErr::Invalid("Invalid RPC version"));
        }

        let program = parser.read_u32_be()?;

        if program != 100003 {// NFS
            return Err(ParseErr::Invalid("Unsupported RPC program"));
        }

        let prog_version = parser.read_u32_be()?;

        let nfs_version = match self.nfs_version {
            Some(old_ver) => {
                if old_ver != prog_version {
                    return Err(ParseErr::Invalid("Program version different than earlier version"));
                }
                old_ver
            },
            None => {
                self.nfs_version = Some(prog_version);
                prog_version
            }
        };

        let prog_nfs = match &self.prog_nfs {
            Some(prog) => prog,
            None => match ProtoNfs::new(&self.conn_id, self.conn_info, nfs_version) {
                Some(prog) => {
                    self.prog_nfs = Some(prog);
                    &self.prog_nfs.as_ref().unwrap()
                },
                None => { return Err(ParseErr::Stop); },
            }
        };

        let proc = parser.read_u32_be()?;

        parser.skip_u32()?; // auth_type
        let auth_len = parser.read_u32_be()? as usize;
        parser.skip(auth_len)?; // auth_pload

        parser.skip_u32()?; // verif_type
        let verif_len = parser.read_u32_be()? as usize;
        parser.skip(verif_len)?;

        let call = ProtoSunRpcCall {
            xid,
            proc,
        };

        self.nfs_calls.push(call);

        trace!("Call with {} payload for XID {:x}, prog {}, version {}, proc {}", parser.remaining_len(), xid, program, prog_version, proc);

        if parser.remaining_len() > 0 {
            prog_nfs.parse_call(xid, proc, &mut parser)
        } else {
            Ok(())
        }
    }


    fn parse_reply<T: Parser>(&mut self, xid: u32, mut parser: T) -> Result<(), ParseErr> {

        let call;

        // Find corresponding NFS call
        if let Some(pos) = self.nfs_calls.iter().position(|c| c.xid == xid) {
            call = self.nfs_calls.swap_remove(pos);
        } else {
            debug!("XID {} for NFS call not found", xid);
            return Err(ParseErr::Invalid("Matching NFS call not found base on XID"));
        }

        let prog_nfs = match &self.prog_nfs {
            Some(prog) => prog,
            None => return Err(ParseErr::Stop),
        };


        let state = parser.read_u32_be()?;

        match state {
            0 => { // ACCEPTED
                parser.skip_u32()?; // verif
                let verif_len = parser.read_u32_be()? as usize;
                parser.skip(verif_len)?;
                let accept_state = parser.read_u32_be()?;

                match accept_state {
                    0 => {}, // SUCCESS
                    _ => { return Err(ParseErr::Stop); } // Stop parsing for now
                }
                trace!("Reply accepted for XID {:x}", xid);


                if parser.remaining_len() > 0 {
                    prog_nfs.parse_reply(xid, call.proc, &mut parser)
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

impl ProtoSunRpcUdp {

    pub fn new() -> Self {
        Self {
            ct: ConntrackTableUnique::new()
        }
    }
}

impl ProtoPktProcessor for ProtoSunRpcUdp {

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
    frag_len: usize,
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
            self.frag_len = (parser.read_u32_be()? & 0x7fffffff) as usize;
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

