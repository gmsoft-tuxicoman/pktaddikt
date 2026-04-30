
use crate::stream::{PktStreamProcessor, PktStreamParser, StreamParseResult};
use crate::packet::{PktInfoStack, PktConnInfo, PktTime};
use crate::conntrack::ConntrackDirection;
use crate::proto::nfs::ProtoNfs;
use crate::event::EventId;


use tracing::{debug, trace};
use smallvec::SmallVec;

#[derive(Debug)]
struct ProtoSunRpcCall {
    xid: u32,
    proc: u32,
}

#[derive(Debug, PartialEq)]
enum ProtoSunRpcState {
    Header,
    Body,
}

#[derive(Debug)]
pub struct ProtoSunRpc {

    conn_id: EventId,
    conn_info: PktConnInfo,
    state: ProtoSunRpcState,
    frag_len: usize,
    prog_nfs: Option<ProtoNfs>,
    nfs_version: Option<u32>,
    nfs_calls: SmallVec<[ProtoSunRpcCall; 8]>,
}

impl ProtoSunRpc {

    fn parse_call(&mut self, ts: PktTime, xid: u32, data: &[u8]) -> StreamParseResult {
        
        if data.len() < 32 {
            return StreamParseResult::Invalid;
        }

        // We must parse starting the RPC version

        let version = u32::from_be_bytes(data[0..4].try_into().unwrap());

        if version != 2 {
            return StreamParseResult::Invalid;
        }

        let program = u32::from_be_bytes(data[4..8].try_into().unwrap());

        if program != 100003 {// NFS
            trace!("Unknown RPC program");
            return StreamParseResult::Invalid;
        }

        let prog_version = u32::from_be_bytes(data[8..12].try_into().unwrap());

        let nfs_version = match self.nfs_version {
            Some(old_ver) => {
                if old_ver != prog_version {
                    return StreamParseResult::Invalid;
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
                None => { return StreamParseResult::Done; },
            }
        };

        let proc = u32::from_be_bytes(data[12..16].try_into().unwrap());

        let auth = u32::from_be_bytes(data[16..20].try_into().unwrap());
        let auth_len = u32::from_be_bytes(data[20..24].try_into().unwrap()) as usize;
    
        if data.len() < auth_len + 32 {
            return StreamParseResult::Invalid;
        }

        let verif = u32::from_be_bytes(data[24 + auth_len .. 28 + auth_len].try_into().unwrap());
        let verif_len = u32::from_be_bytes(data[28 + auth_len .. 32 + auth_len ].try_into().unwrap()) as usize;

        let offset = auth_len + verif_len + 32;
        if data.len() < offset {
            return StreamParseResult::Invalid
        }

        let pload = &data[offset..];

        let call = ProtoSunRpcCall {
            xid,
            proc,
        };

        self.nfs_calls.push(call);

        trace!("Call with {} payload for XID {:x}, prog {}, version {}, proc {}", pload.len(), xid, program, prog_version, proc);

        if pload.len() > 0 {
            prog_nfs.parse_call(ts, xid, proc, pload)
        } else {
            StreamParseResult::Ok
        }
    }


    fn parse_reply(&mut self, ts:PktTime, xid: u32, data: &[u8]) -> StreamParseResult {

        let call;

        // Find corresponding NFS call
        if let Some(pos) = self.nfs_calls.iter().position(|c| c.xid == xid) {
            call = self.nfs_calls.swap_remove(pos);
        } else {
            debug!("XID {} for NFS call not found", xid);
            return StreamParseResult::Invalid;
        }

        let prog_nfs = match &self.prog_nfs {
            Some(prog) => prog,
            None => return StreamParseResult::Done,
        };


        if data.len() < 8 {
            return StreamParseResult::Invalid;
        }

        let state = u32::from_be_bytes(data[0..4].try_into().unwrap());

        match state {
            0 => { // ACCEPTED
                if data.len() < 16 {
                    return StreamParseResult::Invalid;
                }
                let verif = u32::from_be_bytes(data[4..8].try_into().unwrap());
                let verif_len = u32::from_be_bytes(data[8..12].try_into().unwrap()) as usize;
                if data.len() < 16 + verif_len {
                    return StreamParseResult::Invalid;
                }
                let accept_state = u32::from_be_bytes(data[12 + verif_len .. 16 + verif_len].try_into().unwrap());

                match accept_state {
                    0 => {}, // SUCCESS
                    _ => { return StreamParseResult::Done; } // Stop parsing for now
                }
                trace!("Reply accepted for XID {:x}", xid);

                let offset = verif_len + 16;
                let pload = &data[offset..];

                if pload.len() > 0 {
                    prog_nfs.parse_reply(ts, xid, call.proc, pload)
                } else {
                    StreamParseResult::Ok
                }

            },
            1 => { // DENIED
                StreamParseResult::Done
            },
            _ => {
                StreamParseResult::Invalid
            },
        }
        
    }
}

impl PktStreamProcessor for ProtoSunRpc {

    fn new(infos: &PktInfoStack) -> Self {
        Self {
            prog_nfs: None,
            nfs_version: None,
            nfs_calls: SmallVec::new(),
            conn_id: infos.get_conn_id().unwrap().clone(),
            conn_info: infos.get_conn_info(),
            state: ProtoSunRpcState::Header,
            frag_len: 0,
        }
    }

    // SUN RPC over TCP
    fn process(&mut self, dir: ConntrackDirection, mut parser: PktStreamParser) -> StreamParseResult {
        
        let ts = parser.timestamp();

        if self.state == ProtoSunRpcState::Header {
            let Some(hdr) = parser.read(4) else {
                return StreamParseResult::NeedData;
            };
            let frag = u32::from_be_bytes(hdr[0..4].try_into().unwrap());
            self.frag_len = (frag & 0x7fffffff) as usize;

            self.state = ProtoSunRpcState::Body;
        }

        // Read the body of the fragment
        let Some(data) = parser.read(self.frag_len) else {
            return StreamParseResult::NeedData;
        };

        self.state = ProtoSunRpcState::Header;
        self.frag_len = 0;

        if data.len() < 8 {
            return StreamParseResult::Invalid;
        }
        let xid = u32::from_be_bytes(data[0..4].try_into().unwrap());
        let msg_type = u32::from_be_bytes(data[4..8].try_into().unwrap());



        match msg_type {
            0 => { self.parse_call(ts, xid, &data[8..]) },
            1 => { self.parse_reply(ts, xid, &data[8..]) },
            _ => {
                trace!("Unknown RPC message type");
                StreamParseResult::Invalid
            }
        }



    }
}

