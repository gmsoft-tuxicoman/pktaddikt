use crate::stream::StreamParseResult;
use crate::event::{EventId, EventBus, EventStr, EventKind, Event, EventPayload};
use crate::packet::{PktConnInfo, PktTime};

use tracing::{debug, trace};
use serde::Serialize;


#[derive(Debug, Serialize)]
struct NetNfsBase {

    conn_id: EventId,
    #[serde(flatten)]
    conn_info: PktConnInfo,
    xid: u32,

}

#[derive(Debug, Serialize)]
pub struct NetNfsExchangeIdCall {

    #[serde(flatten)]
    base: NetNfsBase,
    co_ownerid: EventStr,
    nii_domain: Option<EventStr>,
    nii_name: Option<EventStr>,
}

#[derive(Debug, Serialize)]
pub struct NetNfsExchangeIdReply {

    #[serde(flatten)]
    base: NetNfsBase,
    so_major_id: EventStr,
    eir_server_scope: EventStr,
    nii_domain: Option<EventStr>,
    nii_name: Option<EventStr>,
}

#[derive(Debug, Serialize)]
pub struct NetNfsCreateSessionCall {

    #[serde(flatten)]
    base: NetNfsBase,
    machine_name: Option<EventStr>,
    uid: Option<u32>,
    gid: Option<u32>,

}

struct NfsData<'a> {
    data: &'a [u8],
    off: usize,
}

impl<'a> NfsData<'a> {

    const NFS4_VERIFIER_SIZE: usize = 8;
    const NFS4_SESSIONID_SIZE: usize = 16;

    fn new(data: &'a [u8], off: usize) -> Self {
        Self {
            data,
            off,
        }
    }

    fn read_u32(&mut self) -> Option<u32> {
        if self.data.len() < self.off + 4 {
            return None;
        }

        self.off += 4;
        Some(u32::from_be_bytes(self.data[self.off - 4 .. self.off].try_into().unwrap()))
    }

    fn read_u64(&mut self) -> Option<u64> {
        if self.data.len() < self.off + 8 {
            return None;
        }

        self.off += 8;
        Some(u64::from_be_bytes(self.data[self.off - 8 .. self.off].try_into().unwrap()))
    }

    fn skip_u32(&mut self, num: usize) -> Option<()> {
        self.skip(4 * num)
    }

    fn skip_u64(&mut self, num: usize) -> Option<()> {
        self.skip(8 * num)
    }

    fn read_opaque(&mut self) -> Option<&'a [u8]> {

        let len = self.read_u32()? as usize;
        self.off += len;
        if self.data.len() < self.off {
            return None;
        }

        let ret = Some(&self.data[self.off - len .. self.off]);

        // Opaque are aligned on 4 bytes
        self.off = (self.off + 3) & !3;
        ret
    }

    fn skip_opaque(&mut self) -> Option<()> {

        let len = self.read_u32()? as usize;
        self.off += len;
        if self.data.len() < self.off {
            return None;
        }

        self.off = (self.off + 3) & !3;
        Some(())
    }

    fn skip(&mut self, len: usize) -> Option<()> {
        self.off += len;
        if self.data.len() < self.off {
            return None;
        }

        Some(())
    }

}


#[derive(Debug)]
pub struct ProtoNfs {

    conn_id: EventId,
    conn_info: PktConnInfo,
    version_major: u32,

}


impl ProtoNfs {

    pub fn new(conn_id: &EventId, conn_info: PktConnInfo, version: u32) -> Option<Self> {
        if version != 4 {
            trace!("Only support for NFSv4 for now ... patch welcome");
            return None;
        }

        Some(Self {
            conn_id: conn_id.clone(),
            conn_info: conn_info.clone(),
            version_major: version,
        })
    }

    pub fn parse_call(&self, ts: PktTime, xid: u32, proc: u32, data: &[u8]) -> StreamParseResult {

        let mut nfs_data = NfsData::new(data, 0);

        let ret = match proc {
            1 => self.compound_call(ts, xid, &mut nfs_data),
            _ => None,
        };

        match ret {
            Some(_) => StreamParseResult::Ok,
            None => StreamParseResult::Invalid,
        }

    }

    pub fn parse_reply(&self, ts: PktTime, xid: u32, proc: u32, data: &[u8]) -> StreamParseResult {


        let mut nfs_data = NfsData::new(data, 0);

        let ret = match proc {
            1 => self.compound_reply(ts, xid, &mut nfs_data),
            _ => None,
        };

        match ret {
            Some(_) => StreamParseResult::Ok,
            None => StreamParseResult::Invalid,
        }

    }

    fn compound_call(&self, ts: PktTime, xid: u32, data: &mut NfsData) -> Option<()> {

        // tag
        data.skip_opaque()?;

        let minorversion = data.read_u32()?;
        let numops = data.read_u32()?;

        trace!("Got CALL COMPOUND NFS4.{} with {} operation(s)", minorversion, numops );

        for _ in 0..numops {

            let opcode = data.read_u32()?;
            match opcode {
                3 => self.access_call(ts, xid, data),
                8 => self.delegreturn_call(ts, xid, data),
                9 => self.getattr_call(ts, xid, data),
                10 => self.getfh_call(ts, xid, data),
                15 => self.lookup_call(ts, xid, data),
                18 => self.open_call(ts, xid, data),
                22 => self.putfh_call(ts, xid, data),
                24 => self.putrootfh_call(ts, xid, data),
                26 => self.readdir_call(ts, xid, data),
                42 => self.exchange_id_call(ts, xid, data),
                43 => self.create_session_call(ts, xid, data),
                44 => self.destroy_session_call(ts, xid, data),
                46 => self.get_dir_delegation_call(ts, xid, data),
                52 => self.secinfo_no_name_call(ts, xid, data),
                53 => self.sequence_call(ts, xid, data),
                57 => self.destroy_client_id_call(ts, xid, data),
                58 => self.reclaim_complete_call(ts, xid, data),
                68 => self.read_plus_call(ts, xid, data),
                _ => {
                    debug!("Unknown NFS opcode {}", opcode);
                    return None;
                }
            }?;
        }

        Some(())

    }

    fn compound_reply(&self, ts: PktTime, xid: u32, data: &mut NfsData) -> Option<()> {

        let status = data.read_u32()?;
        data.skip_opaque()?; // tag

        let numops = data.read_u32()?;

        trace!("Got REPLY COMPOUND with status {} and {} operation(s)", status, numops );

        for _ in 0..numops {

            let opcode = data.read_u32()?;
            let status = data.read_u32()?;
            match opcode {
                3 => self.access_reply(ts, xid, status, data),
                8 => self.delegreturn_reply(ts, xid, status, data),
                9 => self.getattr_reply(ts, xid, status, data),
                10 => self.getfh_reply(ts, xid, status, data),
                15 => self.lookup_reply(ts, xid, status, data),
                18 => self.open_reply(ts, xid, status, data),
                22 => self.putfh_reply(ts, xid, status, data),
                24 => self.putrootfh_reply(ts, xid, status, data),
                26 => self.readdir_reply(ts, xid, status, data),
                42 => self.exchange_id_reply(ts, xid, status, data),
                43 => self.create_session_reply(ts, xid, status, data),
                44 => self.destroy_session_reply(ts, xid, status, data),
                46 => self.get_dir_delegation_reply(ts, xid, status, data),
                52 => self.secinfo_no_name_reply(ts, xid, status, data),
                53 => self.sequence_reply(ts, xid, status, data),
                57 => self.destroy_client_id_reply(ts, xid, status, data),
                58 => self.reclaim_complete_reply(ts, xid, status, data),
                68 => self.read_plus_reply(ts, xid, status, data),
                _ => {
                    debug!("Unknown NFS opcode {}", opcode);
                    return None;
                }
            }?;
        }

        Some(())

    }

    fn exchange_id_call(&self, ts: PktTime, xid: u32, data: &mut NfsData) -> Option<()> {

        trace!("EXCHANGE_ID CALL");

        let co_ownerid;
        let mut nii_domain = None;
        let mut nii_name = None;

        { // eia_clientowner

            // co_verifier
            data.skip(NfsData::NFS4_VERIFIER_SIZE)?;
            // co_ownerid
            co_ownerid = data.read_opaque()?;
            trace!("Found owner id : {}", String::from_utf8_lossy(co_ownerid));
        }

        { // eia_flags
            data.skip_u32(1)?;
        }

        { // eia_state_protect
            let spa_how = data.read_u32()?;
            match spa_how {
                0 => {}, // SP4_NONE
                1 => { data.skip_u32(2)?; }, // SP4_MACH_CRED (spo_must_enforce, spo_must_allow)
                2 => { // SP4_SSV
                    data.skip_u32(2)?; // ssp_ops { spo_must_enforce, spo_must_allow}
                    data.skip_opaque()?; // ssp_hash_algs
                    data.skip_opaque()?; // ssp_encr_algs
                    data.skip_u32(2)?; // ssp_window, ssp_num_gss_handles
                },
                _ => { return None; }
            }

        }

        { // eia_client_impl_id

            let num = data.read_u32()?;

            if num == 1 { // Max 1 element
                // nii_domain
                nii_domain = Some(data.read_opaque()?);
                trace!("Found implementor domain : {}", String::from_utf8_lossy(nii_domain.unwrap()));
                // nii_name
                nii_name = Some(data.read_opaque()?);
                trace!("Found implentation name : {}", String::from_utf8_lossy(nii_name.unwrap()));
                // nii_data
                data.skip_u32(3)?;
            } else if num > 1 {
                return None;
            }
        }

        if EventBus::has_subscribers(EventKind::NetNfsExchangeIdCall) {

            let evt_pload = NetNfsExchangeIdCall {
                base: NetNfsBase {
                    conn_id: self.conn_id.clone(),
                    conn_info: self.conn_info.clone(),
                    xid,
                },
                co_ownerid: co_ownerid.into(),
                nii_domain: nii_domain.map(Into::into),
                nii_name: nii_name.map(Into::into),
            };

            let evt = Event::new(ts, EventPayload::NetNfsExchangeIdCall(evt_pload));
            evt.send();
        }
        Some(())
    }

    fn exchange_id_reply(&self, ts: PktTime, xid: u32, status: u32, data: &mut NfsData) -> Option<()> {

        trace!("EXCHANGE_ID REPLY");

        if status != 0 {
            // Not OK
            return Some(());
        }

        let eir_clientid = data.read_u64()?;

        data.skip_u32(2); // eir_sequenceid, eir_flags

        { // eir_state_protect
            let spr_how = data.read_u32()?;
            match spr_how {
                0 => {}, // SP4_NONE
                1 => { data.skip_u32(2)?; }, // SP4_MACH_CRED (spo_must_enforce, spo_must_allow)
                2 => { // SP4_SSV
                    data.skip_u32(2)?; // ssi_ops { spo_must_enforce, spo_must_allow}
                    data.skip_u32(4)?; // spi_hash_alg, spi_encr_alg, spi_ssv_len, spi_window
                    data.skip_u32(2)?; // ssp_window, ssp_num_gss_handles
                    data.skip_opaque()?; // spi_handles
                },
                _ => { return None; }
            }
        }

        let so_major_id;
        { // eir_server_owner
            data.skip_u64(1)?; // so_minor_id
            so_major_id = data.read_opaque()?;
        }
        trace!("Found server ID: {}", String::from_utf8_lossy(so_major_id));

        let eir_server_scope = data.read_opaque()?;
        trace!("Found server scope: {}", String::from_utf8_lossy(eir_server_scope));

        let mut nii_domain = None;
        let mut nii_name = None;
        { // eir_server_impl_id

            let num = data.read_u32()?;

            if num == 1 { // Max 1 element
                nii_domain = Some(data.read_opaque()?);
                trace!("Found implementor domain : {}", String::from_utf8_lossy(nii_domain.unwrap()));
                nii_name = Some(data.read_opaque()?);
                trace!("Found implentation name : {}", String::from_utf8_lossy(nii_name.unwrap()));
                // nii_data
                data.skip_u32(3)?;
            } else if num > 1 {
                return None;
            }
        }

        if EventBus::has_subscribers(EventKind::NetNfsExchangeIdReply) {

            let evt_pload = NetNfsExchangeIdReply {
                base: NetNfsBase {
                    conn_id: self.conn_id.clone(),
                    conn_info: self.conn_info.clone(),
                    xid,
                },
                so_major_id: so_major_id.into(),
                eir_server_scope: eir_server_scope.into(),
                nii_domain: nii_domain.map(Into::into),
                nii_name: nii_name.map(Into::into),
            };

            let evt = Event::new(ts, EventPayload::NetNfsExchangeIdReply(evt_pload));
            evt.send();
        }

        Some(())
    }

    fn create_session_call(&self, ts: PktTime, xid: u32, data: &mut NfsData) -> Option<()> {

        trace!("CREATE_SESSION CALL");

        let csa_clientid = data.read_u64()?;
        let csa_sequence = data.read_u32()?;

        data.skip_u32(1)?; // csa_flags

        { // csa_fore_chan_attrs
            data.skip_u32(6);
            let ca_rdma_ird_len = data.read_u32()? as usize;
            if ca_rdma_ird_len > 1 {
                return None;
            } else if ca_rdma_ird_len > 0 {
                data.skip_u32(ca_rdma_ird_len)?;
            }
        }

        { // csa_back_chan_attrs
            data.skip_u32(6);
            let ca_rdma_ird_len = data.read_u32()? as usize;
            if ca_rdma_ird_len > 1 {
                return None;
            } else if ca_rdma_ird_len > 0 {
                data.skip_u32(ca_rdma_ird_len)?;
            }
        }

        data.skip_u32(1); // csa_cb_program

        let mut machine_name = None;
        let mut uid = None;
        let mut gid = None;


        let csa_sec_param_count = data.read_u32()?;

        if csa_sec_param_count > 4 {
            return None;
        }

        for _ in 0..csa_sec_param_count {

            { // csa_sec_params
                let cb_secflavor = data.read_u32()?;
                match cb_secflavor {
                    0 => {}, // AUTH_NONE
                    1 => { // AUTH_SYS
                        data.skip_u32(1)?; // stamp
                        machine_name = Some(data.read_opaque()?);
                        trace!("Found machine_name {}", String::from_utf8_lossy(machine_name.unwrap()));
                        uid = Some(data.read_u32()?);
                        gid = Some(data.read_u32()?);
                        // Additional gids don't seem common so I'll just ignore them for now
                        data.skip_opaque()?; // gids
                    },
                    2 => {  // RPCSEC_GSS
                        data.skip_u32(1)?; // gcbp_service
                        data.skip_opaque()?; // gcbp_handle_from_server
                        data.skip_opaque()?; // gcbp_handle_from_client
                    }
                    _ => { return None; },
                }
            }
        }

        if EventBus::has_subscribers(EventKind::NetNfsCreateSessionCall) {

            let evt_pload = NetNfsCreateSessionCall {
                base: NetNfsBase {
                    conn_id: self.conn_id.clone(),
                    conn_info: self.conn_info.clone(),
                    xid,
                },
                machine_name: machine_name.map(Into::into),
                uid,
                gid,
            };

            let evt = Event::new(ts, EventPayload::NetNfsCreateSessionCall(evt_pload));
            evt.send();
        }

        Some(())

    }

    fn create_session_reply(&self, ts: PktTime, xid: u32, status: u32, data: &mut NfsData) -> Option<()> {

        trace!("CREATE_SESSION REPLY");

        if status != 0 {
            // Not OK
            return Some(());
        }

        data.skip(NfsData::NFS4_SESSIONID_SIZE)?; // csr_sessionid
        data.skip_u32(2)?; // csr_sequence, csr_flags

        { // csr_fore_chan_attrs
            data.skip_u32(6);
            let ca_rdma_ird_len = data.read_u32()? as usize;
            if ca_rdma_ird_len > 1 {
                return None;
            } else if ca_rdma_ird_len > 0 {
                data.skip_u32(ca_rdma_ird_len)?;
            }
        }

        { // csr_back_chan_attrs
            data.skip_u32(6);
            let ca_rdma_ird_len = data.read_u32()? as usize;
            if ca_rdma_ird_len > 1 {
                return None;
            } else if ca_rdma_ird_len > 0 {
                data.skip_u32(ca_rdma_ird_len)?;
            }
        }

        Some(())
    }

    fn sequence_call(&self, ts: PktTime, xid: u32, data: &mut NfsData) -> Option<()> {

        trace!("SEQUENCE CALL");

        data.skip(NfsData::NFS4_SESSIONID_SIZE)?; // sa_sessionid
        data.skip_u32(4)?; // sa_sequenceid, sa_slotid, sa_highest_slotid, sa_cachethis

        Some(())
    }

    fn sequence_reply(&self, ts: PktTime, xid: u32, status: u32, data: &mut NfsData) -> Option<()> {

        trace!("SEQUENCE REPLY");

        if status != 0 {
            // Not OK
            return Some(());
        }

        data.skip(NfsData::NFS4_SESSIONID_SIZE)?; // sr_sessionid
        data.skip_u32(5)?; // sr_sequenceid, sr_slotid, sr_highest_slotid, sr_target_highest_slotid, sr_status_flags

        Some(())
    }

    fn reclaim_complete_call(&self, ts: PktTime, xid: u32, data: &mut NfsData) -> Option<()> {
        trace!("RECLAIM_COMPLETE CALL");

        data.skip_u32(1)?; // rca_one_fs

        Some(())
    }

    fn reclaim_complete_reply(&self, ts: PktTime, xid: u32, status: u32, data: &mut NfsData) -> Option<()> {

        trace!("RECLAIM_COMPLETE REPLY");
        Some(())
    }

    fn putrootfh_call(&self, ts: PktTime, xid: u32, data: &mut NfsData) -> Option<()> {

        trace!("PUTROOTFH CALL");
        Some(())
    }

    fn putrootfh_reply(&self, ts: PktTime, xid: u32, status: u32, data: &mut NfsData) -> Option<()> {

        trace!("PUTROOTFH REPLY");
        Some(())
    }

    fn getfh_call(&self, ts: PktTime, xid: u32, data: &mut NfsData) -> Option<()> {

        trace!("GETFH CALL");
        Some(())
    }

    fn getfh_reply(&self, ts: PktTime, xid: u32, status: u32, data: &mut NfsData) -> Option<()> {

        trace!("GETFH REPLY");

        if status != 0 {
            return Some(());
        }

        data.skip_opaque()?; // file handle
        Some(())
    }

    fn getattr_call(&self, ts: PktTime, xid: u32, data: &mut NfsData) -> Option<()> {

        trace!("GETATTR CALL");

        let len = data.read_u32()? as usize;
        data.skip_u32(len)?;
        Some(())
    }

    fn getattr_reply(&self, ts: PktTime, xid: u32, status: u32, data: &mut NfsData) -> Option<()> {

        trace!("GETATTR REPLY");

        if status != 0 {
            return Some(());
        }

        let attrmask_len = data.read_u32()? as usize;
        data.skip_u32(attrmask_len)?; // attrmask

        data.skip_opaque()?; // attr_vals

        Some(())
    }

    fn secinfo_no_name_call(&self, ts: PktTime, xid: u32, data: &mut NfsData) -> Option<()> {

        trace!("SECINFO_NO_NAME CALL");

        data.skip_u32(1)?; // SECINFO_NO_NAME4args
        Some(())
    }

    fn secinfo_no_name_reply(&self, ts: PktTime, xid: u32, status: u32, data: &mut NfsData) -> Option<()> {

        trace!("SECINFO_NO_NAME REPLY");
        data.skip_opaque()?; // SECINFO4res<>
        Some(())
    }

    fn putfh_call(&self, ts: PktTime, xid: u32, data: &mut NfsData) -> Option<()> {

        trace!("PUTFH CALL");

        data.skip_opaque()?;
        Some(())
    }

    fn putfh_reply(&self, ts: PktTime, xid: u32, status: u32, data: &mut NfsData) -> Option<()> {

        trace!("PUTFH REPLY");
        Some(())
    }

    fn access_call(&self, ts: PktTime, xid: u32, data: &mut NfsData) -> Option<()> {

        trace!("ACCESS CALL");
        data.skip_u32(1)?;
        Some(())
    }

    fn access_reply(&self, ts: PktTime, xid: u32, status: u32, data: &mut NfsData) -> Option<()> {

        trace!("ACCESS REPLY");
        data.skip_u32(2)?; // supported, access
        Some(())
    }

    fn lookup_call(&self, ts: PktTime, xid: u32, data: &mut NfsData) -> Option<()> {

        trace!("LOOKUP CALL");
        data.skip_opaque()?; // objname
        Some(())
    }

    fn lookup_reply(&self, ts: PktTime, xid: u32, status: u32, data: &mut NfsData) -> Option<()> {

        trace!("LOOKUP REPLY");
        Some(())
    }

    fn get_dir_delegation_call(&self, ts: PktTime, xid: u32, data: &mut NfsData) -> Option<()> {

        trace!("GET_DIR_DELEGATION CALL");
        data.skip_u32(1); // gdda_signal_deleg_avail
        data.skip_opaque()?; // gdda_notification_types
        data.skip_u64(1); // gdda_child_attr_delay seconds
        data.skip_u32(1); // gdda_child_attr_delay nanos
        data.skip_u64(1); // gdda_dir_attr_delay seconds
        data.skip_u32(1); // gdda_dir_attr_delay nanos
        data.skip_opaque()?; // gdda_child_attributes
        data.skip_opaque()?; // gddr_dir_attributes
        Some(())
    }

    fn get_dir_delegation_reply(&self, ts: PktTime, xid: u32, status: u32, data: &mut NfsData) -> Option<()> {

        trace!("GET_DIR_DELEGATION REPLY");

        let gddrnf_status = data.read_u32()?; // gddrnf_status

        match gddrnf_status {
            0 => { // GDD4_OK
                debug!("GET_DIR_DELEGATION GDD4_OK not implemented");
                return None; // FIXME
            },
            1 => { // GDD4_UNAVAIL
                data.skip_u32(1); // gddrnf_will_signal_deleg_avail
            },
            _ => { return None; }
        }



        Some(())
    }

    fn readdir_call(&self, ts: PktTime, xid: u32, data: &mut NfsData) -> Option<()> {

        trace!("READDIR CALL");
        data.skip_u64(2)?; // cookie, cookieverf
        data.skip_u32(2)?; // dircount, maxcount
        let attrmask_len = data.read_u32()? as usize;
        data.skip_u32(attrmask_len)?; // attrmask
        Some(())
    }

    fn readdir_reply(&self, ts: PktTime, xid: u32, status: u32, data: &mut NfsData) -> Option<()> {

        trace!("READDIR REPLY");

        if status != 0 {
            return Some(());
        }

        data.skip(NfsData::NFS4_VERIFIER_SIZE)?; // cookieverf

        loop {
            let present = data.read_u32()?;
            match present {
                0 => break,
                1 => {},
                _ => { return None ; },
            }

            data.skip_u64(1); // cookie
            let name = data.read_opaque()?;
            trace!("Found file {}", String::from_utf8_lossy(name));

            let attrmask_len = data.read_u32()? as usize;
            data.skip_u32(attrmask_len)?; // attrmask
            data.skip_opaque()?; // attr_vals
        }

        data.skip_u32(1); // eof


        Some(())
    }

    fn open_call(&self, ts: PktTime, xid: u32, data: &mut NfsData) -> Option<()> {

        trace!("OPEN CALL");
        data.skip_u32(3)?; // seqid, share_access, share_deny
        data.skip_u64(1)?; // clientid
        data.skip_opaque()?; // owner
        data.skip_u32(2)?; // openhow, claim

        Some(())
    }

    fn open_reply(&self, ts: PktTime, xid: u32, status: u32, data: &mut NfsData) -> Option<()> {

        trace!("OPEN REPLY");

        if status != 0 {
            return Some(());
        }

        data.skip(16)?; // stateid

        data.skip_u32(1)?; // cinfo.atomic
        data.skip_u64(2)?; // cinfo.before, cinfo.after

        data.skip_u32(1)?; // rflags
        data.skip_opaque()?; // attrset

        let delegation_type = data.read_u32()?; // delegation_type
        match delegation_type {
            0 => {}, // OPEN_DELEGATE_NONE
            1 => { // OPEN_DELEGATE_READ
                data.skip(16)?; // stateid
                data.skip_u32(1)?; // recall

                data.skip_u32(3)?; // read.{type, flag, access_mask}
                data.skip_opaque(); // read.who
            },
            2 => { // OPEN_DELEGATE_WRITE

                data.skip(16)?; // stateid
                data.skip_u32(1)?; // recall

                data.skip_u32(3)?; // space_limit

                data.skip_u32(3)?; // read.{type, flag, access_mask}
                data.skip_opaque(); // read.who
            },
            3 => { // OPEN_DELEGATE_NONE_EXT
                let ond_why = data.read_u32()?;
                match ond_why {
                    0 | 1 => { data.skip_u32(1)?; }
                    _ => {}
                }
            }
            _ => {
                debug!("Unknown delegation type {}", delegation_type);
                return None;
            }
        }

        Some(())
    }

    fn read_plus_call(&self, ts: PktTime, xid: u32, data: &mut NfsData) -> Option<()> {

        trace!("READ_PLUS CALL");

        data.skip(16); // rpa_stateid
        data.skip_u64(1); // rpa_offset
        data.skip_u32(1); // rpa_count
        Some(())
    }

    fn read_plus_reply(&self, ts: PktTime, xid: u32, status: u32, data: &mut NfsData) -> Option<()> {

        trace!("READ_PLUS REPLY");

        let eof = data.read_u32()? != 0; // eof

        let content_count = data.read_u32()?;

        for _ in 0..content_count {
            let rpc_content = data.read_u32()?;
            match rpc_content {
                0 => { // DATA
                    let d_offset = data.read_u64()?;
                    let d_length = data.read_u32()? as usize;
                    trace!("Got {} of data from READ_PLUS at offset {}", d_length, d_offset);
                    data.skip(d_length)?;
                },

                1 => { // HOLE
                    let di_offset = data.read_u64()?;
                    let content = data.read_opaque()?;
                    trace!("Got hole in READ_PLUS, offset {}, length {}", di_offset, content.len());
                },
                _ => {
                    debug!("Unsupported content in READ_PLUS");
                    return None;
                }
            }
        }

        Some(())
    }

    fn delegreturn_call(&self, ts: PktTime, xid: u32, data: &mut NfsData) -> Option<()> {

        trace!("DELEGRETURN CALL");
        data.skip(16)?;
        Some(())
    }

    fn delegreturn_reply(&self, ts: PktTime, xid: u32, status: u32, data: &mut NfsData) -> Option<()> {

        trace!("DELEGRETURN REPLY");
        Some(())
    }

    fn destroy_session_call(&self, ts: PktTime, xid: u32, data: &mut NfsData) -> Option<()> {

        trace!("DESTROY_SESSION CALL");
        data.skip(NfsData::NFS4_SESSIONID_SIZE)?;
        Some(())
    }

    fn destroy_session_reply(&self, ts: PktTime, xid: u32, status: u32, data: &mut NfsData) -> Option<()> {

        trace!("DESTROY_SESSION REPLY");
        Some(())
    }

    fn destroy_client_id_call(&self, ts: PktTime, xid: u32, data: &mut NfsData) -> Option<()> {

        trace!("DESTROY_CLIENT_ID CALL");
        data.skip_u64(1)?;
        Some(())
    }

    fn destroy_client_id_reply(&self, ts: PktTime, xid: u32, status: u32, data: &mut NfsData) -> Option<()> {

        trace!("DESTROY_CLIENT_ID REPLY");
        Some(())
    }
}
