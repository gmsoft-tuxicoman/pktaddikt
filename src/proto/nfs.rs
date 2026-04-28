use crate::stream::StreamParseResult;
use crate::event::{EventId, EventBus, EventStr, EventKind, Event, EventPayload};
use crate::packet::{PktConnInfo, PktTime};

use tracing::trace;
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

    const NFS4_OPAQUE_LIMIT: usize = 1024;
    const NFS4_VERIFIER_SIZE: usize = 8;

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
        if len > Self::NFS4_OPAQUE_LIMIT {
            return None;
        }
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
        if len > Self::NFS4_OPAQUE_LIMIT {
            return None;
        }
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
                42 => self.exchange_id_call(ts, xid, data),
                43 => self.create_session_call(ts, xid, data),
                _ => { return None; }
            }?;
        }

        Some(())

    }

    fn compound_reply(&self, ts: PktTime, xid: u32, data: &mut NfsData) -> Option<()> {

        let status = data.read_u32()?;

        // tag
        data.skip_opaque()?;

        let numops = data.read_u32()?;

        trace!("Got REPLY COMPOUND with status {} and {} operation(s)", status, numops );

        for _ in 0..numops {

            let opcode = data.read_u32()?;
            match opcode {
                42 => self.exchange_id_reply(ts, xid, data),
                _ => { return None; }
            }?;
        }

        Some(())

    }

    fn exchange_id_call(&self, ts: PktTime, xid: u32, data: &mut NfsData) -> Option<()> {

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

    fn exchange_id_reply(&self, ts: PktTime, xid: u32, data: &mut NfsData) -> Option<()> {

        let status = data.read_u32()?;

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

        let csa_clientid = data.read_u64()?;
        let csa_sequence = data.read_u32()?;

        data.skip_u32(1)?; // csa_flags

        { // csa_fore_chan_attrs
            data.skip_u32(6);
        }

        { // csa_back_chan_attrs
            data.skip_u32(6);
        }

        data.skip_u32(1); // csa_cb_program

        let mut machine_name = None;
        let mut uid = None;
        let mut gid = None;

        { // csa_sec_params
            let cb_secflavor = data.read_u32()?;
            match cb_secflavor {
                0 => {}, // AUTH_NONE
                1 => { // AUTH_SYS
                    data.skip_u32(1)?; // stamp
                    machine_name = Some(data.read_opaque()?);
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
}
