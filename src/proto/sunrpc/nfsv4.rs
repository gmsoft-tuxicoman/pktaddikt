use crate::base::{Parser, ParseErr};
use crate::event::{EventStr, EventKind, Event, EventPayload};
use crate::messagebus::MessageBus;
use crate::base::UniqueId;
use crate::packet::PktConnInfo;
use crate::proto::sunrpc::xdr::*;
use crate::blob::Blob;

use tracing::{debug, trace};
use serde::Serialize;
use std::collections::HashMap;
use std::net::IpAddr;


#[derive(Debug, Serialize)]
pub struct NetNfsV4Base {

    pub conn_id: UniqueId,
    pub client_addr: IpAddr,
    pub client_port: u16,
    pub server_addr: IpAddr,
    pub server_port: u16,
    pub xid: u32,

}

#[derive(Debug, Serialize)]
pub struct NetNfsV4CallExchangeId {

    #[serde(flatten)]
    pub base: NetNfsV4Base,
    pub co_ownerid: EventStr,
    pub nii_domain: Option<EventStr>,
    pub nii_name: Option<EventStr>,
}

#[derive(Debug, Serialize)]
pub struct NetNfsV4ReplyExchangeId {

    #[serde(flatten)]
    pub base: NetNfsV4Base,
    pub so_major_id: EventStr,
    pub eir_server_scope: EventStr,
    pub nii_domain: Option<EventStr>,
    pub nii_name: Option<EventStr>,
}

#[derive(Debug, Serialize)]
pub struct NetNfsV4CallCreateSession {

    #[serde(flatten)]
    pub base: NetNfsV4Base,
    pub machine_name: Option<EventStr>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,

}

pub struct ProtoNfsV4 {

    conn_id: UniqueId,
    conn_info: PktConnInfo,
    blobs: HashMap<Vec<u8>, Blob>,
    server_addr: Option<IpAddr>,
    server_port: Option<u16>,
    client_addr: Option<IpAddr>,
    client_port: Option<u16>,

}


impl ProtoNfsV4 {

    const NFS4_VERIFIER_SIZE: u32 = 8;
    const NFS4_SESSIONID_SIZE: u32 = 16;

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

    pub fn parse_call<T: Parser>(&mut self, xid: u32, proc: u32, parser: &mut T) -> Result<(), ParseErr> {

        if self.server_addr.is_none() {
            // ConnInfo will be in the right direction for the first call/reply
            self.client_addr = self.conn_info.src_host;
            self.client_port = self.conn_info.src_port;
            self.server_addr = self.conn_info.dst_host;
            self.server_port = self.conn_info.dst_port;
        }

        if proc != 1 { // NFSv4 only has COMPOUND
            return Err(ParseErr::Invalid("Unknown NFSv4 procedure called"));
        }

        // tag
        skip_opaque(parser)?;

        let minorversion = parser.read_u32_be()?;
        let numops = parser.read_u32_be()?;

        trace!("Got CALL COMPOUND NFS4.{} with {} operation(s)", minorversion, numops);

        for _ in 0..numops {

            let opcode = parser.read_u32_be()?;
            match opcode {
                3 => self.access_call(xid, parser),
                8 => self.delegreturn_call(xid, parser),
                9 => self.getattr_call(xid, parser),
                10 => self.getfh_call(xid, parser),
                15 => self.lookup_call(xid, parser),
                18 => self.open_call(xid, parser),
                22 => self.putfh_call(xid, parser),
                24 => self.putrootfh_call(xid, parser),
                26 => self.readdir_call(xid, parser),
                42 => self.exchange_id_call(xid, parser),
                43 => self.create_session_call(xid, parser),
                44 => self.destroy_session_call(xid, parser),
                46 => self.get_dir_delegation_call(xid, parser),
                52 => self.secinfo_no_name_call(xid, parser),
                53 => self.sequence_call(xid, parser),
                57 => self.destroy_client_id_call(xid, parser),
                58 => self.reclaim_complete_call(xid, parser),
                68 => self.read_plus_call(xid, parser),
                _ => {
                    debug!("Unknown NFS opcode {}", opcode);
                    return Err(ParseErr::Invalid("Unknown NFS opcode in COMPOUND call"));
                }
            }?;
        }

        Ok(())
    }

    pub fn parse_reply<T: Parser>(&mut self, xid: u32, proc: u32, parser: &mut T) -> Result<(), ParseErr> {

        if self.server_addr.is_none() {
            // ConnInfo will be in the right direction for the first call/reply
            self.client_addr = self.conn_info.dst_host;
            self.client_port = self.conn_info.dst_port;
            self.server_addr = self.conn_info.src_host;
            self.server_port = self.conn_info.src_port;
        }

        if proc != 1 { // NFSv4 only has COMPOUND
            return Err(ParseErr::Invalid("Unknown NFSv4 procedure in replied"));
        }

        let status = parser.read_u32_be()?;
        skip_opaque(parser)?; // tag

        let numops = parser.read_u32_be()?;

        trace!("Got REPLY COMPOUND with status {} and {} operation(s)", status, numops);

        for _ in 0..numops {

            let opcode = parser.read_u32_be()?;
            let status = parser.read_u32_be()?;
            match opcode {
                3 => self.access_reply(xid, status, parser),
                8 => self.delegreturn_reply(xid, status, parser),
                9 => self.getattr_reply(xid, status, parser),
                10 => self.getfh_reply(xid, status, parser),
                15 => self.lookup_reply(xid, status, parser),
                18 => self.open_reply(xid, status, parser),
                22 => self.putfh_reply(xid, status, parser),
                24 => self.putrootfh_reply(xid, status, parser),
                26 => self.readdir_reply(xid, status, parser),
                42 => self.exchange_id_reply(xid, status, parser),
                43 => self.create_session_reply(xid, status, parser),
                44 => self.destroy_session_reply(xid, status, parser),
                46 => self.get_dir_delegation_reply(xid, status, parser),
                52 => self.secinfo_no_name_reply(xid, status, parser),
                53 => self.sequence_reply(xid, status, parser),
                57 => self.destroy_client_id_reply(xid, status, parser),
                58 => self.reclaim_complete_reply(xid, status, parser),
                68 => self.read_plus_reply(xid, status, parser),
                _ => {
                    debug!("Unknown NFS opcode {}", opcode);
                    return Err(ParseErr::Invalid("Unknown NFS opcode in COMPOUND reply"));
                }
            }?;
        }

        Ok(())

    }

    fn event_base(&self, xid: u32) -> NetNfsV4Base {
        NetNfsV4Base {
            conn_id: self.conn_id.clone(),
            client_addr: self.client_addr.unwrap(),
            client_port: self.client_port.unwrap(),
            server_addr: self.server_addr.unwrap(),
            server_port: self.server_port.unwrap(),
            xid,
        }
    }

    fn exchange_id_call<T: Parser>(&self, xid: u32, parser: &mut T) -> Result<(), ParseErr> {

        trace!("EXCHANGE_ID CALL");

        let co_ownerid;
        let mut nii_domain = None;
        let mut nii_name = None;

        { // eia_clientowner

            // co_verifier
            parser.skip(ProtoNfsV4::NFS4_VERIFIER_SIZE)?;
            // co_ownerid
            co_ownerid = read_opaque(parser)?;
            trace!("Found owner id : {}", String::from_utf8_lossy(&co_ownerid));
        }

        { // eia_flags
            parser.skip_u32()?;
        }

        { // eia_state_protect
            let spa_how = parser.read_u32_be()?;
            match spa_how {
                0 => {}, // SP4_NONE
                1 => { parser.skip_u32s(2)?; }, // SP4_MACH_CRED (spo_must_enforce, spo_must_allow)
                2 => { // SP4_SSV
                    parser.skip_u32s(2)?; // ssp_ops { spo_must_enforce, ssp_ops.spo_must_allow }
                    skip_opaque(parser)?; // ssp_hash_algs
                    skip_opaque(parser)?; // ssp_encr_algs
                    parser.skip_u32s(2)?; // ssp_window, ssp_num_gss_handles
                },
                _ => { return Err(ParseErr::Invalid("Invalid spa_how value in exchange_id call")); }
            }

        }

        { // eia_client_impl_id

            let num = parser.read_u32_be()?;

            if num == 1 { // Max 1 element
                // nii_domain
                nii_domain = Some(read_opaque(parser)?);
                trace!("Found implementor domain : {}", String::from_utf8_lossy(nii_domain.as_ref().unwrap()));
                // nii_name
                nii_name = Some(read_opaque(parser)?);
                trace!("Found implentation name : {}", String::from_utf8_lossy(nii_name.as_ref().unwrap()));
                // nii_data
                parser.skip_u32s(3)?;
            } else if num > 1 {
                return Err(ParseErr::Invalid("More than one element in eia_client_impl_id in exchange_id call"));
            }
        }

        if MessageBus::event_has_subscribers(EventKind::NetNfsV4CallExchangeId) {

            let evt_pload = NetNfsV4CallExchangeId {
                base: self.event_base(xid),
                co_ownerid: co_ownerid.into(),
                nii_domain: nii_domain.map(Into::into),
                nii_name: nii_name.map(Into::into),
            };

            let evt = Event::new(parser.timestamp(), EventPayload::NetNfsV4CallExchangeId(evt_pload));
            MessageBus::publish_event(evt);
        }
        Ok(())
    }

    fn exchange_id_reply<T: Parser>(&self, xid: u32, status: u32, parser: &mut T) -> Result<(), ParseErr> {

        trace!("EXCHANGE_ID REPLY");

        if status != 0 {
            // Not OK
            return Ok(());
        }

        parser.skip_u64()?; // eir_clientid
        parser.skip_u32s(2)?; // eir_sequenceid, eir_flags

        { // eir_state_protect
            let spr_how = parser.read_u32_be()?;
            match spr_how {
                0 => {}, // SP4_NONE
                1 => { parser.skip_u32s(2)?; }, // SP4_MACH_CRED (spo_must_enforce, spo_must_allow)
                2 => { // SP4_SSV
                    parser.skip_u32s(2)?; // ssi_ops { spo_must_enforce, spo_must_allow}
                    parser.skip_u32s(4)?; // spi_hash_alg, spi_encr_alg, spi_ssv_len, spi_window
                    parser.skip_u32s(2)?; // ssp_window, ssp_num_gss_handles
                    skip_opaque(parser)?; // spi_handles
                },
                _ => { return Err(ParseErr::Invalid("Invalid value for spa_how in exchange_id reply")); }
            }
        }

        let so_major_id;
        { // eir_server_owner
            parser.skip_u64()?; // so_minor_id
            so_major_id = read_opaque(parser)?;
        }
        trace!("Found server ID: {}", String::from_utf8_lossy(&so_major_id));

        let eir_server_scope = read_opaque(parser)?;
        trace!("Found server scope: {}", String::from_utf8_lossy(&eir_server_scope));

        let mut nii_domain = None;
        let mut nii_name = None;
        { // eir_server_impl_id

            let num = parser.read_u32_be()?;

            if num == 1 { // Max 1 element
                nii_domain = Some(read_opaque(parser)?);
                trace!("Found implementor domain : {}", String::from_utf8_lossy(nii_domain.as_ref().unwrap()));
                nii_name = Some(read_opaque(parser)?);
                trace!("Found implentation name : {}", String::from_utf8_lossy(nii_name.as_ref().unwrap()));
                // nii_data
                parser.skip_u32s(3)?;
            } else if num > 1 {
                return Err(ParseErr::Invalid("More than one element in eir_server_impl_id in exchange_id reply"));
            }
        }

        if MessageBus::event_has_subscribers(EventKind::NetNfsV4ReplyExchangeId) {

            let evt_pload = NetNfsV4ReplyExchangeId {
                base: self.event_base(xid),
                so_major_id: so_major_id.into(),
                eir_server_scope: eir_server_scope.into(),
                nii_domain: nii_domain.map(Into::into),
                nii_name: nii_name.map(Into::into),
            };

            let evt = Event::new(parser.timestamp(), EventPayload::NetNfsV4ReplyExchangeId(evt_pload));
            MessageBus::publish_event(evt);
        }

        Ok(())
    }

    fn create_session_call<T: Parser>(&self, xid: u32, parser: &mut T) -> Result<(), ParseErr> {

        trace!("CREATE_SESSION CALL");

        parser.skip_u64()?; // csa_clientid
        parser.skip_u32s(2)?; // csa_sequence, csa_flags

        { // csa_fore_chan_attrs
            parser.skip_u32s(6)?;
            let ca_rdma_ird_len = parser.read_u32_be()?;
            if ca_rdma_ird_len > 1 {
                return Err(ParseErr::Invalid("ca_rdma_ird_len > 1 in create_session call"));
            } else if ca_rdma_ird_len > 0 {
                parser.skip_u32s(ca_rdma_ird_len)?;
            }
        }

        { // csa_back_chan_attrs
            parser.skip_u32s(6)?;
            let ca_rdma_ird_len = parser.read_u32_be()?;
            if ca_rdma_ird_len > 1 {
                return Err(ParseErr::Invalid("ca_rdma_ird_len > 1 in create_session call"));
            } else if ca_rdma_ird_len > 0 {
                parser.skip_u32s(ca_rdma_ird_len)?;
            }
        }

        parser.skip_u32()?; // csa_cb_program

        let mut machine_name = None;
        let mut uid = None;
        let mut gid = None;


        let csa_sec_param_count = parser.read_u32_be()?;

        if csa_sec_param_count > 4 {
            return Err(ParseErr::Invalid("csa_sec_param_count > 4 in create_session call"));
        }

        for _ in 0..csa_sec_param_count {

            { // csa_sec_params
                let cb_secflavor = parser.read_u32_be()?;
                match cb_secflavor {
                    0 => {}, // AUTH_NONE
                    1 => { // AUTH_SYS
                        parser.skip_u32()?; // stamp
                        machine_name = Some(read_opaque(parser)?);
                        trace!("Found machine_name {}", String::from_utf8_lossy(machine_name.as_ref().unwrap()));
                        uid = Some(parser.read_u32_be()?);
                        gid = Some(parser.read_u32_be()?);
                        // Additional gids don't seem common so I'll just ignore them for now
                        skip_opaque(parser)?; // gids
                    },
                    2 => {  // RPCSEC_GSS
                        parser.skip_u32()?; // gcbp_service
                        skip_opaque(parser)?; // gcbp_handle_from_server
                        skip_opaque(parser)?; // gcbp_handle_from_client
                    }
                    _ => { return Err(ParseErr::Invalid("Invalid cb_secflavor in create_session call")); },
                }
            }
        }

        if MessageBus::event_has_subscribers(EventKind::NetNfsV4CallCreateSession) {

            let evt_pload = NetNfsV4CallCreateSession {
                base: self.event_base(xid),
                machine_name: machine_name.map(Into::into),
                uid,
                gid,
            };

            let evt = Event::new(parser.timestamp(), EventPayload::NetNfsV4CallCreateSession(evt_pload));
            MessageBus::publish_event(evt);
        }

        Ok(())

    }

    fn create_session_reply<T: Parser>(&self, _xid: u32, status: u32, parser: &mut T) -> Result<(), ParseErr> {

        trace!("CREATE_SESSION REPLY");

        if status != 0 {
            // Not OK
            return Ok(());
        }

        parser.skip(ProtoNfsV4::NFS4_SESSIONID_SIZE)?; // csr_sessionid
        parser.skip_u32s(2)?; // csr_sequence, csr_flags

        { // csr_fore_chan_attrs
            parser.skip_u32s(6)?;
            let ca_rdma_ird_len = parser.read_u32_be()?;
            if ca_rdma_ird_len > 1 {
                return Err(ParseErr::Invalid("ca_rdma_ird_len > 1 in create_session reply"));
            } else if ca_rdma_ird_len > 0 {
                parser.skip_u32s(ca_rdma_ird_len)?;
            }
        }

        { // csr_back_chan_attrs
            parser.skip_u32s(6)?;
            let ca_rdma_ird_len = parser.read_u32_be()?;
            if ca_rdma_ird_len > 1 {
                return Err(ParseErr::Invalid("ca_rdma_ird_len > 1 in create_session reply"));
            } else if ca_rdma_ird_len > 0 {
                parser.skip_u32s(ca_rdma_ird_len)?;
            }
        }

        Ok(())
    }

    fn sequence_call<T: Parser>(&self, _xid: u32, parser: &mut T) -> Result<(), ParseErr> {

        trace!("SEQUENCE CALL");

        parser.skip(ProtoNfsV4::NFS4_SESSIONID_SIZE)?; // sa_sessionid
        parser.skip_u32s(4)?; // sa_sequenceid, sa_slotid, sa_highest_slotid, sa_cachethis

        Ok(())
    }

    fn sequence_reply<T: Parser>(&self, _xid: u32, status: u32, parser: &mut T) -> Result<(), ParseErr> {

        trace!("SEQUENCE REPLY");

        if status != 0 {
            // Not OK
            return Ok(());
        }

        parser.skip(ProtoNfsV4::NFS4_SESSIONID_SIZE)?; // sr_sessionid
        parser.skip_u32s(5)?; // sr_sequenceid, sr_slotid, sr_highest_slotid, sr_target_highest_slotid, sr_status_flags

        Ok(())
    }

    fn reclaim_complete_call<T: Parser>(&self, _xid: u32, parser: &mut T) -> Result<(), ParseErr> {
        trace!("RECLAIM_COMPLETE CALL");

        parser.skip_u32()?; // rca_one_fs

        Ok(())
    }

    fn reclaim_complete_reply<T: Parser>(&self, _xid: u32, _status: u32, _parser: &mut T) -> Result<(), ParseErr> {

        trace!("RECLAIM_COMPLETE REPLY");
        Ok(())
    }

    fn putrootfh_call<T: Parser>(&self, _xid: u32, _parser: &mut T) -> Result<(), ParseErr> {

        trace!("PUTROOTFH CALL");
        Ok(())
    }

    fn putrootfh_reply<T: Parser>(&self, _xid: u32, _status: u32, _parser: &mut T) -> Result<(), ParseErr> {

        trace!("PUTROOTFH REPLY");
        Ok(())
    }

    fn getfh_call<T: Parser>(&self, _xid: u32, _parser: &mut T) -> Result<(), ParseErr> {

        trace!("GETFH CALL");
        Ok(())
    }

    fn getfh_reply<T: Parser>(&self, _xid: u32, status: u32, parser: &mut T) -> Result<(), ParseErr> {

        trace!("GETFH REPLY");

        if status != 0 {
            return Ok(());
        }

        skip_opaque(parser)?; // file handle
        Ok(())
    }

    fn getattr_call<T: Parser>(&self, _xid: u32, parser: &mut T) -> Result<(), ParseErr> {

        trace!("GETATTR CALL");

        let len = parser.read_u32_be()?;
        parser.skip_u32s(len)?;
        Ok(())
    }

    fn getattr_reply<T: Parser>(&self, _xid: u32, status: u32, parser: &mut T) -> Result<(), ParseErr> {

        trace!("GETATTR REPLY");

        if status != 0 {
            return Ok(());
        }

        let attrmask_len = parser.read_u32_be()?;
        parser.skip_u32s(attrmask_len)?; // attrmask

        skip_opaque(parser)?; // attr_vals

        Ok(())
    }

    fn secinfo_no_name_call<T: Parser>(&self, _xid: u32, parser: &mut T) -> Result<(), ParseErr> {

        trace!("SECINFO_NO_NAME CALL");

        parser.skip_u32()?; // SECINFO_NO_NAME4args
        Ok(())
    }

    fn secinfo_no_name_reply<T: Parser>(&self, _xid: u32, _status: u32, parser: &mut T) -> Result<(), ParseErr> {

        trace!("SECINFO_NO_NAME REPLY");
        skip_opaque(parser)?; // SECINFO4res<>
        Ok(())
    }

    fn putfh_call<T: Parser>(&self, _xid: u32, parser: &mut T) -> Result<(), ParseErr> {

        trace!("PUTFH CALL");

        skip_opaque(parser)?;
        Ok(())
    }

    fn putfh_reply<T: Parser>(&self, _xid: u32, _status: u32, _arser: &mut T) -> Result<(), ParseErr> {

        trace!("PUTFH REPLY");
        Ok(())
    }

    fn access_call<T: Parser>(&self, _xid: u32, parser: &mut T) -> Result<(), ParseErr> {

        trace!("ACCESS CALL");
        parser.skip_u32()?;
        Ok(())
    }

    fn access_reply<T: Parser>(&self, _xid: u32, _status: u32, parser: &mut T) -> Result<(), ParseErr> {

        trace!("ACCESS REPLY");
        parser.skip_u32s(2)?; // supported, access
        Ok(())
    }

    fn lookup_call<T: Parser>(&self, _xid: u32, parser: &mut T) -> Result<(), ParseErr> {

        trace!("LOOKUP CALL");
        skip_opaque(parser)?; // objname
        Ok(())
    }

    fn lookup_reply<T: Parser>(&self, _xid: u32, _status: u32, _parser: &mut T) -> Result<(), ParseErr> {

        trace!("LOOKUP REPLY");
        Ok(())
    }

    fn get_dir_delegation_call<T: Parser>(&self, _xid: u32, parser: &mut T) -> Result<(), ParseErr> {

        trace!("GET_DIR_DELEGATION CALL");
        parser.skip_u32()?; // gdda_signal_deleg_avail
        skip_opaque(parser)?; // gdda_notification_types
        parser.skip_u64()?; // gdda_child_attr_delay seconds
        parser.skip_u32()?; // gdda_child_attr_delay nanos
        parser.skip_u64()?; // gdda_dir_attr_delay seconds
        parser.skip_u32()?; // gdda_dir_attr_delay nanos
        skip_opaque(parser)?; // gdda_child_attributes
        skip_opaque(parser)?; // gddr_dir_attributes
        Ok(())
    }

    fn get_dir_delegation_reply<T: Parser>(&self, _xid: u32, _status: u32, parser: &mut T) -> Result<(), ParseErr> {

        trace!("GET_DIR_DELEGATION REPLY");

        let gddrnf_status = parser.read_u32_be()?; // gddrnf_status

        match gddrnf_status {
            0 => { // GDD4_OK
                debug!("GET_DIR_DELEGATION GDD4_OK not implemented");
                // FIXME
                return Err(ParseErr::Invalid("GET_DIR_DELEGATION GDD4_OK not implemented"));
            },
            1 => { // GDD4_UNAVAIL
                parser.skip_u32()?; // gddrnf_will_signal_deleg_avail
            },
            _ => { return Err(ParseErr::Invalid("Invalid gddrnf_status value in get_dir_delegation reply")); }
        }



        Ok(())
    }

    fn readdir_call<T: Parser>(&self, _xid: u32, parser: &mut T) -> Result<(), ParseErr> {

        trace!("READDIR CALL");
        parser.skip_u64s(2)?; // cookie, cookieverf
        parser.skip_u32s(2)?; // dircount, maxcount
        let attrmask_len = parser.read_u32_be()?;
        parser.skip_u32s(attrmask_len)?; // attrmask
        Ok(())
    }

    fn readdir_reply<T: Parser>(&self, _xid: u32, status: u32, parser: &mut T) -> Result<(), ParseErr> {

        trace!("READDIR REPLY");

        if status != 0 {
            return Ok(());
        }

        parser.skip(ProtoNfsV4::NFS4_VERIFIER_SIZE)?; // cookieverf

        loop {
            let present = parser.read_u32_be()?;
            match present {
                0 => break,
                1 => {},
                _ => { return Err(ParseErr::Invalid("Invalid 'present' value in readdir reply")) ; },
            }

            parser.skip_u64()?; // cookie
            let name = read_opaque(parser)?;
            trace!("Found file {}", String::from_utf8_lossy(&name));

            let attrmask_len = parser.read_u32_be()?;
            parser.skip_u32s(attrmask_len)?; // attrmask
            skip_opaque(parser)?; // attr_vals
        }

        parser.skip_u32()?; // eof


        Ok(())
    }

    fn open_call<T: Parser>(&self, _xid: u32, parser: &mut T) -> Result<(), ParseErr> {

        trace!("OPEN CALL");
        parser.skip_u32s(3)?; // seqid, share_access, share_deny
        parser.skip_u64()?; // clientid
        skip_opaque(parser)?; // owner
        parser.skip_u32s(2)?; // openhow, claim

        Ok(())
    }

    fn open_reply<T: Parser>(&self, _xid: u32, status: u32, parser: &mut T) -> Result<(), ParseErr> {

        trace!("OPEN REPLY");

        if status != 0 {
            return Ok(());
        }

        parser.skip(16)?; // stateid

        parser.skip_u32()?; // cinfo.atomic
        parser.skip_u64s(2)?; // cinfo.before, cinfo.after

        parser.skip_u32()?; // rflags
        skip_opaque(parser)?; // attrset

        let delegation_type = parser.read_u32_be()?; // delegation_type
        match delegation_type {
            0 => {}, // OPEN_DELEGATE_NONE
            1 => { // OPEN_DELEGATE_READ
                parser.skip(16)?; // stateid
                parser.skip_u32()?; // recall

                parser.skip_u32s(3)?; // read.{type, flag, access_mask}
                skip_opaque(parser)?; // read.who
            },
            2 => { // OPEN_DELEGATE_WRITE

                parser.skip(16)?; // stateid
                parser.skip_u32()?; // recall

                parser.skip_u32s(3)?; // space_limit

                parser.skip_u32s(3)?; // read.{type, flag, access_mask}
                skip_opaque(parser)?; // read.who
            },
            3 => { // OPEN_DELEGATE_NONE_EXT
                let ond_why = parser.read_u32_be()?;
                match ond_why {
                    0 | 1 => { parser.skip_u32()?; }
                    _ => {}
                }
            }
            _ => {
                debug!("Unknown delegation type {}", delegation_type);
                return Err(ParseErr::Invalid("Invalid delegation_type in open reply"));
            }
        }

        Ok(())
    }

    fn read_plus_call<T: Parser>(&self, _xid: u32, parser: &mut T) -> Result<(), ParseErr> {

        trace!("READ_PLUS CALL");

        parser.skip(16)?; // rpa_stateid
        parser.skip_u64()?; // rpa_offset
        parser.skip_u32()?; // rpa_count
        Ok(())
    }

    fn read_plus_reply<T: Parser>(&self, _xid: u32, _status: u32, parser: &mut T) -> Result<(), ParseErr> {

        trace!("READ_PLUS REPLY");

        parser.skip_u32()?; // eof

        let content_count = parser.read_u32_be()?;

        for _ in 0..content_count {
            let rpc_content = parser.read_u32_be()?;
            match rpc_content {
                0 => { // DATA
                    let d_offset = parser.read_u64_be()?;
                    let d_length = parser.read_u32_be()?;
                    trace!("Got {} of data from READ_PLUS at offset {}", d_length, d_offset);
                    parser.skip(d_length)?;
                },

                1 => { // HOLE
                    let di_offset = parser.read_u64_be()?;
                    let content = read_opaque(parser)?;
                    trace!("Got hole in READ_PLUS, offset {}, length {}", di_offset, content.len());
                },
                _ => {
                    debug!("Unsupported content in READ_PLUS");
                    return Err(ParseErr::Invalid("Invalid rpc_content value in read_plus reply"));
                }
            }
        }

        Ok(())
    }

    fn delegreturn_call<T: Parser>(&self, _xid: u32, parser: &mut T) -> Result<(), ParseErr> {

        trace!("DELEGRETURN CALL");
        parser.skip(16)?;
        Ok(())
    }

    fn delegreturn_reply<T: Parser>(&self, _xid: u32, _status: u32, _parser: &mut T) -> Result<(), ParseErr> {

        trace!("DELEGRETURN REPLY");
        Ok(())
    }

    fn destroy_session_call<T: Parser>(&self, _xid: u32, parser: &mut T) -> Result<(), ParseErr> {

        trace!("DESTROY_SESSION CALL");
        parser.skip(ProtoNfsV4::NFS4_SESSIONID_SIZE)?;
        Ok(())
    }

    fn destroy_session_reply<T: Parser>(&self, _xid: u32, _status: u32, _parser: &mut T) -> Result<(), ParseErr> {

        trace!("DESTROY_SESSION REPLY");
        Ok(())
    }

    fn destroy_client_id_call<T: Parser>(&self, _xid: u32, parser: &mut T) -> Result<(), ParseErr> {

        trace!("DESTROY_CLIENT_ID CALL");
        parser.skip_u64()?;
        Ok(())
    }

    fn destroy_client_id_reply<T: Parser>(&self, _xid: u32, _status: u32, _parser: &mut T) -> Result<(), ParseErr> {

        trace!("DESTROY_CLIENT_ID REPLY");
        Ok(())
    }
}
