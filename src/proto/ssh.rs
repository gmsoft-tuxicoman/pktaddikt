use crate::base::{Parser, ParseErr};
use crate::stream::{PktStreamProcessor, PktStreamParser};
use crate::packet::{PktInfoStack, Packet, PktTime};
use crate::conntrack::ConntrackDirection;
use crate::event::{EventStr, EventKind, Event, EventPayload};
use crate::base::UniqueId;
use crate::messagebus::MessageBus;


use serde::Serialize;
use std::net::IpAddr;
use tracing::{debug, trace};

#[derive(Debug, Serialize)]
pub struct NetSshSession {

    pub conn_id: UniqueId,
    pub server_addr: IpAddr,
    pub server_port: u16,
    pub server_version: Option<EventStr>,
    pub client_addr: IpAddr,
    pub client_port: u16,
    pub client_version: Option<EventStr>,
    pub kex_algorithm: Option<EventStr>,
    pub server_host_key_algorithm: Option<EventStr>,
    pub encryption_algorithm_client_to_server: Option<EventStr>,
    pub mac_algorithm_client_to_server: Option<EventStr>,
    pub compression_algorithm_client_to_server: Option<EventStr>,
    pub encryption_algorithm_server_to_client: Option<EventStr>,
    pub mac_algorithm_server_to_client: Option<EventStr>,
    pub compression_algorithm_server_to_client: Option<EventStr>,

    pub authentication_failed: u32,
    pub authentication_succeeded: Option<bool>,
}

pub struct ProtoSshStateAlgos {

    kex_algorithms: Vec<EventStr>,
    server_host_key_algorithms: Vec<EventStr>,
    encryption_algorithms_client_to_server: Vec<EventStr>,
    encryption_algorithms_server_to_client: Vec<EventStr>,
    mac_algorithms_client_to_server: Vec<EventStr>,
    mac_algorithms_server_to_client: Vec<EventStr>,
    compression_algorithms_client_to_server: Vec<EventStr>,
    compression_algorithms_server_to_client: Vec<EventStr>,
}

#[derive(Default)]
pub struct ProtoSshStateInfo {

    pkt_len: Option<u32>,
    encrypted: bool,
    algos: Option<ProtoSshStateAlgos>,
}

pub struct ProtoSsh {

    state: [ProtoSshStateInfo; 2],

    service_accept_len: Option<u32>,
    encrypted_msg_count: u32,
    service_accept_seen: bool,
    ts: Option<PktTime>,

    evt_pload: Option<NetSshSession>,

}

impl PktStreamProcessor for ProtoSsh {

    fn new(infos: &PktInfoStack) -> Self {

        let conn_info = infos.get_conn_info();

        let evt_pload = NetSshSession {
            conn_id: infos.get_conn_id().unwrap().clone(),
            server_addr: conn_info.dst_host.unwrap().clone(),
            server_port: conn_info.dst_port.unwrap().clone(),
            server_version: None,
            client_addr: conn_info.src_host.unwrap().clone(),
            client_port: conn_info.src_port.unwrap().clone(),
            client_version: None,
            kex_algorithm: None,
            server_host_key_algorithm: None,
            encryption_algorithm_client_to_server: None,
            mac_algorithm_client_to_server: None,
            compression_algorithm_client_to_server: None,
            encryption_algorithm_server_to_client: None,
            mac_algorithm_server_to_client: None,
            compression_algorithm_server_to_client: None,

            authentication_failed: 0,
            authentication_succeeded: None,

        };

        Self {
            state: Default::default(),
            service_accept_len: None,
            encrypted_msg_count: 0,
            service_accept_seen: false,
            ts: None,
            evt_pload: Some(evt_pload),
        }
    }

    fn process(&mut self, dir: ConntrackDirection, mut parser: PktStreamParser) -> Result<(), ParseErr> {

        if ! MessageBus::event_has_subscribers(EventKind::NetSshSession) || self.evt_pload.is_none() {
            return Err(ParseErr::Stop);
        }

        if dir == ConntrackDirection::Reverse && self.state[1].encrypted {
            // We are trying to find out about auth success/failure by looking at encrypted msg len
            // Once we detect auth success or we bail out, issue Err::Stop to stop processing the
            // stream
            return self.process_encrypted_server_msg(&mut parser);
        }

        let state = &mut self.state[dir as usize];

        if state.encrypted {
            // Connection is encrypted, nothing to do but wait for both sides to encrypt
            parser.skip(parser.remaining_len())?;
            return Ok(());
        }

        if self.ts.is_none() {
            self.ts = Some(parser.timestamp());
        }

        let evt_pload = self.evt_pload.as_mut().unwrap();

        // Parse Version string first
        if dir == ConntrackDirection::Forward {
            if evt_pload.client_version.is_none() {
                evt_pload.client_version = ProtoSsh::parse_version(parser)?;
                return Ok(());
            }
        } else {
            if evt_pload.server_version.is_none() {
                evt_pload.server_version = ProtoSsh::parse_version(parser)?;
                return Ok(());
            }
        }

        // It's the binary protocol after version exchange

        // Check if we got some length already
        let pkt_len = match state.pkt_len {
            Some(len) => len,
            None => {
                let len = parser.read_u32_be()?;
                state.pkt_len = Some(len);
                len
            }
        };

        if pkt_len > 35000 {
            // Packet is too big according to RFC
            return Err(ParseErr::Invalid("SSH packet too big"));
        }

        let mut bin_pkt = parser.sub_packet(pkt_len)?;
        // Get ready for the next packet
        state.pkt_len = None;

        let padding_len = bin_pkt.read_u8()?;
        if (padding_len as u32) > pkt_len {
            return Err(ParseErr::Invalid("Padding length bigger than packet"));
        }

        bin_pkt.shrink(padding_len as u32);

        let msg_type = bin_pkt.read_u8()?;
        trace!("SSH packet type {}", msg_type);


        match msg_type {
            20 => { // SSH_MSG_KEXINIT
                self.parse_kexinit(dir, &mut bin_pkt)?;

            },
            21 => { // SSH_MSG_NEWKEYS
                trace!("Connection encryption started");
                evt_pload.authentication_succeeded = Some(false);
                state.encrypted = true;
            },
            _ => {
                trace!("Ignoring unknown message type {}", msg_type);
            }
        }

        Ok(())
    }

}

impl ProtoSsh {


    fn process_encrypted_server_msg(&mut self, parser: &mut PktStreamParser) -> Result<(), ParseErr> {

        let len = parser.remaining_len();
        parser.skip(parser.remaining_len())?; // Discard the data

        let evt_pload = self.evt_pload.as_mut().unwrap();
        let svc_acc_len = match self.service_accept_len {
            Some(l) => l,
            None => {
                if let Some(comp) = &evt_pload.compression_algorithm_server_to_client {
                    if &**comp != b"none" {
                        debug!("Compression enabled on SSH connection, cannot guess authentication status");
                        return Err(ParseErr::Stop);
                    }
                }

                let Some(enc) = &evt_pload.encryption_algorithm_server_to_client else {
                    debug!("Encryption algorithm unknown");
                    return Err(ParseErr::Stop);
                };

                let Some(mac) = &evt_pload.mac_algorithm_server_to_client else {
                    debug!("Mac algorithm unknown");
                    return Err(ParseErr::Stop);
                };

                self.service_accept_len = ProtoSsh::service_accept_len_guess(enc, mac);
                if self.service_accept_len.is_none() {
                    debug!("Unknown combination of encryption and mac : {}/{}",  String::from_utf8_lossy(enc), String::from_utf8_lossy(mac));
                    return Err(ParseErr::Stop);
                }
                self.service_accept_len.unwrap()
            }
        };

        self.encrypted_msg_count += 1;

        if ! self.service_accept_seen {
            if len == svc_acc_len {
                self.service_accept_seen = true;
            }
            return Ok(())
        }

        // Auth failure is always 16 bytes more
        if len == (svc_acc_len + 16) {
            trace!("Authentication failed detected");
            evt_pload.authentication_failed += 1;

        // Auth success is always 16 bytes less
        } else if len == svc_acc_len - 16 {
            trace!("Authentication success detected");
            evt_pload.authentication_succeeded = Some(true);
        }


        // If we have auth success or if we reached the message threshold, emit the event

        if evt_pload.authentication_succeeded == Some(true) || self.encrypted_msg_count > 20 {

            let evt_pload = self.evt_pload.take().unwrap();
            let evt = Event::new(self.ts.unwrap(), EventPayload::NetSshSession(evt_pload));
            MessageBus::publish_event(evt);
        }


        Ok(())
    }

    fn parse_version(mut parser: PktStreamParser) -> Result<Option<EventStr>, ParseErr> {
        let line = parser.readline()?;

        if ! line.starts_with(b"SSH-") {
            trace!("Ignoring non SSH version banner");
            return Ok(None);
        }

        trace!("Found SSH version {}", String::from_utf8_lossy(&*line));

        Ok(Some(EventStr::from(line)))
    }

    fn read_name_list(parser: &mut Packet) -> Result<Vec<u8>, ParseErr> {
        let len = parser.read_u32_be()?;
        let ret = parser.read(len)?;
        trace!("Name list : {}", String::from_utf8_lossy(&*ret));
        Ok(ret.into_owned())
    }

    fn algo_selection(client: &Vec<EventStr>, server: &Vec<EventStr>) -> Option<EventStr> {

        for c in client {
            if server.contains(c) {
                return Some(c.clone());
            }
        }
        None
    }

    fn service_accept_len_guess(encryption_algorithm: &EventStr, mac_algorithm: &EventStr) -> Option<u32> {

        // Known TCP payload size for service accept len
        match &**encryption_algorithm {
            b"chacha20-poly1305@openssh.com" => Some(44),
            b"aes128-gcm@openssh.com" | b"aes256-gcm@openssh.com" => Some(52),
            b"aes128-ctr" | b"aes192-ctr" | b"aes256-ctr" | b"aes128-cbc" | b"aes192-cbc" | b"aes256-cbc" | b"3des-cbc" => match &**mac_algorithm {
                b"hmac-sha2-256" | b"hmac-sha2-256-etm@openssh.com" => Some(64),
                b"hmac-sha2-512" | b"hmac-sha2-512-etm@openssh.com" => Some(96),
                b"hmac-sha1"     | b"hmac-sha1-etm@openssh.com"     => Some(52),
                _ => None
            }

            _ => None,
        }

    }

    fn parse_kexinit(&mut self, dir: ConntrackDirection, parser: &mut Packet) -> Result<(), ParseErr> {

        let state = &mut self.state[dir as usize];

        parser.skip(16)?; // Cookie

        let kex_algorithms = ProtoSsh::read_name_list(parser)?;
        let server_host_key_algorithms = ProtoSsh::read_name_list(parser)?;
        let encryption_algorithms_client_to_server = ProtoSsh::read_name_list(parser)?;
        let encryption_algorithms_server_to_client = ProtoSsh::read_name_list(parser)?;
        let mac_algorithms_client_to_server = ProtoSsh::read_name_list(parser)?;
        let mac_algorithms_server_to_client = ProtoSsh::read_name_list(parser)?;
        let compression_algorithms_client_to_server = ProtoSsh::read_name_list(parser)?; 
        let compression_algorithms_server_to_client = ProtoSsh::read_name_list(parser)?;
        let _languages_client_to_server = ProtoSsh::read_name_list(parser)?;
        let _languages_server_to_client = ProtoSsh::read_name_list(parser)?;
        let _first_kex_packet_follows = parser.read_u8()?;
        parser.skip_u32()?; // Reserved

        let algos = ProtoSshStateAlgos {
            kex_algorithms: kex_algorithms.split(|&b| b == b',').map(EventStr::from).collect(),
            server_host_key_algorithms: server_host_key_algorithms.split(|&b| b == b',').map(EventStr::from).collect(),
            encryption_algorithms_client_to_server: encryption_algorithms_client_to_server.split(|&b| b == b',').map(EventStr::from).collect(),
            encryption_algorithms_server_to_client: encryption_algorithms_server_to_client.split(|&b| b == b',').map(EventStr::from).collect(),
            mac_algorithms_client_to_server: mac_algorithms_client_to_server.split(|&b| b == b',').map(EventStr::from).collect(),
            mac_algorithms_server_to_client: mac_algorithms_server_to_client.split(|&b| b == b',').map(EventStr::from).collect(),
            compression_algorithms_client_to_server: compression_algorithms_client_to_server.split(|&b| b == b',').map(EventStr::from).collect(),
            compression_algorithms_server_to_client: compression_algorithms_server_to_client.split(|&b| b == b',').map(EventStr::from).collect(),
        };

        state.algos = Some(algos);


        if let (Some(client), Some(server)) = (&self.state[0].algos, &self.state[1].algos) {
            // We know both client and server algos. Let's see which one will be used
    
            let evt_pload = self.evt_pload.as_mut().unwrap();

            // Common algo
            evt_pload.kex_algorithm = ProtoSsh::algo_selection(&client.kex_algorithms, &server.kex_algorithms);
            evt_pload.server_host_key_algorithm = ProtoSsh::algo_selection(&client.server_host_key_algorithms, &server.server_host_key_algorithms);

            // From the client perspective
            evt_pload.encryption_algorithm_client_to_server = ProtoSsh::algo_selection(&client.encryption_algorithms_client_to_server, &server.encryption_algorithms_client_to_server);
            evt_pload.mac_algorithm_client_to_server = ProtoSsh::algo_selection(&client.mac_algorithms_client_to_server, &server.mac_algorithms_client_to_server);
            evt_pload.compression_algorithm_client_to_server = ProtoSsh::algo_selection(&client.compression_algorithms_client_to_server, &server.compression_algorithms_client_to_server);

            // From the server perspective
            evt_pload.encryption_algorithm_server_to_client = ProtoSsh::algo_selection(&client.encryption_algorithms_server_to_client, &server.encryption_algorithms_server_to_client);
            evt_pload.mac_algorithm_server_to_client = ProtoSsh::algo_selection(&client.mac_algorithms_server_to_client, &server.mac_algorithms_server_to_client);
            evt_pload.compression_algorithm_server_to_client = ProtoSsh::algo_selection(&client.compression_algorithms_server_to_client, &server.compression_algorithms_server_to_client);

        }


        Ok(())
    }
}

impl Drop for ProtoSsh {

    fn drop(&mut self) {

        if self.evt_pload.is_none() {
            return;
        }
        let evt_pload = self.evt_pload.take().unwrap();
        let evt = Event::new(self.ts.unwrap(), EventPayload::NetSshSession(evt_pload));
        MessageBus::publish_event(evt);

    }

}
