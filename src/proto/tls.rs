use crate::base::{Parser, ParseErr};
use crate::stream::{PktStreamProcessor, PktStreamParser, PktSubStream};
use crate::packet::PktInfoStack;
use std::net::IpAddr;
use crate::conntrack::ConntrackDirection;
use crate::event::{EventStr, EventPayload, Event};
use crate::base::UniqueId;
use crate::packet::Packet;
use crate::messagebus::MessageBus;


use tracing::trace;
use serde::Serialize;


#[derive(Debug, Serialize)]
pub struct NetTlsClientHello {
    pub conn_id: UniqueId,
    pub client_addr: IpAddr,
    pub client_port: u16,
    pub server_addr: IpAddr,
    pub server_port: u16,
    pub version: TlsVersion,
    pub server_name: Option<EventStr>,
    pub next_proto: Vec<EventStr>,
}


#[derive(Debug, Serialize)]
pub enum TlsVersion {
    SSLv3 = 0x300,
    TLSv10 = 0x301,
    TLSv11 = 0x302,
    TLSv12 = 0x303,
    TLSv13 = 0x304,
    Unknown
}


#[derive(Debug, PartialEq)]
enum ProtoTlsState {
    RecordHeader,
    ChangeCipher,
    Alert,
    Handshake,
    ApplicationData,
    HeartBeat,
    Invalid
}

#[derive(Debug)]
pub struct ProtoTlsDir {

    state: ProtoTlsState,
    rlen: u32,
    handshake_stream: PktSubStream,
    handshake_proto: ProtoTlsHandshake,
}

impl Default for ProtoTlsDir {
    fn default() -> Self {
        Self {
            state: ProtoTlsState::RecordHeader,
            rlen: 0,
            handshake_stream: PktSubStream::new(),
            handshake_proto: ProtoTlsHandshake::new(),
        }
    }
}


#[derive(Debug)]
pub struct ProtoTls {

    dir: [ProtoTlsDir;2],
    conn_id: UniqueId,
    client_addr: IpAddr,
    client_port: u16,
    server_addr: IpAddr,
    server_port: u16,
}

impl ProtoTls {

    fn read_record(&mut self, dir: ConntrackDirection, mut parser: PktStreamParser) -> Result<(), ParseErr> {

        let ctype = parser.read_u8()?;
        parser.skip_u16()?; // version

        let status = &mut self.dir[dir as usize];
        status.rlen = parser.read_u16_be()? as u32;

        if status.rlen > 16384 {
            return Err(ParseErr::Invalid("TLS Record length > 16384"));
        }

        status.state = match ctype {
            20 => ProtoTlsState::ChangeCipher,
            21 => ProtoTlsState::Alert,
            22 => ProtoTlsState::Handshake,
            23 => ProtoTlsState::ApplicationData,
            24 => ProtoTlsState::HeartBeat,
            _ => ProtoTlsState::Invalid,
        };

        trace!("Got TLS record of type {:?} and length {}", status.state, status.rlen);

        Ok(())

    }
}

impl PktStreamProcessor for ProtoTls {

    fn new(infos: &PktInfoStack) -> Self {
        let conn_info = infos.get_conn_info();
        Self {
            dir: [ProtoTlsDir::default(), ProtoTlsDir::default()],
            conn_id: infos.get_conn_id().unwrap().clone(),
            client_addr: conn_info.src_host.unwrap(),
            client_port: conn_info.src_port.unwrap(),
            server_addr: conn_info.dst_host.unwrap(),
            server_port: conn_info.dst_port.unwrap(),
        }
    }

    fn process(&mut self, dir: ConntrackDirection, mut parser: PktStreamParser) -> Result<(), ParseErr> {

        let status = &mut self.dir[dir as usize];

        if status.state == ProtoTlsState::RecordHeader {
            return self.read_record(dir, parser);
        }

        parser.has_len(status.rlen)?;

        if status.rlen == 0 {
            // Empty TLS record: nothing to process, go back to reading the next record
            // header (sub_packet(0) would otherwise abort parsing for the connection).
            status.state = ProtoTlsState::RecordHeader;
            return Ok(());
        }

        let mut pkt = parser.sub_packet(status.rlen)?;

        let ret = match status.state {
            ProtoTlsState::Handshake => {
                let mut stream_data = status.handshake_stream.add_packet(&mut pkt);
                status.handshake_proto.process(dir, &mut stream_data, &self.conn_id, self.client_addr, self.client_port, self.server_addr, self.server_port)
            }
            ProtoTlsState::ChangeCipher => {
                if pkt.read_u8()? != 1 {
                    return Err(ParseErr::Invalid("Invalid TLS ChangeCipher content, expected 1"));
                }
                // Stop trying to process the stream for now
                Err(ParseErr::Stop)
            }
            _ => Err(ParseErr::Stop),
        };

        status.state = ProtoTlsState::RecordHeader;
        status.rlen = 0;

        ret
    }
}


#[derive(Debug)]
enum ProtoTlsHandshakeType {

    HelloRequest,
    ClientHello,
    ServerHello,
    Certificate,
    ServerKeyExchange,
    CertificateRequest,
    ServerHelloDone,
    CertificateVerify,
    ClientKeyExchange,
    Finished,
    //FIXME add missing
}

#[derive(Debug)]
pub struct ProtoTlsHandshake {

    ctype: Option<ProtoTlsHandshakeType>,
    clen: u32,

}

impl ProtoTlsHandshake {

    fn new() -> Self {
        Self {
            ctype: None,
            clen: 0,
        }
    }

    fn process(&mut self, _dir: ConntrackDirection, parser: &mut PktStreamParser, conn_id: &UniqueId, client_addr: IpAddr, client_port: u16, server_addr: IpAddr, server_port: u16) -> Result<(), ParseErr> {
            
        if self.ctype.is_none() {
            let ctype = match parser.read_u8()? {
                0 => ProtoTlsHandshakeType::HelloRequest,
                1 => ProtoTlsHandshakeType::ClientHello,
                2 => ProtoTlsHandshakeType::ServerHello,
                11 => ProtoTlsHandshakeType::Certificate,
                12 => ProtoTlsHandshakeType::ServerKeyExchange,
                13 => ProtoTlsHandshakeType::CertificateRequest,
                14 => ProtoTlsHandshakeType::ServerHelloDone,
                15 => ProtoTlsHandshakeType::CertificateVerify,
                16 => ProtoTlsHandshakeType::ClientKeyExchange,
                20 => ProtoTlsHandshakeType::Finished,
                _ => return Err(ParseErr::Invalid("Invalid TLS Handshake content type")),
            };
            self.clen = parser.read_u24_be()?;

            if self.clen > 16384 {
                // According to RFC, record len should be less than 16k (2^14)
                return Err(ParseErr::Invalid("Content length > 16384 for TLS Handshake record"));
            }

            trace!("Got handshake of type {:?} and len {}", ctype, self.clen);

            self.ctype = Some(ctype);
        }

        if self.clen == 0 {
            // A zero-length handshake message is valid (e.g. ServerHelloDone). There is
            // no body to parse, and none of the messages we care about are empty, so
            // reset and continue rather than failing on sub_packet(0).
            self.ctype = None;
            return Ok(());
        }

        // Make sure we have enough data to continue
        let mut pkt = parser.sub_packet(self.clen)?;

        let ret = match self.ctype {
            Some(ProtoTlsHandshakeType::ClientHello) => self.parse_client_hello(&mut pkt, conn_id, client_addr, client_port, server_addr, server_port),
            _ => Ok(())
        };

        self.ctype = None;
        self.clen = 0;

        if ret == Err(ParseErr::Truncated) {
            return Err(ParseErr::Invalid("Unable to parse TLS Handshake message as it appeared truncated"));
        }
        ret
    }

    fn parse_client_hello(&self, parser: &mut Packet, conn_id: &UniqueId, client_addr: IpAddr, client_port: u16, server_addr: IpAddr, server_port: u16) -> Result<(), ParseErr> {

        let mut version = parser.read_u16_be()?;

        // Skip random
        parser.skip(32)?;

        let session_id_len = parser.read_u8()? as u32;

        if session_id_len > 32 {
            return Err(ParseErr::Invalid("TLS Client Hello session ID lenght > 32"));
        }

        parser.skip(session_id_len)?;


        // Parse and validate cipher suite length
        let cipher_suite_len = parser.read_u16_be()? as u32;
        parser.skip(cipher_suite_len)?;

        // Parse and validate compression method len
        let compression_method_len = parser.read_u8()? as u32;
        parser.skip(compression_method_len)?;

        // Check for presence of extensions

        if parser.remaining_len() == 0 {
            // No extension
            return Ok(());
        }

        // Parse and validate extensions}
        let extensions_len = parser.read_u16_be()? as u32;

        if extensions_len > parser.remaining_len() {
            return Err(ParseErr::Invalid("Extensions length bigger than TLS Client Hello remaining length"));
        } else if extensions_len < parser.remaining_len() {
            parser.shrink(extensions_len);
            // WEIRD should be equal
        }



        let mut server_name: Option<EventStr> = None;
        let mut next_proto: Vec<EventStr> = Vec::with_capacity(1);

        while parser.remaining_len() > 0 {

            let etype = parser.read_u16_be()?;
            let elen =  parser.read_u16_be()? as u32;

            if elen == 0 {
                // A zero-length extension is valid (e.g. extended_master_secret, GREASE).
                // None of the extensions we parse below carry an empty body, so skip it
                // rather than letting sub_packet(0) abort the whole ClientHello.
                continue;
            }

            let mut epkt = parser.sub_packet(elen)?;

            match etype {
                0 => { // Server Name Indication
                    epkt.skip_u16()?; // Name list length
                    let name_list_type = epkt.read_u8()?;
                    if name_list_type != 0 {
                        // Should be 0 for HostName type
                        return Err(ParseErr::Invalid("TLS SNI ServerNameType should be 0"));
                    }
                    let name_len = epkt.read_u16_be()? as u32;
                    let hostname = epkt.read(name_len)?;
                    trace!("Found SNI with hostname: {}", String::from_utf8_lossy(&hostname));
                    server_name = Some(hostname.into());

                    if epkt.remaining_len() > 0 {
                        trace!("SNI with multiple hostnames found");
                    }
                },

                43 => { // Supported version
                    version = epkt.read_u16_be()?;

                }

                16 | 17513 | 17613 => { // ALPS | draft-vvv-tls-alps-01
                    let alpn_len = epkt.read_u16_be()? as u32;
                    if alpn_len > epkt.remaining_len() {
                        return Err(ParseErr::Invalid("TLS ClientHello ALPN extension len > than advertised extension len"));
                    }
                    epkt.shrink(alpn_len);
                    while epkt.remaining_len() > 0 {
                        let proto_len = epkt.read_u8()? as u32;
                        let proto = epkt.read(proto_len)?;
                        trace!("Found next protocol: {}", String::from_utf8_lossy(&proto));
                        next_proto.push(proto.into());
                    }

                }
                _ => ()
            }
        }

        let ver_enum = match version {
            0x300 => TlsVersion::SSLv3,
            0x301 => TlsVersion::TLSv10,
            0x302 => TlsVersion::TLSv11,
            0x303 => TlsVersion::TLSv12,
            0x304 => TlsVersion::TLSv13,
            _ => TlsVersion::Unknown,
        };

        let evt_pload = NetTlsClientHello {
            conn_id: conn_id.clone(),
            client_addr,
            client_port,
            server_addr,
            server_port,
            version: ver_enum,
            server_name,
            next_proto,
        };


        let evt = Event::new(parser.timestamp(), EventPayload::NetTlsClientHello(evt_pload));
        MessageBus::publish_event(evt);


        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::packet::{Packet, PktTime};
    use std::net::Ipv4Addr;

    // Builds a minimal ClientHello body (the bytes parse_client_hello receives) with a
    // single trailing extension of the given type and body.
    fn client_hello(ext_type: u16, ext_body: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&[0x03, 0x03]); // version TLS 1.2
        b.extend_from_slice(&[0u8; 32]);    // random
        b.push(0);                          // session id length
        b.extend_from_slice(&[0x00, 0x00]); // cipher suite length
        b.push(0);                          // compression method length

        let mut exts = Vec::new();
        exts.extend_from_slice(&ext_type.to_be_bytes());
        exts.extend_from_slice(&(ext_body.len() as u16).to_be_bytes());
        exts.extend_from_slice(ext_body);

        b.extend_from_slice(&(exts.len() as u16).to_be_bytes()); // extensions length
        b.extend_from_slice(&exts);
        b
    }

    fn parse(data: &[u8]) -> Result<(), ParseErr> {
        let hs = ProtoTlsHandshake::new();
        let mut pkt = Packet::from_slice(PktTime::from_micros(0), data);
        hs.parse_client_hello(
            &mut pkt,
            &UniqueId::new(PktTime::from_micros(0)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            1234,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
        )
    }

    // A zero-length extension (e.g. extended_master_secret, type 23) must not abort the
    // ClientHello parse. Regression: sub_packet(0) returned Invalid.
    #[test]
    fn tls_client_hello_zero_length_extension() {
        let data = client_hello(23, &[]);
        assert!(parse(&data).is_ok(), "zero-length extension should parse");
    }

    // A non-empty extension still parses (sanity check the harness).
    #[test]
    fn tls_client_hello_non_empty_extension() {
        // supported_versions style body; we don't assert on the value here.
        let data = client_hello(43, &[0x02, 0x03, 0x04]);
        assert!(parse(&data).is_ok(), "non-empty extension should parse");
    }
}
