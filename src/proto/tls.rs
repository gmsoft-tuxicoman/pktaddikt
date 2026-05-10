use crate::base::{Parser, ParseErr};
use crate::stream::{PktStreamProcessor, PktStreamParser, PktSubStream};
use crate::packet::{PktInfoStack, PktConnInfo};
use crate::conntrack::ConntrackDirection;
use crate::event::{EventId, EventStr, EventPayload, Event};
use crate::packet::Packet;


use tracing::trace;
use serde::Serialize;


#[derive(Debug, Serialize)]
pub struct NetTlsClientHello {
    pub conn_id: EventId,
    #[serde(flatten)]
    pub conn_info: PktConnInfo,
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
    rlen: usize,
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
    conn_id: EventId,
    conn_info: PktConnInfo,
}

impl ProtoTls {

    fn read_record(&mut self, dir: ConntrackDirection, mut parser: PktStreamParser) -> Result<(), ParseErr> {

        let ctype = parser.read_u8()?;
        parser.skip_u16()?; // version

        let status = &mut self.dir[dir as usize];
        status.rlen = parser.read_u16_be()? as usize;

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
        Self {
            dir: [ProtoTlsDir::default(), ProtoTlsDir::default()],
            conn_id: infos.get_conn_id().unwrap().clone(),
            conn_info: infos.get_conn_info(),
        }
    }

    fn process(&mut self, dir: ConntrackDirection, mut parser: PktStreamParser) -> Result<(), ParseErr> {

        let status = &mut self.dir[dir as usize];

        if status.state == ProtoTlsState::RecordHeader {
            return self.read_record(dir, parser);
        }

        parser.has_len(status.rlen)?;

        let mut pkt = parser.sub_packet(status.rlen)?;

        let ret = match status.state {
            ProtoTlsState::Handshake => {
                let mut stream_data = status.handshake_stream.add_packet(&mut pkt);
                status.handshake_proto.process(dir, &mut stream_data, &self.conn_id, self.conn_info)
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
    clen: usize,

}

impl ProtoTlsHandshake {

    fn new() -> Self {
        Self {
            ctype: None,
            clen: 0,
        }
    }

    fn process(&mut self, _dir: ConntrackDirection, parser: &mut PktStreamParser, conn_id: &EventId, conn_info: PktConnInfo) -> Result<(), ParseErr> {
            
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
            self.clen = parser.read_u24_be()? as usize;

            if self.clen > 16384 {
                // According to RFC, record len should be less than 16k (2^14)
                return Err(ParseErr::Invalid("Content length > 16384 for TLS Handshake record"));
            }

            trace!("Got handshake of type {:?} and len {}", ctype, self.clen);

            self.ctype = Some(ctype);
        }


        // Make sure we have enough data to continue
        let mut pkt = parser.sub_packet(self.clen)?;

        let ret = match self.ctype {
            Some(ProtoTlsHandshakeType::ClientHello) => self.parse_client_hello(&mut pkt, conn_id, conn_info),
            _ => Ok(())
        };

        self.ctype = None;
        self.clen = 0;

        if ret == Err(ParseErr::Truncated) {
            return Err(ParseErr::Invalid("Unable to parse TLS Handshake message as it appeared truncated"));
        }
        ret
    }

    fn parse_client_hello(&self, parser: &mut Packet, conn_id: &EventId, conn_info: PktConnInfo) -> Result<(), ParseErr> {

        let mut version = parser.read_u16_be()?;

        // Skip random
        parser.skip(32)?;

        let session_id_len = parser.read_u8()? as usize;

        if session_id_len > 32 {
            return Err(ParseErr::Invalid("TLS Client Hello session ID lenght > 32"));
        }

        parser.skip(session_id_len)?;


        // Parse and validate cipher suite length
        let cipher_suite_len = parser.read_u16_be()? as usize;
        parser.skip(cipher_suite_len)?;

        // Parse and validate compression method len
        let compression_method_len = parser.read_u8()? as usize;
        parser.skip(compression_method_len)?;

        // Check for presence of extensions

        if parser.remaining_len() == 0 {
            // No extension
            return Ok(());
        }

        // Parse and validate extensions}
        let extensions_len = parser.read_u16_be()? as usize;

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
            let elen =  parser.read_u16_be()? as usize;

            let mut epkt = parser.sub_packet(elen)?;

            match etype {
                0 => { // Server Name Indication
                    epkt.skip_u16()?; // Name list length
                    let name_list_type = epkt.read_u8()?;
                    if name_list_type != 0 {
                        // Should be 0 for HostName type
                        return Err(ParseErr::Invalid("TLS SNI ServerNameType should be 0"));
                    }
                    let name_len = epkt.read_u16_be()? as usize;
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
                    let alpn_len = epkt.read_u16_be()? as usize;
                    if alpn_len > epkt.remaining_len() {
                        return Err(ParseErr::Invalid("TLS ClientHello ALPN extension len > than advertised extension len"));
                    }
                    epkt.shrink(alpn_len);
                    while epkt.remaining_len() > 0 {
                        let proto_len = epkt.read_u8()? as usize;
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
            conn_info,
            version: ver_enum,
            server_name,
            next_proto,
        };


        let evt = Event::new(parser.timestamp(), EventPayload::NetTlsClientHello(evt_pload));
        evt.send();


        Ok(())
    }
}
