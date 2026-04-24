use crate::stream::{PktStreamProcessor, PktStreamParser, StreamParseResult, PktSubStream, PktSubStreamData};
use crate::packet::{PktInfoStack, PktConnInfo, PktTime};
use crate::conntrack::ConntrackDirection;
use crate::event::{EventId, EventStr, EventPayload, Event};


use tracing::trace;
use serde::Serialize;


#[derive(Debug, Serialize)]
pub struct NetTlsClientHello {
    pub conn_id: EventId,
    #[serde(flatten)]
    pub conn_info: PktConnInfo,
    pub version: TlsVersion,
    pub server_name: Option<EventStr>,
    pub next_proto: Option<EventStr>,
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

    fn read_record(&mut self, dir: ConntrackDirection, mut parser: PktStreamParser) -> StreamParseResult {
        let Some(data) = parser.read(5) else {
            return StreamParseResult::NeedData;
        };

        let status = &mut self.dir[dir as usize];
        
        status.rlen = ((data[3] as usize) << 8) + (data[4] as usize);

        if status.rlen > 16384 {
            return StreamParseResult::Invalid;
        }

        status.state = match data[0] {
            20 => ProtoTlsState::ChangeCipher,
            21 => ProtoTlsState::Alert,
            22 => ProtoTlsState::Handshake,
            23 => ProtoTlsState::ApplicationData,
            24 => ProtoTlsState::HeartBeat,
            _ => ProtoTlsState::Invalid,
        };

        trace!("Got TLS record of type {:?} and length {}", status.state, status.rlen);

        StreamParseResult::Ok

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

    fn process(&mut self, dir: ConntrackDirection, mut parser: PktStreamParser) -> StreamParseResult {

        let ts = parser.timestamp();
        let status = &mut self.dir[dir as usize];

        if status.state == ProtoTlsState::RecordHeader {
            return self.read_record(dir, parser);
        }

        let Some(data) = parser.read(status.rlen) else {
            return StreamParseResult::NeedData;
        };

        let ret = match status.state {
            ProtoTlsState::Handshake => {
                let mut stream_data = status.handshake_stream.add_data(&data);
                status.handshake_proto.process(dir, &mut stream_data, ts, &self.conn_id, self.conn_info)
            }
            ProtoTlsState::ChangeCipher => {
                if data[0] != 1 {
                    return StreamParseResult::Invalid;
                }
                // Stop trying to process the stream for now
                StreamParseResult::Done
            }
            _ => StreamParseResult::Done,
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

    fn process(&mut self, _dir: ConntrackDirection, stream: &mut PktSubStreamData, ts: PktTime, conn_id: &EventId, conn_info: PktConnInfo) -> StreamParseResult {
            
        if self.ctype.is_none() {
            let Some(data) = stream.read(4) else {
                return StreamParseResult::NeedData;
            };
            let ctype = match data[0] {
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
                _ => return StreamParseResult::Invalid,
            };
            self.clen = ((data[1] as usize) << 16) + ((data[2] as usize) << 8) + (data[3] as usize);

            if self.clen > 16384 {
                // According to RFC, record len should be less than 16k (2^14)
                return StreamParseResult::Invalid;
            }

            trace!("Got handshake of type {:?} and len {}", ctype, self.clen);

            self.ctype = Some(ctype);
        }

        let Some(data) = stream.read(self.clen) else {
            return StreamParseResult::NeedData;
        };

        let ret = match self.ctype {
            Some(ProtoTlsHandshakeType::ClientHello) => self.parse_client_hello(&data, ts, conn_id, conn_info),
            _ => StreamParseResult::Ok,
        };

        self.ctype = None;
        self.clen = 0;

        ret
    }

    fn parse_client_hello(&self, data: &[u8], ts: PktTime, conn_id: &EventId, conn_info: PktConnInfo) -> StreamParseResult {

        if data.len() < 34 {
            return StreamParseResult::Invalid;
        }

        let mut version = ((data[0] as usize) << 8) + (data[1] as usize);

        // Skip over random (32 bytes)

        let session_id_len = data[34] as usize;

        if session_id_len > 32 {
            return StreamParseResult::Invalid;
        }

        let mut pos = 34 + 1 + session_id_len;


        // Parse and validate cipher suite length
        if data.len() < pos + 2 {
            return StreamParseResult::Invalid;
        }
        let cipher_suite_len = ((data[pos] as usize) << 8) + (data[pos + 1] as usize);

        pos += 2 + cipher_suite_len;


        // Parse and validate compression method len
        if data.len() < pos + 1 {
            return StreamParseResult::Invalid;
        }
        let compression_method_len = data[pos] as usize;
        pos += 1 + compression_method_len;

        // Check for presense of extensions
        if data.len() < pos {
            return StreamParseResult::Invalid;
        } else if data.len() == pos {
            // No extension
            return StreamParseResult::Ok
        }

        // Parse and validate extensions}
        if data.len() < pos + 2 {
            return StreamParseResult::Invalid;
        }
        let extensions_len = ((data[pos] as usize) << 8) + (data[pos + 1] as usize);
        pos += 2;
        if data.len() < pos + extensions_len {
            return StreamParseResult::Invalid;
        }

        let extensions = &data[pos..pos+extensions_len];

        let mut server_name: Option<EventStr> = None;
        let mut next_proto: Option<EventStr> = None;

        let mut ep = 0;
        while ep < extensions.len() {

            if ep + 4 > extensions.len() {
                return StreamParseResult::Invalid;
            }

            let etype = ((extensions[ep] as usize) << 8) + (extensions[ep + 1] as usize);
            let elen = ((extensions[ep + 2] as usize) << 8) + (extensions[ep + 3] as usize);
            ep += 4;

            if ep + elen > extensions.len() {
                return StreamParseResult::Invalid;
            }
            let ext = &extensions[ep .. ep + elen];

            ep += elen;
            match etype {
                0 => { // Server Name Indication
                    if ext.len() < 5 {
                        return StreamParseResult::Invalid;
                    }
                    let name_list_len = ((ext[0] as usize) << 8) + (ext[1] as usize);
                    if ext[2] != 0 {
                        // Should be 0 for HostName type
                        return StreamParseResult::Invalid;
                    }
                    let name_len = ((ext[3] as usize) << 8) + (ext[4] as usize);
                    if name_len + 5 > ext.len() {
                        return StreamParseResult::Invalid;
                    }
                    let hostname = &ext[5..5+name_len];
                    trace!("Found SNI with hostname: {}", String::from_utf8_lossy(hostname));
                    server_name = Some(hostname.to_vec().into());

                    if name_list_len > name_len + 3 {
                        trace!("SNI with multiple hostnames found");
                    }
                },
                43 => { // Supported version
                    if ext.len() < 2 {
                        return StreamParseResult::Invalid;
                    }
                    version = ((ext[0] as usize) << 8) + (ext[1] as usize);

                }

                17513 | 17613 => { // draft-vvv-tls-alps-01
                    if ext.len() < 5 {
                        return StreamParseResult::Invalid;
                    }
                    // Skip over ALPS Extension lenght and check the proto name directly
                    let alpn_len = ext[3] as usize;
                    if alpn_len + 2 < ext.len() {
                        return StreamParseResult::Invalid;
                    }
                    let proto = &ext[3 .. 3 + alpn_len];
                    trace!("Found next protocol: {}", String::from_utf8_lossy(proto));
                    next_proto = Some(proto.to_vec().into());

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


        let evt = Event::new(ts, EventPayload::NetTlsClientHello(evt_pload));
        evt.send();


        StreamParseResult::Ok
    }
}
