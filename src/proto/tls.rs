use crate::stream::{PktStreamProcessor, PktStreamParser, StreamParseResult, PktSubStream, PktSubStreamData};
use crate::packet::{PktInfoStack, PktTime};
use crate::conntrack::ConntrackDirection;

use tracing::trace;

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

    dir: [ProtoTlsDir;2]
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
            dir: [ProtoTlsDir::default(), ProtoTlsDir::default()]
        }
    }

    fn process(&mut self, dir: ConntrackDirection, mut parser: PktStreamParser) -> StreamParseResult {

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
                status.handshake_proto.process(dir, &mut stream_data)
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
    Invalid,
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

    fn process(&mut self, dir: ConntrackDirection, stream: &mut PktSubStreamData) -> StreamParseResult {
            
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

            trace!("Got handshake of type {:?} and len {}", ctype, self.clen);

            self.ctype = Some(ctype);
            return StreamParseResult::Ok;
        }

        let _data = stream.read(self.clen);
        self.ctype = None;
        self.clen = 0;

        StreamParseResult::Ok
    }
}
