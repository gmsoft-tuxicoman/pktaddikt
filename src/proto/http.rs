
use crate::stream::{PktStreamProcessor, PktStreamParser, StreamParseResult};
use crate::packet::PktInfoStack;
use crate::conntrack::ConntrackDirection;

use memchr::memchr;
use tracing::trace;

#[derive(Debug)]
enum ProtoHttpState {
    FirstLine,
    Headers,
    Body,
}


#[derive(Debug)]
pub struct ProtoHttp {

    state: ProtoHttpState,
    client_dir: Option<ConntrackDirection>,
    method: Option<String>,
    version: Option<String>,
    uri: Option<String>,
}

impl ProtoHttp {

    fn parse_first_line(&mut self, dir: ConntrackDirection, mut parser: PktStreamParser) -> StreamParseResult {

        let line_opt = parser.readline();
        let line = match line_opt {
            Some(ref l) => l,
            None => return StreamParseResult::NeedData,
        };

        trace!("Parsing first line : {}", String::from_utf8_lossy(line));

        // Both query and response have 3 tokens
        // FIXME add HTTP/0.9 suppport
        let end1 = match memchr(b' ', line) {
            Some(o) => o,
            None => return StreamParseResult::Invalid,
        };


        let tok1 = &line[..end1];

        let mut start2 = end1 + 1;
        while start2 < line.len() {
            if line[start2] == b' ' {
                start2 += 1;
            } else {
                break;
            }
        }

        let end2 = match memchr(b' ', &line[start2..]) {
            Some(o) => o + start2,
            None => return StreamParseResult::Invalid,
        };

        let tok2 = &line[start2..end2];

        let mut start3 = end2 + 1;
        while start3 < line.len() {
            if line[start3] == b' ' {
                start3 += 1;
            } else {
                break;
            }
        }

        let tok3 = &line[start3..];

        // We got a slice with the first 3 tokens
        // Let's see if we have a query or a response



        match tok1.len() > 5 && tok1[..5].eq_ignore_ascii_case(b"HTTP/") {
            false => {
                // We got a request
                match self.client_dir {
                    None => { self.client_dir = Some(dir); },
                    Some(d) => {
                        if d != dir {
                            // We got a request in the wrong direction
                            return StreamParseResult::Invalid;
                        }
                    }
                };
                self.parse_request(tok1, tok2, tok3)
            },
            true => {
                self.parse_response(tok1, tok2, tok3)
            }
        }

    }

    fn parse_request(&mut self, method: &[u8], uri: &[u8], version: &[u8]) -> StreamParseResult {

        // Make sure we got something that looks like a method
        for &b in method {
            // Method are supposed to be [a-zA-Z]*
            if b < b'A' || (b > b'Z' && b < b'a') || b > b'z' {
                return StreamParseResult::Invalid;
            }
        }

        // Check that the version is valid
        if ! version.starts_with(b"HTTP/") { // Case sensitive check
            if version.len() < 8 || ! version[0..5].eq_ignore_ascii_case(b"HTTP/") {
                // Version is not valid
                return StreamParseResult::Invalid;
            } else {
                // Version matched but it's not uppercase
                // WEIRD
            }
        }

        self.method = Some(String::from_utf8_lossy(method).into_owned());
        trace!("HTTP Method: {}", self.method.as_ref().unwrap());
        self.uri = Some(String::from_utf8_lossy(uri).into_owned());
        trace!("HTTP URI: {}", self.uri.as_ref().unwrap());
        self.version = Some(String::from_utf8_lossy(version).into_owned());
        trace!("HTTP Version: {}", self.version.as_ref().unwrap());

        self.state = ProtoHttpState::Headers;
        StreamParseResult::Ok
    }

    fn parse_response(&mut self, _version: &[u8], status: &[u8], _reason: &[u8]) -> StreamParseResult {

        // Parse status code

        let mut status_code = 0usize;

        for &b in status {
            if b < b'0' || b > b'9' {
                return StreamParseResult::Invalid;
            }

            status_code = status_code * 10 + (b - b'0') as usize;
        }

        trace!("HTTP Status code: {}", status_code);

        self.state = ProtoHttpState::Headers;

        StreamParseResult::Ok
    }

    fn parse_headers(&mut self, dir: ConntrackDirection, mut parser: PktStreamParser) -> StreamParseResult {
        let line_opt = parser.readline();
        let line = match line_opt {
            Some(ref l) => l,
            None => return StreamParseResult::NeedData,
        };

        if line.len() == 0 {
            self.state = ProtoHttpState::Body;
            return StreamParseResult::Ok;
        }

        let colon = match memchr(b':', line) {
            Some(o) => o,
            None => return StreamParseResult::Invalid,
        };

        let name = &line[..colon];


        let mut value = colon + 1;
        while value < line.len() {
            if line[value] == b' ' {
                value += 1;
            } else {
                break;
            }
        }

        let value = &line[value..];

        trace!("HTTP header: \"{}: {}\"",  String::from_utf8_lossy(name), String::from_utf8_lossy(value));

        StreamParseResult::Ok
    }

    fn parse_body(&self, dir: ConntrackDirection, mut parser: PktStreamParser) -> StreamParseResult {
        StreamParseResult::Done
    }
}

impl PktStreamProcessor for ProtoHttp {

    fn new(infos: &PktInfoStack) -> Self {
        ProtoHttp {
            state: ProtoHttpState::FirstLine,
            client_dir: None,
            method: None,
            version: None,
            uri: None,
        }
    }

    fn process(&mut self, dir: ConntrackDirection, mut parser: PktStreamParser) -> StreamParseResult {

        match self.state {
            ProtoHttpState::FirstLine => self.parse_first_line(dir, parser),
            ProtoHttpState::Headers => self.parse_headers(dir, parser),
            ProtoHttpState::Body => self.parse_body(dir, parser),
        }
    }

}

#[cfg(test)]
mod tests {

    use crate::packet::{Packet, PktDataOwned, PktInfoStack, PktTime};
    use crate::proto::{Protocols, ProtoInfo};
    use crate::stream::PktStream;
    use crate::conntrack::ConntrackDirection;
    use crate::proto::ipv4::ProtoIpv4Info;
    use crate::proto::tcp::ProtoTcpInfo;
    use std::net::Ipv4Addr;


    #[test]
    fn http_parse_basic() {

        let mut infos = PktInfoStack::new(Protocols::Ipv4);
        let mut info = infos.proto_last_mut();

        info.proto_info = Some(ProtoInfo::Ipv4(ProtoIpv4Info {
            src: Ipv4Addr::new(10, 0, 0, 1),
            dst: Ipv4Addr::new(10, 0, 0, 2),
            id: 0,
            hdr_len: 0,
            ttl: 0,
            proto: 17,
        }));

        infos.proto_push(Protocols::Tcp, None);

        info = infos.proto_last_mut();

        info.proto_info = Some(ProtoInfo::Tcp(ProtoTcpInfo {
            sport: 1234,
            dport: 80,
            seq: 0,
            ack: 0,
            window: 0,
            flags: 0,
        }));

        infos.proto_push(Protocols::Http, None);

        let mut stream = PktStream::new(Protocols::Http, &infos).unwrap();

        let pkt_data = PktDataOwned::new(b"GET / HTTP/1.1\r\n");
        let mut pkt = Packet::new(PktTime::from_micros(0), pkt_data);
        stream.process_packet(ConntrackDirection::Forward, &mut pkt);

        println!("{:?}", stream.proto());

    }


}
