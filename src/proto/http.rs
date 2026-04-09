
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
                // We got a response
                StreamParseResult::Ok
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
        self.uri = Some(String::from_utf8_lossy(uri).into_owned());
        self.version = Some(String::from_utf8_lossy(version).into_owned());

        self.state = ProtoHttpState::Headers;
        StreamParseResult::Ok
    }

    fn parse_headers(&self, dir: ConntrackDirection, mut parser: PktStreamParser) -> StreamParseResult {
        StreamParseResult::Done
    }

    fn parse_body(&self, dir: ConntrackDirection, mut parser: PktStreamParser) -> StreamParseResult {
        StreamParseResult::Ok
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
    use crate::proto::Protocols;
    use crate::param::{Param, ParamValue};
    use crate::stream::PktStream;
    use crate::conntrack::ConntrackDirection;
    use std::net::Ipv4Addr;


    #[test]
    fn http_parse_basic() {

        let mut infos = PktInfoStack::new(Protocols::Ipv4);
        let mut info = infos.proto_last_mut();
        info.field_push(Param { name: "src", value: Some(ParamValue::Ipv4(Ipv4Addr::new(10, 0, 0, 1))) });
        info.field_push(Param { name: "dst", value: Some(ParamValue::Ipv4(Ipv4Addr::new(10, 0, 0, 2))) });

        infos.proto_push(Protocols::Tcp, None);
        info = infos.proto_last_mut();
        info.field_push(Param { name: "sport", value: Some(ParamValue::U16(1234)) });
        info.field_push(Param { name: "dport", value: Some(ParamValue::U16(80)) });

        infos.proto_push(Protocols::Http, None);

        let mut stream = PktStream::new(Protocols::Http, &infos).unwrap();

        let pkt_data = PktDataOwned::new(b"GET / HTTP/1.1\r\n");
        let mut pkt = Packet::new(PktTime::from_micros(0), pkt_data);
        stream.process_packet(ConntrackDirection::Forward, &mut pkt);

        println!("{:?}", stream.proto());

    }


}
