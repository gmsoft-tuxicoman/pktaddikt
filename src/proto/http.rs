
use crate::stream::{PktStreamProcessor, PktStreamParser, StreamParseResult};
use crate::packet::PktInfoStack;
use crate::conntrack::ConntrackDirection;

use memchr::memchr;
use tracing::trace;

enum ProtoHttpState {
    FirstLine,
    Headers,
    Body,
}

pub struct ProtoHttp {

    state: ProtoHttpState,
    client_dir: Option<ConntrackDirection>,
}

impl ProtoHttp {

    fn parse_first_line(&mut self, dir: ConntrackDirection, mut parser: PktStreamParser) -> StreamParseResult {

        let line_opt = parser.readline();
        let line = match line_opt {
            Some(ref l) => l,
            None => return StreamParseResult::NeedData,
        };

        // Both query and response have 3 tokens
        let end1 = match memchr(b' ', line) {
            Some(o) => o,
            None => return StreamParseResult::Invalid,
        };

        let tok1 = &line[..end1];
        trace!("Token 1 : {}", String::from_utf8_lossy(tok1));

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
        trace!("Token 2 : {}", String::from_utf8_lossy(tok2));

        let mut start3 = end2 + 1;
        while start3 < line.len() {
            if line[start3] == b' ' {
                start3 += 1;
            } else {
                break;
            }
        }

        let tok3 = &line[start3..];
        trace!("Token 3 : {}", String::from_utf8_lossy(tok3));

        trace!("HTTP LINE ! {}", String::from_utf8_lossy(line));

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
