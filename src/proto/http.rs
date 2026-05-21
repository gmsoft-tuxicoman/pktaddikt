use crate::base::{Parser, ParseErr};
use crate::stream::{PktStreamProcessor, PktStreamParser};
use crate::packet::{PktInfoStack, PktTime, PktConnInfo};
use crate::conntrack::ConntrackDirection;
use crate::event::{Event, EventPayload, EventStr, EventKind};
use crate::messagebus::MessageBus;
use crate::base::{atoi, htoi, UniqueId};
use crate::blob::Blob;

use memchr::memchr;
use tracing::trace;
use serde::Serialize;
use std::cmp;

#[derive(Debug, Serialize)]
pub struct NetHttpRequestBasic {
    pub conn_id: UniqueId,
    #[serde(flatten)]
    pub conn_info: PktConnInfo,
    pub ts: PktTime,
    pub method: String,
    pub version: String,
    pub uri: EventStr,
}


#[derive(Debug, Serialize)]
pub struct NetHttpRequestFull {
    pub base: NetHttpRequestBasic,
    pub headers: Vec<(EventStr, EventStr)>
}

#[derive(Debug, Serialize)]
pub struct NetHttpResponseBasic {
    pub conn_id: UniqueId,
    #[serde(flatten)]
    pub conn_info: PktConnInfo,
    pub ts: PktTime,
    pub status: u16,
    pub version: String,
    pub reason: EventStr,
}

#[derive(Debug, Serialize)]
pub struct NetHttpResponseFull {
    pub base: NetHttpResponseBasic,
    pub headers: Vec<(EventStr, EventStr)>,
}

#[derive(Debug)]
enum ProtoHttpState {
    FirstLine,
    Headers,
    Body,
}

#[derive(Debug)]
enum ProtoHttpEvent {
    RequestBasic(NetHttpRequestBasic),
    ResponseBasic(NetHttpResponseBasic),
}


#[derive(Debug)]
struct ProtoHttpStateInfo {

    state: ProtoHttpState,
    content_len: Option<u64>, // Either full Content-Length or chunk length
    content_pos: u64,
    chunked: bool,
    event_basic: Option<ProtoHttpEvent>,
    blob: Option<Blob>,
}

impl ProtoHttpStateInfo {

    fn reset(&mut self) {
        self.state = ProtoHttpState::FirstLine;
        self.content_len = None;
        self.content_pos = 0;
        self.chunked = false;

        if let Some(e) = self.event_basic.take() {
            let evt = match e {
                ProtoHttpEvent::RequestBasic(p) => Event::new(p.ts, EventPayload::NetHttpRequestBasic(p)),
                ProtoHttpEvent::ResponseBasic(p) => Event::new(p.ts, EventPayload::NetHttpResponseBasic(p)),
            };
            MessageBus::publish_event(evt);
        }
        self.event_basic = None;
        self.blob = None;
    }
}

#[derive(Debug)]
pub struct ProtoHttp {

    client_dir: Option<ConntrackDirection>,
    info: [ProtoHttpStateInfo;2],
    conn_id: UniqueId,
    conn_info: PktConnInfo,
    last_status: u16,
}

impl ProtoHttp {

    fn parse_first_line(&mut self, dir: ConntrackDirection, mut parser: PktStreamParser) -> Result<(), ParseErr> {

        // Check if there is any reason to parse Http stuff first
        if ! (MessageBus::event_has_subscribers(EventKind::NetHttpRequestBasic)
            || MessageBus::event_has_subscribers(EventKind::NetHttpResponseBasic)) {
            // All done, nothing to parse
            return Err(ParseErr::Stop);
        }


        let ts = parser.timestamp();

        let line = parser.readline()?;

        trace!("Parsing first line : {}", String::from_utf8_lossy(&line));

        // Both query and response have 3 tokens
        // FIXME add HTTP/0.9 suppport
        let end1 = match memchr(b' ', &line) {
            Some(o) => o,
            None => return Err(ParseErr::Invalid("Not enough words in HTTP query")),
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
            None => return Err(ParseErr::Invalid("Could not find second word in HTTP first line")),
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
                            return Err(ParseErr::Invalid("Request received from the client"));
                        }
                    }
                };
                self.parse_request(tok1, tok2, tok3, dir, ts)
            },
            true => {
                self.parse_response(tok1, tok2, tok3, dir, ts)
            }
        }

    }

    fn parse_request(&mut self, method: &[u8], uri: &[u8], version: &[u8], dir: ConntrackDirection, ts: PktTime) -> Result<(), ParseErr> {

        // Make sure we got something that looks like a method
        for &b in method {
            // Method are supposed to be [a-zA-Z]*
            if b < b'A' || (b > b'Z' && b < b'a') || b > b'z' {
                return Err(ParseErr::Invalid("HTTP method contains other characters than letters"));
            }
        }

        // Check that the version is valid
        if ! version.starts_with(b"HTTP/") { // Case sensitive check
            if version.len() < 8 || ! version[0..5].eq_ignore_ascii_case(b"HTTP/") {
                // Version is not valid
                return Err(ParseErr::Invalid("Invalid HTTP version received"));
            } else {
                // Version matched but it's not uppercase
                // WEIRD
            }
        }
        self.info[dir as usize].state = ProtoHttpState::Headers;

        if ! MessageBus::event_has_subscribers(EventKind::NetHttpRequestBasic) {
            return Ok(());
        }

        let evt = NetHttpRequestBasic {
            conn_id: self.conn_id.clone(),
            conn_info: self.conn_info,
            ts,
            method: String::from_utf8_lossy(method).into_owned(),
            version: String::from_utf8_lossy(version).into_owned(),
            uri: uri.into(),
        };

        trace!("HTTP Method: {}", evt.method);
        trace!("HTTP URI: {}", String::from_utf8_lossy(&evt.uri));
        trace!("HTTP Version: {}", evt.version);

        self.info[dir as usize].event_basic = Some(ProtoHttpEvent::RequestBasic(evt));

        Ok(())
    }

    fn parse_response(&mut self, version: &[u8], status: &[u8], reason: &[u8], dir: ConntrackDirection, ts: PktTime) -> Result<(), ParseErr> {

        // Parse status code

        let Some(status_code) = atoi(status) else {
            return Err(ParseErr::Invalid("Could not parse status code"));
        };

        self.info[dir as usize].state = ProtoHttpState::Headers;
        self.last_status = status_code as u16;

        if ! MessageBus::event_has_subscribers(EventKind::NetHttpResponseBasic) {
            return Ok(());
        }

        trace!("HTTP Status code: {}", status_code);

        let evt = NetHttpResponseBasic {
            conn_id: self.conn_id.clone(),
            conn_info: self.conn_info,
            ts,
            version: String::from_utf8_lossy(version).into_owned(),
            status: status_code as u16,
            reason: reason.into(),

        };

        self.info[dir as usize].event_basic = Some(ProtoHttpEvent::ResponseBasic(evt));

        Ok(())
    }

    fn parse_headers(&mut self, dir: ConntrackDirection, mut parser: PktStreamParser) -> Result<(), ParseErr> {
        let line = parser.readline()?;

        if line.len() == 0 {
            // All headers are processed

            // Send the basic event here

            if let Some(e) = self.info[dir as usize].event_basic.take() {
                let evt = match e {
                    ProtoHttpEvent::RequestBasic(p) => Event::new(p.ts, EventPayload::NetHttpRequestBasic(p)),
                    ProtoHttpEvent::ResponseBasic(p) => Event::new(p.ts, EventPayload::NetHttpResponseBasic(p)),
                };
                MessageBus::publish_event(evt);
            }

            if self.info[dir as usize].chunked && self.info[dir as usize].content_len.is_some() {
                // Ignore Content-Length for chunked transfers
                self.info[dir as usize].content_len = None;
            }


            if let Some(clen) = self.info[dir as usize].content_len {

                if clen == 0 {
                    // Content length is 0, no body
                    self.info[dir as usize].reset();
                    return Ok(());
                }

            } else if Some(dir) == self.client_dir {
                // It's a query and no Content-Length was provided
                if ! self.info[dir as usize].chunked {
                    // No body expected
                    self.info[dir as usize].reset();
                    return Ok(());
                }
            }

            // Some status code should not contain any body
            if Some(dir.opposite()) == self.client_dir && ((self.last_status >= 100 && self.last_status < 200) || self.last_status == 204 || self.last_status == 304) {
                    // No body expected
                    self.info[dir as usize].reset();
                    return Ok(());
            }

            self.info[dir as usize].state = ProtoHttpState::Body;
            return Ok(());
        }

        let colon = match memchr(b':', &line) {
            Some(o) => o,
            None => return Err(ParseErr::Invalid("Could not find ':' in header line"))
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

        if self.info[dir as usize].content_len.is_none() {
            if name.eq_ignore_ascii_case(b"Content-Length") {
                self.info[dir as usize].content_len = atoi(value);
                if self.info[dir as usize].content_len.is_none() {
                    return Err(ParseErr::Invalid("Could not parse Content-Length header"));
                }
            }
        }

        if ! self.info[dir as usize].chunked {
            if name.eq_ignore_ascii_case(b"Transfer-Encoding") && value.eq_ignore_ascii_case(b"chunked") {
                self.info[dir as usize].chunked = true;
            }
        }

        trace!("HTTP header: \"{}: {}\"",  String::from_utf8_lossy(name), String::from_utf8_lossy(value));

        Ok(())
    }

    fn parse_body(&mut self, dir: ConntrackDirection, mut parser: PktStreamParser) -> Result<(), ParseErr> {

        if let Some(content_len) = self.info[dir as usize].content_len {
            let mut remaining_len = content_len - self.info[dir as usize].content_pos;

            let blob = self.info[dir as usize].blob.get_or_insert_with(|| Blob::new(parser.timestamp(), None).set_size(content_len));
            let data_len = cmp::min(remaining_len as u32, parser.remaining_len());

            blob.data(self.info[dir as usize].content_pos, parser.sub_packet(data_len)?);

            self.info[dir as usize].content_pos += data_len as u64;
            trace!("Got {} bytes of payload ({}/{})", data_len, self.info[dir as usize].content_pos, content_len);
            remaining_len -= data_len as u64;

            if remaining_len == 0 {
                // Payload done
                trace!("Payload complete");
                self.info[dir as usize].reset();

            }
        } else {
            // No Content-Length, must be a HTTP/1.0 response containing the whole body

            let blob = self.info[dir as usize].blob.get_or_insert_with(|| Blob::new(parser.timestamp(), None));
            let data_len = parser.remaining_len();
            blob.data(self.info[dir as usize].content_pos, parser.sub_packet(data_len)?);
            trace!("Got {} bytes of payload", data_len);
            self.info[dir as usize].content_pos += data_len as u64;

        }

        Ok(())
    }

    fn parse_body_chunked(&mut self, dir: ConntrackDirection, mut parser: PktStreamParser) -> Result<(), ParseErr> {


        if let Some(chunk_len) = self.info[dir as usize].content_len {

            // We already have a chunk len, let's see what remains to be parsed

            let remaining_len = chunk_len - self.info[dir as usize].content_pos;

            if remaining_len > 0 {
                // remaining_len will be 0 if we go the content but not the CRLF
                // FIXME actually use the data
                let data_len = cmp::min(remaining_len as u32, parser.remaining_len());
                parser.skip(data_len)?;
                self.info[dir as usize].content_pos += data_len as u64;
                trace!("Got {} of chunked payload ({}/{})", data_len, self.info[dir as usize].content_pos, chunk_len);
            }

            let line = parser.readline()?;

            if line.len() > 0 {
                // Line is supposed to be empty
                return Err(ParseErr::Invalid("Non-empty line after chunked size"));
            }

            self.info[dir as usize].content_len = None;
            if chunk_len == 0 {
                self.info[dir as usize].reset();
                trace!("End of chunked content");
            } else {
                trace!("End of chunk");
            }

        } else {

            // First, read the chunk length

            let line = parser.readline()?;

            if line.len() > 10 {
                // Chunk is wayy too big
                return Err(ParseErr::Invalid("Chunk size too big"));
            }

            self.info[dir as usize].content_len = htoi(&line);
            if self.info[dir as usize].content_len.is_none() {
                // Unable to parse chunk length
                return Err(ParseErr::Invalid("Unable to parse chunk length"));
            }

            trace!("Got chunk of {} bytes", self.info[dir as usize].content_len.unwrap());
            self.info[dir as usize].content_pos = 0;

        }

        Ok(())
    }
}

impl PktStreamProcessor for ProtoHttp {

    fn new(infos: &PktInfoStack) -> Self {


        ProtoHttp {
            conn_id: infos.get_conn_id().unwrap().clone(),
            conn_info: infos.get_conn_info(),
            info:  [ ProtoHttpStateInfo {
                state: ProtoHttpState::FirstLine,
                content_len: None,
                content_pos: 0,
                chunked: false,
                event_basic: None,
                blob: None,
            },
             ProtoHttpStateInfo {
                state: ProtoHttpState::FirstLine,
                content_len: None,
                content_pos: 0,
                chunked: false,
                event_basic: None,
                blob: None,
            } ],
            client_dir: None,
            last_status: 0,
        }
    }

    fn process(&mut self, dir: ConntrackDirection, parser: PktStreamParser) -> Result<(), ParseErr> {

        match self.info[dir as usize].state {
            ProtoHttpState::FirstLine => self.parse_first_line(dir, parser),
            ProtoHttpState::Headers => self.parse_headers(dir, parser),
            ProtoHttpState::Body => {

                if Some(dir.opposite()) == self.client_dir  && self.info[dir as usize].content_pos == 0 {
                    // We need to check if the body looks like a reply
                    // If it does, then we assume it's a reply to a HEAD request
                    let data = parser.peek(5)?;
                    if data[0..5].eq_ignore_ascii_case(b"HTTP/") {
                        trace!("Found reply to HEAD request");
                        self.info[dir as usize].reset();
                        return Ok(())
                    }
                }

                match self.info[dir as usize].chunked {
                    false => self.parse_body(dir, parser),
                    true => self.parse_body_chunked(dir, parser),
                }
            }
        }
    }

}
#[cfg(test)]
mod tests {

    use crate::packet::{Packet, PktInfoStack, PktTime};
    use crate::proto::{Protocols, ProtoInfo};
    use crate::stream::PktStream;
    use crate::conntrack::ConntrackDirection;
    use crate::proto::ipv4::ProtoIpv4Info;
    use crate::proto::tcp::ProtoTcpInfo;
    use crate::base::UniqueId;
    use std::net::Ipv4Addr;


    #[test]
    fn http_parse_basic() {

        let mut infos = PktInfoStack::new(Protocols::Ipv4);
        infos.set_conn_id(UniqueId::new(PktTime::from_micros(0)));

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

        let mut pkt = Packet::from_slice(PktTime::from_micros(0), b"GET / HTTP/1.1\r\n");
        stream.process_packet(ConntrackDirection::Forward, &mut pkt);

    }


}
