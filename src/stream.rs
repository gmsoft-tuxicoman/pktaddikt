use crate::packet::{Packet, PktInfoStack, PktTime};
use crate::proto::Protocols;
use crate::conntrack::ConntrackDirection;
use crate::proto::test::ProtoTest;
use crate::proto::http::ProtoHttp;

use std::borrow::Cow;
use memchr::memchr;

pub trait PktStreamProcessor {
    fn new(infos: &PktInfoStack) -> Self;
    fn process(&mut self, dir: ConntrackDirection, parser: PktStreamParser) -> StreamParseResult;
}

pub enum PktStreamProto {
    Test(ProtoTest),
    Http(ProtoHttp),
}

pub struct PktStream {

    proto: PktStreamProto,
    pkt_buff_fwd: Vec<Packet<'static>>,
    pkt_buff_rev: Vec<Packet<'static>>,
    is_active: bool,

}

#[derive(PartialEq, Debug)]
pub enum StreamParseResult {
    Ok, // Some item was parsed, waiting for more stuff to parse
    NeedData, // Tried to parse something but there was not enough data
    Done, // WIP Done parsing
    Invalid, // Parsing failed
}

pub struct PktStreamParser<'a, 'b> {
    pkt: &'a mut Packet<'b>,
    pkt_buff: &'a mut Vec<Packet<'static>>
}

impl PktStream {

    pub fn new(proto: Protocols, infos: &PktInfoStack) -> Option<PktStream> {
        Some(PktStream {
            proto: match proto {
                Protocols::Test => PktStreamProto::Test(<ProtoTest as PktStreamProcessor>::new(infos)),
                Protocols::Http => PktStreamProto::Http(ProtoHttp::new(infos)),
                _ => return None
            },
            pkt_buff_fwd: Vec::new(),
            pkt_buff_rev: Vec::new(),
            is_active: true,
        })
    }

    pub fn is_active(&self) -> bool {
        self.is_active
    }

    #[cfg(test)]
    pub fn add_expectation(&mut self, data: &[u8], ts: PktTime) {
        let PktStreamProto::Test(ref mut test) = self.proto else {
            panic!("Stream proto is not Test");
        };
        test.add_expectation(data, ts);
    }

    pub fn process_packet(&mut self, dir: ConntrackDirection, pkt: &mut Packet) {

        if ! self.is_active {
            return;
        }

        let pkt_buff =  match dir {
            ConntrackDirection::Forward => &mut self.pkt_buff_fwd,
            ConntrackDirection::Reverse => &mut self.pkt_buff_rev,
        };


        let ret = loop {
            let parser = PktStreamParser::new(pkt, pkt_buff);
            let ret = match &mut self.proto {
                PktStreamProto::Test(p) => p.process(dir, parser),
                PktStreamProto::Http(p) => p.process(dir, parser),
            };

            if ret != StreamParseResult::Ok {
                // Parsing cannot continue
                break ret;
            }

            if pkt.remaining_len() == 0 {
                // No more data to parse
                break StreamParseResult::Ok;
            }
        };

        if ret == StreamParseResult::NeedData && pkt.remaining_len() > 0 {
            pkt_buff.push(pkt.clone());
        } else if ret == StreamParseResult::Invalid || ret == StreamParseResult::Done {
            self.is_active = false;
            return;
        }
    }
}

impl<'a, 'b> PktStreamParser<'a, 'b> {

    fn new(pkt: &'a mut Packet<'b>, pkt_buff: &'a mut Vec<Packet<'static>>) -> PktStreamParser<'a, 'b> {
        PktStreamParser {
            pkt: pkt,
            pkt_buff: pkt_buff
        }
    }

    fn buffered_len(&self) -> usize {
        let mut len :usize = 0;
        for buf in self.pkt_buff.iter() {
            len += buf.remaining_len();
        }
        len
    }

    pub fn timestamp(&self) -> PktTime {
        self.pkt.ts
    }

    pub fn remaining_len(&self) -> usize {
        self.pkt.remaining_len() + self.buffered_len()
    }

    pub fn remaining_data(&mut self) -> Cow<'_, [u8]> {
        if self.pkt_buff.len() == 0 {
            return Cow::Borrowed(self.pkt.remaining_data());
        }

        let mut data = Vec::with_capacity(self.remaining_len());
        for buf in self.pkt_buff.iter_mut() {
            data.extend_from_slice(buf.remaining_data());
        }
        data.extend_from_slice(self.pkt.remaining_data());
        self.pkt_buff.clear();
        Cow::Owned(data)

    }


    pub fn readline(&mut self) -> Option<Cow<'_, [u8]>> {
        // Assume the line is not in the buffered packets
        let mut off;
        let mut skip;

        {
            let peek = self.pkt.peek();
            off = memchr(b'\n', peek)?;
            skip = 1;

            if off > 1 && peek[off - 1] == b'\r' {
                off -= 1;
                skip += 1;
            }
        }

        if self.pkt_buff.len() == 0 {
            return Some(Cow::Borrowed(&self.pkt.read_bytes(off + skip).as_ref().unwrap()[..off]));
        }

        let mut data = Vec::with_capacity(self.buffered_len() + off);
        for buf in self.pkt_buff.iter_mut() {
            data.extend_from_slice(buf.remaining_data());
        }
        data.extend_from_slice(self.pkt.read_bytes(off)?);
        let _ = self.pkt.skip_bytes(skip);
        self.pkt_buff.clear();
        Some(Cow::Owned(data))
    }

}
