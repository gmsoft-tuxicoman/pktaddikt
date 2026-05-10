use crate::base::{Parser, ParseErr};
use crate::packet::{Packet, PktInfoStack, PktTime};
use crate::proto::Protocols;
use crate::conntrack::ConntrackDirection;
use crate::proto::test::ProtoTest;
use crate::proto::http::ProtoHttp;
use crate::proto::dns::ProtoDns;
use crate::proto::tls::ProtoTls;
use crate::proto::sunrpc::ProtoSunRpc;

use std::borrow::Cow;
use memchr::memchr;
use smallvec::SmallVec;
use std::sync::Arc;

pub trait PktStreamProcessor {
    fn new(infos: &PktInfoStack) -> Self;
    fn process(&mut self, dir: ConntrackDirection, parser: PktStreamParser) -> Result<(), ParseErr>;
}

#[derive(Debug)]
pub enum PktStreamProto {
    Test(ProtoTest),
    Http(ProtoHttp),
    Dns(ProtoDns),
    Tls(ProtoTls),
    SunRpc(ProtoSunRpc),
}

pub struct PktStream {

    proto: PktStreamProto,
    pkt_buff_fwd: SmallVec<[Packet<'static>; 1]>,
    pkt_buff_rev: SmallVec<[Packet<'static>; 1]>,
    is_active: bool,

}

impl PktStream {

    pub fn new(proto: Protocols, infos: &PktInfoStack) -> Option<PktStream> {
        Some(PktStream {
            proto: match proto {
                Protocols::Test => PktStreamProto::Test(<ProtoTest as PktStreamProcessor>::new(infos)),
                Protocols::Http => PktStreamProto::Http(ProtoHttp::new(infos)),
                Protocols::Dns => PktStreamProto::Dns(<ProtoDns as PktStreamProcessor>::new(infos)),
                Protocols::Tls => PktStreamProto::Tls(ProtoTls::new(infos)),
                Protocols::SunRpc => PktStreamProto::SunRpc(<ProtoSunRpc as PktStreamProcessor>::new(infos)),
                _ => return None
            },
            pkt_buff_fwd: SmallVec::new(),
            pkt_buff_rev: SmallVec::new(),
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
            let parser = PktStreamParser::new(pkt, pkt_buff, false);
            let ret = match &mut self.proto {
                PktStreamProto::Test(p) => p.process(dir, parser),
                PktStreamProto::Http(p) => p.process(dir, parser),
                PktStreamProto::Dns(p) => p.process(dir, parser),
                PktStreamProto::Tls(p) => p.process(dir, parser),
                PktStreamProto::SunRpc(p) => p.process(dir, parser),
            };

            if ret.is_err() {
                // Parsing cannot continue
                break ret;
            }

            if pkt.remaining_len() == 0 {
                // No more data to parse
                break Ok(());
            }
        };

        match ret {
            Ok(_) => return,
            Err(e) => match e {
                ParseErr::Truncated => {
                    if pkt.remaining_len() > 0 {
                        pkt_buff.push(pkt.to_owned());
                    }
                },
                _ => {
                    self.is_active = false;
                    return;
                }
            }
        }

    }

    #[cfg(test)]
    pub fn proto(&self) -> &PktStreamProto {
        &self.proto
    }
}

pub struct PktStreamParser<'a, 'b> {
    pkt: &'a mut Packet<'b>,
    pkt_buff: &'a mut SmallVec<[Packet<'static>; 1]>,
    save_on_drop: bool,
}

impl<'a, 'b> PktStreamParser<'a, 'b> {

    fn new(pkt: &'a mut Packet<'b>, pkt_buff: &'a mut SmallVec<[Packet<'static>; 1]>, save_on_drop: bool) -> PktStreamParser<'a, 'b> {
        PktStreamParser {
            pkt: pkt,
            pkt_buff: pkt_buff,
            save_on_drop,
        }
    }

    #[inline]
    fn buffered_len(&self) -> usize {
        let mut len :usize = 0;
        for buf in self.pkt_buff.iter() {
            len += buf.remaining_len();
        }
        len
    }

    #[cold]
    #[inline(never)]
    pub fn readline_slow(&mut self) -> Result<Cow<'_, [u8]>, ParseErr> {
        let mut newline: Option<(usize, usize)> = None;
        let fake_id = self.pkt_buff.len();
        for (pkt_id, pkt) in self.pkt_buff.iter().enumerate().chain(std::iter::once((fake_id, & *self.pkt))) {
            let peek = pkt.peek();
            if let Some(off) = memchr(b'\n', peek) {
                newline = Some((pkt_id, off));
                break;
            }
        }

        let (pkt_id, off) = newline.ok_or(ParseErr::Truncated)?;

        let mut ret = Vec::new();

        if pkt_id > 1 {
            // Consume all the buffers
            for _ in 0 .. pkt_id - 1 {
                let p = self.pkt_buff.remove(0);
                ret.extend_from_slice(p.peek());
            }
        }

        if pkt_id == fake_id {
            // Use self.pkt for last data
            ret.extend_from_slice(&self.pkt.read(off).unwrap());
        } else {
            // Use first packet left in the buffer
            ret.extend_from_slice(&self.pkt_buff[0].read(off).unwrap());
            if self.pkt_buff[0].remaining_len() == 0 {
                self.pkt_buff.remove(0);
            }

        }

        ret.pop(); // Remove \n

        if ret.len() > 1 && ret[ret.len() - 1] == b'\r' {
            ret.pop(); // Remove \r
        }

        Ok(Cow::Owned(ret))
    }

    #[inline]
    pub fn readline(&mut self) -> Result<Cow<'_, [u8]>, ParseErr> {
        if self.pkt_buff.is_empty() {
            let peek = self.pkt.peek();
            let Some(mut off) = memchr(b'\n', peek) else {
                return Err(ParseErr::Truncated);
            };
            let mut skip = 1;
            if off > 0 && peek[off - 1] == b'\r' {
                off -= 1;
                skip += 1;
            }

            let ret = self.pkt.read_skip(off, skip).unwrap();
            Ok(ret)

        } else {
            self.readline_slow()
        }
    }

    // Read exact number of bytes or nothing
    #[cold]
    #[inline(never)]
    fn read_slow(&mut self, mut len: usize) -> Result<Vec<u8>, ParseErr> {
        // Only called when there is something in the buffer

        self.has_len(len)?;

        let mut data = Vec::with_capacity(len);

        while let Some(p) = self.pkt_buff.first_mut() {
            if p.remaining_len() < len {
                // The whole packet will be used
                let mut p = self.pkt_buff.remove(0);
                len -= p.remaining_len();
                data.extend_from_slice(p.remaining_data());
            } else {
                // Use only what we need
                data.extend_from_slice(&p.read(len).unwrap());
                len = 0;
                break;
            }
        }

        if self.pkt.remaining_len() == len {
            data.extend_from_slice(self.pkt.remaining_data());
        } else if len > 0 {
            data.extend_from_slice(&self.pkt.read(len).unwrap());
        }

        Ok(data)

    }
    #[cold]
    #[inline(never)]
    fn read_fixed_slow<const N: usize>(&mut self) -> Result<[u8; N], ParseErr> {
        // Only called when there is something in the buffer
        let mut tmp = [0u8; N];
        let mut offset = 0;

        self.has_len(N)?;

        while let Some(p) = self.pkt_buff.first_mut() {
            if p.remaining_len() < N - offset {
                // The whole packet will be used
                let mut p = self.pkt_buff.remove(0);
                let data = p.remaining_data();
                tmp[offset .. offset + data.len()].copy_from_slice(data);
                offset += data.len();
            } else {
                // Use only what we need
                tmp[offset .. N].copy_from_slice(&p.read(N - offset).unwrap());
                return Ok(tmp);
            }
        }

        tmp[offset .. N].copy_from_slice(&self.pkt.read(N - offset).unwrap());
        Ok(tmp)
    }

    #[cold]
    #[inline(never)]
    fn skip_slow(&mut self, mut size: usize) -> Result<(), ParseErr> {

        self.has_len(size)?;
        while let Some(p) = self.pkt_buff.first_mut() {
            if p.remaining_len() < size {
                size -= p.remaining_len();
                self.pkt_buff.remove(0);
            } else {
                p.skip(size).unwrap();
                return Ok(());
            }
        }

        self.pkt.skip(size).unwrap();
        Ok(())
    }

    #[inline]
    pub fn sub_packet(&mut self, size: usize) -> Result<Packet<'_>, ParseErr> {
        if self.pkt_buff.is_empty() {
            self.pkt.sub_packet(size)
        } else {
            Ok(Packet::from_vec(self.pkt.timestamp(), Arc::new(self.read_slow(size)?)))
        }

    }

    #[cold]
    #[inline(never)]
    fn peek_slow(&self, min_size: usize) -> Result<Cow<'_, [u8]>, ParseErr> {
        if self.pkt_buff[0].remaining_len() >= min_size {
            return Ok(Cow::Borrowed(self.pkt_buff[0].peek()));
        }

        let mut ret = Vec::with_capacity(min_size);

        for pkt in self.pkt_buff.iter().chain(std::iter::once(& *self.pkt)) {
            ret.extend_from_slice(pkt.peek());
            if ret.len() >= min_size {
                break;
            }
        }

        Ok(Cow::Owned(ret))

    }

    #[inline]
    pub fn peek(&self, min_size: usize) -> Result<Cow<'_, [u8]>, ParseErr> {
        if self.pkt_buff.is_empty() {
            self.pkt.has_len(min_size)?;
            Ok(Cow::Borrowed(self.pkt.peek()))
        } else {
            if self.pkt.remaining_len() + self.buffered_len() < min_size {
                return Err(ParseErr::Truncated);
            }
            self.peek_slow(min_size)
        }
    }
}

impl Parser for PktStreamParser<'_, '_> {


    #[inline]
    fn read(&mut self, size: usize) -> Result<Cow<'_, [u8]>, ParseErr> {
        if self.pkt_buff.is_empty() {
            self.pkt.read(size)
        } else {
            Ok(Cow::Owned(self.read_slow(size)?))
        }
    }

    #[inline]
    fn read_fixed<const N: usize>(&mut self) -> Result<[u8; N], ParseErr> {
        if self.pkt_buff.is_empty() {
            self.pkt.read_fixed::<N>()
        } else {
            self.read_fixed_slow::<N>()
        }
    }

    #[inline]
    fn remaining_len(&self) -> usize {
        if self.pkt_buff.is_empty() {
            self.pkt.remaining_len()
        } else {
            self.pkt.remaining_len() + self.buffered_len()
        }
    }

    #[inline]
    fn skip(&mut self, size: usize) -> Result<(), ParseErr> {
        if self.pkt_buff.is_empty() {
            self.pkt.skip(size)
        } else {
            self.skip_slow(size)
        }
    }

    #[inline]
    fn timestamp(&self) -> PktTime {
        self.pkt.timestamp()
    }

}

impl Drop for PktStreamParser<'_, '_> {

    fn drop(&mut self) {

        if self.save_on_drop && self.pkt.remaining_len() > 0 {
            self.pkt_buff.push(self.pkt.to_owned());
        }
    }
}

#[derive(Debug)]
pub struct PktSubStream {

    buff: SmallVec<[Packet<'static>; 1]>,
}

impl PktSubStream {

    pub fn new() -> Self {

        Self {
            buff: SmallVec::new(),
        }
    }

    pub fn add_packet<'a, 'b>(&'a mut self, pkt: &'b mut Packet<'b>) -> PktStreamParser<'a, 'b> {
            PktStreamParser::new(pkt, &mut self.buff, true)
    }

}

