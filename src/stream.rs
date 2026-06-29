use crate::base::{Parser, ParseErr};
use crate::packet::{Packet, PktInfoStack, PktTime};
use crate::proto::Protocols;
use crate::conntrack::ConntrackDirection;
use crate::proto::test::ProtoTest;
use crate::proto::http::ProtoHttp;
use crate::proto::dns::ProtoDnsTcp;
use crate::proto::tls::ProtoTls;
use crate::proto::sunrpc::ProtoSunRpcTcp;
use crate::proto::ssh::ProtoSsh;

use std::borrow::Cow;
use memchr::memchr;
use smallvec::SmallVec;
use std::sync::Arc;
use tracing::debug;

pub trait PktStreamProcessor {
    fn new(infos: &PktInfoStack) -> Self;
    fn process(&mut self, dir: ConntrackDirection, parser: PktStreamParser) -> Result<(), ParseErr>;
}

pub enum PktStreamProto {
    Test(ProtoTest),
    Http(ProtoHttp),
    Dns(ProtoDnsTcp),
    Tls(ProtoTls),
    SunRpc(ProtoSunRpcTcp),
    Ssh(ProtoSsh),
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
                Protocols::Dns => PktStreamProto::Dns(ProtoDnsTcp::new(infos)),
                Protocols::Tls => PktStreamProto::Tls(ProtoTls::new(infos)),
                Protocols::SunRpc => PktStreamProto::SunRpc(ProtoSunRpcTcp::new(infos)),
                Protocols::Ssh => PktStreamProto::Ssh(ProtoSsh::new(infos)),
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
                PktStreamProto::Ssh(p) => p.process(dir, parser),
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
                ParseErr::Stop => (),
                _ => {
                    debug!("Error while parsing stream: {:?}", e);
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
    fn buffered_len(&self) -> u32 {
        let mut len :u32 = 0;
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

        // Consume all the buffers
        for _ in 0 .. pkt_id {
            let p = self.pkt_buff.remove(0);
            ret.extend_from_slice(p.peek());
        }

        if pkt_id == fake_id {
            // Use self.pkt for last data
            ret.extend_from_slice(&self.pkt.read_skip(off as u32, 1).unwrap());
        } else {
            // Use first packet left in the buffer
            ret.extend_from_slice(&self.pkt_buff[0].read_skip(off as u32, 1).unwrap());
            if self.pkt_buff[0].remaining_len() == 0 {
                self.pkt_buff.remove(0);
            }

        }

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

            let ret = self.pkt.read_skip(off as u32, skip).unwrap();
            Ok(ret)

        } else {
            self.readline_slow()
        }
    }

    // Read exact number of bytes or nothing
    #[cold]
    #[inline(never)]
    fn read_slow(&mut self, mut len: u32) -> Result<Vec<u8>, ParseErr> {
        // Only called when there is something in the buffer

        self.has_len(len)?;

        let mut data = Vec::with_capacity(len as usize);

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
        let mut offset :usize = 0;

        self.has_len(N as u32)?;

        while let Some(p) = self.pkt_buff.first_mut() {
            if (p.remaining_len() as usize) < N - offset {
                // The whole packet will be used
                let mut p = self.pkt_buff.remove(0);
                let data = p.remaining_data();
                tmp[offset as usize .. offset as usize + data.len()].copy_from_slice(data);
                offset += data.len();
            } else {
                // Use only what we need
                tmp[offset .. N].copy_from_slice(&p.read((N - offset) as u32).unwrap());
                return Ok(tmp);
            }
        }

        tmp[offset .. N].copy_from_slice(&self.pkt.read((N - offset) as u32).unwrap());
        Ok(tmp)
    }

    #[cold]
    #[inline(never)]
    fn skip_slow(&mut self, mut size: u32) -> Result<(), ParseErr> {

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

    #[cold]
    #[inline(never)]
    fn peek_slow(&self, min_size: u32) -> Result<Cow<'_, [u8]>, ParseErr> {
        if self.pkt_buff[0].remaining_len() >= min_size {
            return Ok(Cow::Borrowed(self.pkt_buff[0].peek()));
        }

        let mut ret = Vec::with_capacity(min_size as usize);

        for pkt in self.pkt_buff.iter().chain(std::iter::once(& *self.pkt)) {
            ret.extend_from_slice(pkt.peek());
            if ret.len() as u32 >= min_size {
                break;
            }
        }

        Ok(Cow::Owned(ret))

    }

    #[inline]
    pub fn peek(&self, min_size: u32) -> Result<Cow<'_, [u8]>, ParseErr> {
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
    fn read(&mut self, size: u32) -> Result<Cow<'_, [u8]>, ParseErr> {
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
    fn remaining_len(&self) -> u32 {
        if self.pkt_buff.is_empty() {
            self.pkt.remaining_len()
        } else {
            self.pkt.remaining_len() + self.buffered_len()
        }
    }

    #[inline]
    fn skip(&mut self, size: u32) -> Result<(), ParseErr> {
        if self.pkt_buff.is_empty() {
            self.pkt.skip(size)
        } else {
            self.skip_slow(size)
        }
    }

    #[inline]
    fn sub_packet(&mut self, size: u32) -> Result<Packet<'_>, ParseErr> {
        if self.pkt_buff.is_empty() {
            self.pkt.sub_packet(size)
        } else {
            Ok(Packet::from_vec(self.pkt.timestamp(), Arc::new(self.read_slow(size)?)))
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


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pktstreamparser_read() {

        // Create 3 packets of 5 bytes each
        let data1 = vec![ 1u8; 5 ];
        let mut pkt1 = Packet::from_slice(PktTime::from_micros(0), &data1);
        let data2 = vec![ 2u8; 5 ];
        let mut pkt2 = Packet::from_slice(PktTime::from_micros(0), &data2);
        let data3 = vec![ 3u8; 5 ];
        let mut pkt3 = Packet::from_slice(PktTime::from_micros(0), &data3);
        let data4 = vec![ 4u8; 5 ];
        let mut pkt4 = Packet::from_slice(PktTime::from_micros(0), &data4);
        let data5 = vec![ 5u8; 5 ];
        let mut pkt5 = Packet::from_slice(PktTime::from_micros(0), &data5);
        let data6 = vec![ 6u8; 5 ];
        let mut pkt6 = Packet::from_slice(PktTime::from_micros(0), &data6);

        let mut stream = PktSubStream::new();

        {
            let mut parser = stream.add_packet(&mut pkt1);
            // Read first 4 bytes to test the fast path
            let out = parser.read(4).unwrap();
            assert_eq!(out.as_ref(), [1u8; 4]);

            // Trying to read 4 more bytes should fail
            let ret = parser.read(4);
            assert_eq!(ret, Err(ParseErr::Truncated));
        }

        // Going out of scope so that the packet is added in the buffer
        assert_eq!(stream.buff.len(), 1);

        {
            let mut parser = stream.add_packet(&mut pkt2);
            // We should have 6 bytes in the buffer, read 3 bytes using the slow path
            let out = parser.read(3).unwrap();
            assert_eq!(out.as_ref(), [ 1u8, 2u8, 2u8]);

            // Test read fixed on 2 bytes using the fast path
            let out = parser.read_fixed::<2>().unwrap();
            assert_eq!(out.as_ref(), [ 2u8, 2u8 ]);
        }

        // Going out of scope, pkt1 should be discarded and pkt2 should be in the buffer
        assert_eq!(stream.buff.len(), 1);
        {
            let mut parser = stream.add_packet(&mut pkt3);
            // Test read fixed on 2 bytes using the slow path
            let out = parser.read_fixed::<2>().unwrap();
            assert_eq!(out.as_ref(), [ 2u8, 3u8 ]);
        }

        // We should have only pkt3 in the buffer
        assert_eq!(stream.buff.len(), 1);

        {
            let mut parser = stream.add_packet(&mut pkt4);

            // Skip one byte from the buffer in the slow path
            parser.skip(1).unwrap();
            // Read one byte fixed lengh
            let out = parser.read_fixed::<1>().unwrap();
            assert_eq!(out.as_ref(), [3u8]);
        }

        // We should have pkt3 and 4 in the buffer
        assert_eq!(stream.buff.len(), 2);

        {
            let mut parser = stream.add_packet(&mut pkt5);
            // Test to skip one byte
            let out = parser.read(3).unwrap();
            assert_eq!(out.as_ref(), [3u8, 3u8, 4u8]);
            let out = parser.read_fixed::<6>().unwrap();
            assert_eq!(out.as_ref(), [4u8, 4u8, 4u8, 4u8, 5u8, 5u8]);
        }

        // We should have pkt5 in the buffer
        assert_eq!(stream.buff.len(), 1);

        {
            let mut parser = stream.add_packet(&mut pkt6);
            let out = parser.read(8).unwrap();
            assert_eq!(out.as_ref(), [5u8, 5u8, 5u8, 6u8, 6u8, 6u8, 6u8, 6u8]);
        }

        // Buffer should be empty
        assert_eq!(stream.buff.len(), 0);
    }

    #[test]
    fn pktstreamparser_skip() {

        // Create 3 packets of 5 bytes each
        let data1 = vec![ 1u8; 5 ];
        let mut pkt1 = Packet::from_slice(PktTime::from_micros(0), &data1);
        let data2 = vec![ 2u8; 5 ];
        let mut pkt2 = Packet::from_slice(PktTime::from_micros(0), &data2);
        let data3 = vec![ 3u8; 5 ];
        let mut pkt3 = Packet::from_slice(PktTime::from_micros(0), &data3);

        let mut stream = PktSubStream::new();

        {
            let mut parser = stream.add_packet(&mut pkt1);
            assert_eq!(parser.remaining_len(), 5);
            parser.skip(4).unwrap();

        }

        // Going out of scope so that the packet is added in the buffer
        assert_eq!(stream.buff.len(), 1);

        {
            let mut parser = stream.add_packet(&mut pkt2);
            parser.skip(3).unwrap();

        }

        // Going out of scope, pkt1 and pkt2 should be in the buffer
        assert_eq!(stream.buff.len(), 1);

        {
            let mut parser = stream.add_packet(&mut pkt3);
            parser.skip(8).unwrap();
        }

        // Buffer should be empty
        assert_eq!(stream.buff.len(), 0);
    }

    #[test]
    fn pktstreamparser_peek() {

        // Create 3 packets of 5 bytes each
        let data1 = vec![ 1u8; 5 ];
        let mut pkt1 = Packet::from_slice(PktTime::from_micros(0), &data1);
        let data2 = vec![ 2u8; 5 ];
        let mut pkt2 = Packet::from_slice(PktTime::from_micros(0), &data2);

        let mut stream = PktSubStream::new();

        {
            let parser = stream.add_packet(&mut pkt1);
            // Peek on fast path, should return the whole packet
            let out = parser.peek(4).unwrap();
            assert_eq!(out.as_ref(), [1u8; 5]);

            // Peek longer than packet, should fail
            let ret = parser.peek(6);
            assert_eq!(ret, Err(ParseErr::Truncated));

        }

        // Going out of scope so that the packet is added in the buffer
        assert_eq!(stream.buff.len(), 1);

        {
            let parser = stream.add_packet(&mut pkt2);
            // Peek on slow path only on the first buffer, should return previous packet
            let out = parser.peek(4).unwrap();
            assert_eq!(out.as_ref(), [1u8; 5]);

            // Peek longer than first packet, it will allocate and return first 2 packets
            let out = parser.peek(6).unwrap();
            assert_eq!(out.as_ref(), [1u8, 1u8, 1u8, 1u8, 1u8, 2u8, 2u8, 2u8, 2u8, 2u8]);

            // Nothing should have been consume
            assert_eq!(parser.remaining_len(), 10);
        }

        // We should have the 2 packets in the buffer since we did not consume them
        assert_eq!(stream.buff.len(), 2);

    }

    #[test]
    fn pktstreamparser_readline() {

        let data1 = b"First line\nSecond";
        let mut pkt1 = Packet::from_slice(PktTime::from_micros(0), data1);
        let data2 = b" line\r\nThird line\r";
        let mut pkt2 = Packet::from_slice(PktTime::from_micros(0), data2);
        let data3 = b"\nFourth li";
        let mut pkt3 = Packet::from_slice(PktTime::from_micros(0), data3);
        let data4 = b"n";
        let mut pkt4 = Packet::from_slice(PktTime::from_micros(0), data4);
        let data5 = b"e\nFift ";
        let mut pkt5 = Packet::from_slice(PktTime::from_micros(0), data5);
        let data6 = b"line\n";
        let mut pkt6 = Packet::from_slice(PktTime::from_micros(0), data6);
        let data7 = b"No line";
        let mut pkt7 = Packet::from_slice(PktTime::from_micros(0), data7);

        let mut stream = PktSubStream::new();

        {
            let mut parser = stream.add_packet(&mut pkt1);
            // Fast path
            let out = parser.readline().unwrap();
            assert_eq!(out.as_ref(), b"First line");

            let ret = parser.readline();
            assert_eq!(ret, Err(ParseErr::Truncated));
        }

        // One packet in the buffer
        assert_eq!(stream.buff.len(), 1);

        {
            let mut parser = stream.add_packet(&mut pkt2);
            let out = parser.readline().unwrap();
            assert_eq!(out.as_ref(), b"Second line");

            let ret = parser.readline();
            assert_eq!(ret, Err(ParseErr::Truncated));
        }

        // One packet in the buffer
        assert_eq!(stream.buff.len(), 1);

        {
            let mut parser = stream.add_packet(&mut pkt3);
            let out = parser.readline().unwrap();
            assert_eq!(out.as_ref(), b"Third line");
        }

        // One packet in the buffer
        assert_eq!(stream.buff.len(), 1);

        {
            let mut parser = stream.add_packet(&mut pkt4);

            // Line not complete in pkt4
            let ret = parser.readline();
            assert_eq!(ret, Err(ParseErr::Truncated));
        }

        // Two packets in the buffer
        assert_eq!(stream.buff.len(), 2);
        {
            let mut parser = stream.add_packet(&mut pkt5);

            let out = parser.readline().unwrap();
            assert_eq!(out.as_ref(), b"Fourth line");

        }

        // One packet in the buffer
        assert_eq!(stream.buff.len(), 1);

        {
            // Do nothing so that the packet gets queued
            stream.add_packet(&mut pkt6);
        }

        // Two packets in the buffer
        assert_eq!(stream.buff.len(), 2);

        {
            let mut parser = stream.add_packet(&mut pkt7);

            let out = parser.readline().unwrap();
            assert_eq!(out.as_ref(), b"Fift line");

            // No more new line
            let ret = parser.readline();
            assert_eq!(ret, Err(ParseErr::Truncated));
        }

    }

    #[test]
    fn pktstreamparser_subpacket() {

        // Create 3 packets of 5 bytes each
        let data1 = vec![ 1u8; 5 ];
        let mut pkt1 = Packet::from_slice(PktTime::from_micros(0), &data1);
        let data2 = vec![ 2u8; 5 ];
        let mut pkt2 = Packet::from_slice(PktTime::from_micros(0), &data2);
        let data3 = vec![ 3u8; 5 ];
        let mut pkt3 = Packet::from_slice(PktTime::from_micros(0), &data3);

        let mut stream = PktSubStream::new();

        {
            let mut parser = stream.add_packet(&mut pkt1);
            let subpkt = parser.sub_packet(3).unwrap();
            assert_eq!(subpkt.peek(), [ 1u8, 1u8, 1u8]);
        }

        {
            let mut parser = stream.add_packet(&mut pkt2);
            // Try to create a packet bigger than current buffer
            let Err(ret) = parser.sub_packet(10) else {
                panic!("Supposed to error out");
            };
            assert_eq!(ret, ParseErr::Truncated);
        }

        {
            let mut parser = stream.add_packet(&mut pkt3);
            let subpkt = parser.sub_packet(5).unwrap();
            assert_eq!(subpkt.peek(), [ 1u8, 1u8, 2u8, 2u8, 2u8]);

            assert_eq!(parser.remaining_len(), 7);
        }

    }
}
