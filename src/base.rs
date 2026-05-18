use crate::packet::{Packet, PktTime};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::borrow::Cow;
use std::sync::atomic::{AtomicU16, Ordering};
use serde::Serialize;

static UNIQUE_ID_COUNTER: AtomicU16 = AtomicU16::new(0);

#[derive(Debug, Clone, Serialize)]
pub struct UniqueId (String);

impl UniqueId {
    pub fn new(ts: PktTime) -> UniqueId {

        let counter = UNIQUE_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
        let val: u128 = ((u64::from(ts) as u128) << 16) | counter as u128;
        UniqueId(base62::encode(val))
    }
}


/// Return error for Proto and Stream API
pub enum ParseErr {
    /// Parsing should stop
    /// Proto: no more inner protocol should be parsed
    /// Stream: no additional data in the stream are required
    Stop,

    /// Not enough data to continue parsing
    /// Proto: more data was expected in the packet, it was likely not captured entirely
    /// Stream: Not enough data was fed to the stream and parsing cannot continue for now
    Truncated,

    /// Unexpected data was found, parsing cannot continue
    Invalid(&'static str), // There was an error parsing the data

    /// Only for Proto. Parsing needs to continue with another packet (i.e. IP fragment
    /// reassembled)
    New(Packet<'static>),

    /// Parsing state not yet known
    Unknown,
}

impl PartialEq for ParseErr {

    fn eq(&self, other:&Self) -> bool {
        use ParseErr::*;

        match (self, other) {
            (Stop, Stop) => true,
            (Truncated, Truncated) => true,
            (Invalid(_), Invalid(_)) => true,
            (New(_), New(_)) => true, // don't check content
            (Unknown, Unknown) => true,
            _ => false,
        }

    }

}

impl fmt::Debug for ParseErr {

    fn fmt(&self, f:&mut fmt::Formatter<'_>) -> fmt::Result {
        use ParseErr::*;

        match self {
            Stop => write!(f, "Stop"),
            Truncated => write!(f, "Truncated"),
            Invalid(e) => write!(f, "Invalid ({})", e),
            New(_) => write!(f, "New"),
            Unknown => write!(f, "Unknown"),
        }

    }
}

impl ParseErr {

    pub fn invalid_reason(&self) -> &'static str {
        match self {
            ParseErr::Invalid(r) => r,
            _ => panic!("Result is not Invalid")
        }
    }

}


pub trait Parser {

    fn read(&mut self, size: usize) -> Result<Cow<'_, [u8]>, ParseErr>;
    fn read_fixed<const N: usize>(&mut self) -> Result<[u8; N], ParseErr>;
    fn remaining_len(&self) -> usize;
    fn skip(&mut self, size: usize) -> Result<(), ParseErr>;
    fn timestamp(&self) -> PktTime;

    #[inline]
    fn has_len(&self, len: usize) -> Result<(), ParseErr> {
        if self.remaining_len() < len {
            return Err(ParseErr::Truncated);
        }
        Ok(())
    }

    #[inline]
    fn read_u8(&mut self) -> Result<u8, ParseErr> {
        Ok(u8::from_be_bytes(self.read_fixed::<1>()?))
    }

    #[inline]
    fn read_u16_be(&mut self) -> Result<u16, ParseErr> {
        Ok(u16::from_be_bytes(self.read_fixed::<2>()?))
    }

    fn read_u24_be(&mut self) -> Result<u32, ParseErr> {
        let [a, b, c] = self.read_fixed::<3>()?;
        Ok(u32::from_be_bytes([0, a, b, c]))
    }

    #[inline]
    fn read_u32_be(&mut self) -> Result<u32, ParseErr> {
        Ok(u32::from_be_bytes(self.read_fixed::<4>()?))
    }

    #[inline]
    fn read_u64_be(&mut self) -> Result<u64, ParseErr> {
        Ok(u64::from_be_bytes(self.read_fixed::<8>()?))
    }

    #[inline]
    fn read_ipv4(&mut self) -> Result<Ipv4Addr, ParseErr> {
        Ok(Ipv4Addr::from(self.read_fixed::<4>()?))
    }

    #[inline]
    fn read_ipv6(&mut self) -> Result<Ipv6Addr, ParseErr> {
        Ok(Ipv6Addr::from(self.read_fixed::<16>()?))
    }

    #[inline]
    fn skip_u8(&mut self) -> Result<(), ParseErr> {
        self.skip(1)
    }

    #[inline]
    fn skip_u16(&mut self) -> Result<(), ParseErr> {
        self.skip(2)
    }

    #[inline]
    fn skip_u32(&mut self) -> Result<(), ParseErr> {
        self.skip(4)
    }

    #[inline]
    fn skip_u32s(&mut self, count: usize) -> Result<(), ParseErr> {
        self.skip(4 * count)
    }

    #[inline]
    fn skip_u64(&mut self) -> Result<(), ParseErr> {
        self.skip(8)
    }

    #[inline]
    fn skip_u64s(&mut self, count: usize) -> Result<(), ParseErr> {
        self.skip(8 * count)
    }
}

// Ascii base 10 to integer
pub fn atoi(val: &[u8]) -> Option<usize> {
    let mut ret = 0usize;

    for &b in val {
        if b < b'0' || b > b'9' {
            return None;
        }

        ret = ret * 10 + (b - b'0') as usize;
    }
    Some(ret)
}

// Ascii hexadecimal to integer
pub fn htoi(val: &[u8]) -> Option<usize> {
    let mut ret = 0usize;

    for &b in val {
        if b >= b'0' && b  <= b'9' {
            ret = (ret << 4 ) + (b - b'0') as usize;
        } else if b >= b'a' && b <= b'f' {
            ret = (ret << 4) + (b - b'a' + 10) as usize;
        } else if b >= b'A' && b <= b'F' {
            ret = (ret << 4) + (b - b'A' + 10) as usize;
        } else {
            return None;
        }
    }
    Some(ret)
}

