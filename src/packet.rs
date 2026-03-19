use crate::proto::Protocols;
use crate::param::Param;
use crate::conntrack::{ConntrackRef, ConntrackWeakRef};
use std::sync::Arc;
use std::ops::Range;
use tracing::trace;
use rangemap::RangeSet;
use std::fmt;
use std::time::Duration;
use std::ops::{Add, Sub};


// Time in microsecond
#[derive(PartialEq,Debug,Clone,Copy,Eq,PartialOrd,Ord)]
pub struct PktTime(u64);

impl PktTime {
    pub fn from_timeval(tv_sec: i64, tv_usec: i64) -> PktTime {
        PktTime((tv_sec as u64 * 1000000) + tv_usec as u64)
    }

    pub fn from_nanos(nsec: u64) -> PktTime {
        PktTime(nsec)
    }
}

impl fmt::Display for PktTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.0 / 1000000, self.0 % 1000000)
    }
}

impl From<Duration> for PktTime {
    fn from(d: Duration) -> Self {
        PktTime(d.as_nanos() as u64)
    }
}

impl From<PktTime> for Duration {
    fn from(d: PktTime) -> Self {
        Duration::from_nanos(d.0)
    }
}

impl From<PktTime> for u64 {
    fn from(d: PktTime) -> Self {
        d.0
    }
}

impl Add<PktTime> for PktTime {
    type Output = PktTime;

    fn add(self, rhs: PktTime) -> Self::Output {
        PktTime(self.0 + rhs.0)
    }
}

impl Sub<PktTime> for PktTime {
    type Output = PktTime;

    fn sub(self, rhs: PktTime) -> Self::Output {
        PktTime(self.0 - rhs.0)
    }
}

// Stack of packet info
pub struct PktInfoStack<'a> {
    infos: Vec<PktInfo<'a>>
}

// All info about a packet
pub struct PktInfo<'a> {
    pub proto: Protocols,
    parent_ce: Option<ConntrackRef>,
    fields: Vec<Param<'a>>
}

impl<'a> PktInfoStack<'a> {

    pub fn new(datalink: Protocols) -> Self {
        let mut ret = PktInfoStack {
            infos: Vec::with_capacity(7)
        };
        ret.proto_push(datalink, None);
        ret
    }

    pub fn proto_push(&mut self, proto: Protocols, parent_ce: Option<ConntrackRef>) {
        let info = PktInfo {
            proto: proto,
            fields: Vec::with_capacity(5),
            parent_ce: parent_ce,
        };
        self.infos.push(info);
    }

    pub fn proto_before_last(&self) -> &PktInfo<'a> {
        &self.infos[self.infos.len() - 2]
    }

    pub fn proto_last(&self) -> &PktInfo<'a> {
        self.infos.last().unwrap()
    }

    pub fn proto_last_mut(&mut self) -> &mut PktInfo<'a> {
        self.infos.last_mut().unwrap()
    }

    pub fn iter(&self) -> impl Iterator<Item = &PktInfo<'a>> {
        self.infos.iter()
    }
}


impl<'a> PktInfo<'a> {

    pub fn field_push(&mut self, param: Param<'a>) {
        self.fields.push(param);
    }

    pub fn iter_fields<'b>(&'b self) -> impl Iterator<Item = &'b Param<'b>> {
        self.fields.iter()
    }

    pub fn parent_ce(&self) -> Option<ConntrackWeakRef> {
        Some(Arc::downgrade(self.parent_ce.as_ref()?))
    }

    pub fn get_field(&self, id: usize) -> &Param<'a> {
        &self.fields[id]
    }

}


// Packet for all your packet needs
pub struct Packet<'a> {
    pub ts: PktTime,
    data_range: Range<usize>,
    pub data: PktDataType<'a>,
}

pub enum PktDataType<'a> {
    Borrowed(PktDataBorrowed<'a>),
    Owned(PktDataOwned),
    Zero(PktDataZero),
    Multipart(PktDataMultipart),
}

impl<'a> PktData for PktDataType<'a> {

    fn data(&self) -> &[u8] {
        match self {
            Self::Borrowed(d) => d.data(),
            Self::Owned(d) => d.data(),
            Self::Zero(d) => d.data(),
            Self::Multipart(d) => d.data()
        }
    }

    fn copy_or_clone(&self) -> PktDataType<'static> {
        match self {
            Self::Borrowed(d) => d.copy_or_clone(),
            Self::Owned(d) => d.copy_or_clone(),
            Self::Zero(d) => d.copy_or_clone(),
            Self::Multipart(d) => d.copy_or_clone()
        }
    }

}


impl<'a> Packet<'a> {

    pub fn new(ts: PktTime, data: PktDataType<'a>) -> Self {

        Packet {
            ts: ts,
            data_range: 0 .. data.data().len(),
            data: data
        }

    }

    pub fn read_u8(&mut self) -> Option<u8> {
        let byte = self.read_bytes(1)?;
        Some(byte[0])
    }

    pub fn read_u16(&mut self) -> Option<u16> {
        let bytes = self.read_bytes(2)?;
        Some((bytes[0] as u16) << 8 | (bytes[1] as u16))
    }

    pub fn remaining_len(&self) -> usize {
        self.data_range.end - self.data_range.start
    }

    pub fn remaining_data(&mut self) -> &[u8] {
        let data = self.data.data();
        let ret = &data[self.data_range.start..self.data_range.end];
        self.data_range.start = self.data_range.end;
        ret
    }

    pub fn peek(&self) -> &[u8] {
        &self.data.data()[self.data_range.start..self.data_range.end]
    }

    pub fn skip_bytes(&mut self, size: usize) -> Result<(),()> {
        trace!("Skipping {} bytes from pkt {:p}", size, self);
        if self.remaining_len() < size {
            self.data_range.start = self.data_range.end;
            return Err(());
        }
        self.data_range.start += size;
        return Ok(());
    }

    pub fn shrink_remaining(&mut self, new_size: usize) {
        let new_end = new_size + self.data_range.start;
        trace!("Shrinking data to {} (was {})", new_size, self.data_range.end - self.data_range.start);
        assert!(self.data_range.end >= new_end, "Trying to shrink a packet with a bigger or equal length!");
        self.data_range.end = new_end;
    }

    pub fn read_bytes(&mut self, size: usize) -> Option<&[u8]> {

        trace!("Reading {} bytes from pkt {:p} (off: {}, len: {})", size, self, self.data_range.start, self.data_range.end - self.data_range.end);
        let data = self.data.data();
        debug_assert!(data.len() >= self.data_range.end - self.data_range.start);
        if self.data_range.start + size > self.data_range.end {
            return None;
        }
        let bytes = &data[self.data_range.start ..(self.data_range.start + size)];
        self.data_range.start += size;
        Some(bytes)

    }

    pub fn clone(&self) -> Packet<'static> {

        Packet {
            ts: self.ts,
            data: self.data.copy_or_clone(),
            data_range: self.data_range.clone(),
        }
    }

}

// Data of a packet
pub trait PktData {

    fn data(&self) -> &[u8];
    fn copy_or_clone(&self) -> PktDataType<'static>;
}

// A packet with a reference to some data
pub struct PktDataBorrowed<'a> {
    data: &'a[u8]
}

impl<'a> PktDataBorrowed<'a> {

    pub fn new(data: &'a[u8]) -> PktDataType<'a> {
        PktDataType::Borrowed(PktDataBorrowed {
           data: data
        })
    }
}

impl<'a> PktData for PktDataBorrowed<'a> {

    fn data(&self) -> &'a [u8] {
        &self.data
    }

    fn copy_or_clone(&self) -> PktDataType<'static> {
        PktDataOwned::new(self.data)
    }

}


// A packet with owned data
pub struct PktDataOwned {
    data: Arc<Vec<u8>>
}

impl PktDataOwned {
    pub fn new_raw(data: &[u8]) -> PktDataOwned {
        PktDataOwned {
            data: Arc::new(data.to_vec())
        }
    }

    pub fn new(data: &[u8]) -> PktDataType<'static> {
        PktDataType::Owned(PktDataOwned::new_raw(data))
    }
}


impl PktData for PktDataOwned {

    fn data(&self) -> &[u8] {
        &self.data
    }

    fn copy_or_clone(&self) -> PktDataType<'static> {
        PktDataType::Owned(PktDataOwned {
            data: self.data.clone()
        })
    }
}

// A packet filled with 0
pub static PKT_ZERO_MAX_LEN :usize = 4096;
static PKT_ZERO: [u8; PKT_ZERO_MAX_LEN] = [0; PKT_ZERO_MAX_LEN];
pub struct PktDataZero {
    len: usize,
}

impl PktDataZero {

    pub fn new_raw(len: usize) -> Self {
        assert!(len <= PKT_ZERO_MAX_LEN, "PktDataZero supports packets up to {} bytes only", PKT_ZERO_MAX_LEN);
        PktDataZero {
            len: len
        }
    }

    pub fn new(len: usize) -> PktDataType<'static> {
        PktDataType::Zero(PktDataZero::new_raw(len))
    }

    pub fn max_len() -> usize {
        PKT_ZERO_MAX_LEN
    }
}

impl PktData for PktDataZero {

    fn data(&self) -> &[u8] {
        &PKT_ZERO[..self.len]
    }

    fn copy_or_clone(&self) -> PktDataType<'static> {
        PktDataType::Zero(PktDataZero {
            len: self.len
        })
    }

}

// A packet created by multiple fragments
pub struct PktDataMultipart {
    data: Arc<Vec<u8>>, // Concatenated data
    ranges: RangeSet<usize>, // Info tracking about data
    tot_len: Option<usize> // Total expected length of the reassembled data

}


impl PktData for PktDataMultipart {

    fn data(&self) -> &[u8] {
        &self.data
    }

    fn copy_or_clone(&self) -> PktDataType<'static> {
        PktDataType::Owned(PktDataOwned {
            data: self.data.clone()
        })
    }

}

impl<'a,'b> PktDataMultipart {

    pub fn new_raw(capacity: usize) -> Self {
        Self {
            data: Arc::new(Vec::with_capacity(capacity)),
            ranges: RangeSet::<usize>::new(),
            tot_len: None
        }
    }

    pub fn new(capacity: usize) -> PktDataType<'a> {
        PktDataType::Multipart(PktDataMultipart::new_raw(capacity))
    }

    pub fn add(&mut self, offset: usize, data: &'b [u8]) {
        // This implementation only works for contiguous packets
        // Packets nested or not having proper boundaries will be dropped

        let range = offset..offset+data.len();

        // Find out if we already have this range
        if self.ranges.iter().any(|r| r.start <= range.start && r.end >= range.end) {
            trace!("Dupe part {} -> {} in multipart {:p}. Discarding", range.start, range.end, self);
        }

        // Add the range in the tracking

        // Copy the data into the buffer

        let data_mut = Arc::get_mut(&mut self.data).expect("PktDataMultipart was cloned before it was complete");

        if data_mut.len() == range.start {
            // Most common case, we can simply append the data
            data_mut.extend_from_slice(data);
        } else {
            // Resize if needed then copy
            if data_mut.len() < range.end {
                data_mut.resize(range.end, 0)
            }
            data_mut[range.start..range.end].copy_from_slice(data);
        }

        trace!("Part {} -> {} added into multipart {:p}", range.start, range.end, self);
        self.ranges.insert(range);

    }


    pub fn set_expected_len(&mut self, tot_len: usize) {

        self.tot_len = Some(tot_len);
    }

    pub fn is_complete(&self) -> bool {
        let ret = match self.tot_len {
            Some(tot_len) => self.ranges.gaps(&(0..tot_len)).next().is_none(),
            None => false
        };

        trace!("Multipart {:p} is complete : {:#}", self, ret);
        ret
    }
}
