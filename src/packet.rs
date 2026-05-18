use crate::base::{Parser, ParseErr};
use crate::proto::{Protocols, ProtoInfo};
use crate::conntrack::{ConntrackRef, ConntrackWeakRef, ConntrackDirection};
use crate::base::UniqueId;
use std::sync::Arc;
use tracing::trace;
use rangemap::RangeSet;
use std::fmt;
use std::time::Duration;
use std::ops::{Add, Sub};
use serde::{Serialize, Serializer};
use std::net::IpAddr;
use std::borrow::Cow;


// Time in microsecond
#[derive(PartialEq,Debug,Clone,Copy,Eq,PartialOrd,Ord)]
pub struct PktTime(u64);

impl PktTime {
    pub fn from_timeval(tv_sec: i64, tv_usec: i64) -> PktTime {
        PktTime((tv_sec as u64 * 1000000) + tv_usec as u64)
    }

    pub fn from_micros(nsec: u64) -> PktTime {
        PktTime(nsec)
    }

}

impl fmt::Display for PktTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{:06}", self.0 / 1000000, self.0 % 1000000)
    }
}

impl From<Duration> for PktTime {
    fn from(d: Duration) -> Self {
        PktTime(d.as_micros() as u64)
    }
}

impl From<PktTime> for Duration {
    fn from(d: PktTime) -> Self {
        Duration::from_micros(d.0)
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

impl Serialize for PktTime {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

// Connection info
#[derive(Debug, Default, Copy, Clone, Serialize)]
pub struct PktConnInfo {
    pub src_host: Option<IpAddr>,
    pub dst_host: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
}

// Stack of packet info
pub struct PktInfoStack {
    infos: Vec<PktInfo>,
    conn_id: Option<UniqueId>,
}

// All info about a packet
pub struct PktInfo {
    pub proto: Protocols,
    pub proto_info: Option<ProtoInfo>,
    parent_ce: Option<(ConntrackRef, ConntrackDirection)>,
    pub tot_len: usize, // Total length of proto header + payload
    pub data_len: usize, // Payload only length
}

impl PktInfoStack {

    pub fn new(datalink: Protocols) -> Self {
        let mut ret = PktInfoStack {
            infos: Vec::with_capacity(7),
            conn_id: None,
        };
        ret.proto_push(datalink, None);
        ret
    }

    pub fn proto_push(&mut self, proto: Protocols, parent_ce: Option<(ConntrackRef, ConntrackDirection)>) {
        let info = PktInfo {
            proto: proto,
            proto_info: None,
            parent_ce: parent_ce,
            tot_len: 0,
            data_len: 0,
        };
        self.infos.push(info);
    }

    pub fn proto_from_last(&self, id: usize) -> Option<&PktInfo> {
        if id > self.infos.len() {
            return None;
        }
        self.infos.get(self.infos.len() - id - 1)
    }

    pub fn proto_id(&mut self, id: usize) -> Option<&mut PktInfo> {
        self.infos.get_mut(id)
    }

    pub fn proto_last(&self) -> &PktInfo {
        self.infos.last().unwrap()
    }

    pub fn proto_last_mut(&mut self) -> &mut PktInfo {
        self.infos.last_mut().unwrap()
    }

    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &PktInfo> {
        self.infos.iter()
    }

    pub fn set_conn_id(&mut self, conn_id: UniqueId) {
        self.conn_id = Some(conn_id);
    }

    pub fn get_conn_id(&self) -> Option<&UniqueId> {
        self.conn_id.as_ref()
    }

    pub fn get_conn_info(&self) -> PktConnInfo {
        let mut conn_info = PktConnInfo {
            src_host: None,
            dst_host: None,
            src_port: None,
            dst_port: None,
        };
        for info in self.infos.iter().rev() {
            match &info.proto_info {
                Some(ProtoInfo::Udp(u)) => {
                    conn_info.src_port = Some(u.sport);
                    conn_info.dst_port = Some(u.dport);
                },
                Some(ProtoInfo::Tcp(t)) => {
                    conn_info.src_port = Some(t.sport);
                    conn_info.dst_port = Some(t.dport);
                },
                Some(ProtoInfo::Ipv4(v4)) => {
                    conn_info.src_host = Some(IpAddr::V4(v4.src));
                    conn_info.dst_host = Some(IpAddr::V4(v4.dst));
                    break;
                },
                Some(ProtoInfo::Ipv6(v6)) => {
                    conn_info.src_host = Some(IpAddr::V6(v6.src));
                    conn_info.dst_host = Some(IpAddr::V6(v6.dst));
                    break;
                }
                _ => ()

            }
        }
        conn_info
    }
}


impl PktInfo {

    pub fn parent_ce(&self) -> Option<(ConntrackWeakRef, ConntrackDirection)> {

        match self.parent_ce {
            Some((ref p, d)) => Some((Arc::downgrade(p), d)),
            None => None,
        }
    }

    pub fn ce_dir(&self) -> Option<ConntrackDirection> {

        match self.parent_ce {
            Some((_, d)) => Some(d),
            None => None,
        }
    }

}

#[derive(Debug)]
pub enum PacketData<'a> {
    Borrowed(&'a[u8]),
    Owned(Arc<[u8]>),
    OwnedVec(Arc<Vec<u8>>),
    Zero(usize),
    Empty,
}

// A packet filled with 0
static PKT_ZERO: [u8; Packet::PKT_ZERO_MAX_LEN] = [0; Packet::PKT_ZERO_MAX_LEN];
impl<'a> PacketData<'a> {

    fn as_slice(&self) -> &[u8] {
        match self {
            PacketData::Owned(arc) => &arc,
            PacketData::OwnedVec(vec) => &vec,
            PacketData::Borrowed(b) => b,
            PacketData::Zero(len) => &PKT_ZERO[0..*len],
            PacketData::Empty => &[],
        }
    }

    fn len(&self) -> usize {
        match self {
            PacketData::Owned(arc) => arc.len(),
            PacketData::OwnedVec(vec) => vec.len(),
            PacketData::Borrowed(b) => b.len(),
            PacketData::Zero(len) => *len,
            PacketData::Empty => 0,
        }
    }
}

// Packet for all your packet needs
#[derive(Debug)]
pub struct Packet<'a> {
    ts: PktTime,
    data: PacketData<'a>,
    range: (usize, usize), // Use a tuple instead of Range because Range isn't Copy
}


impl<'a> Packet<'a> {

    pub const PKT_ZERO_MAX_LEN :usize = 4096;

    pub fn from_slice(ts: PktTime, data: &'a [u8]) -> Self {
        let pkt_data = PacketData::Borrowed(data);
        let len = pkt_data.len();
        Self {
            ts,
            data: pkt_data,
            range: (0, len),
        }
    }


    pub fn from_vec(ts: PktTime, data: Arc<Vec<u8>>) -> Self {
        let pkt_data = PacketData::OwnedVec(data.clone());
        let len = pkt_data.len();
        Self {
            ts,
            data: pkt_data,
            range: (0, len),
        }
    }

    pub fn from_zero(ts: PktTime, len: usize) -> Self {
        let pkt_data = PacketData::Zero(len);
        Self {
            ts,
            data: pkt_data,
            range: (0, len),
        }
    }

    pub fn to_owned(&self) -> Packet<'static> {
        let mut range = self.range;
        let pkt_data = match &self.data {
            PacketData::Owned(arc) => PacketData::Owned(arc.clone()),
            PacketData::OwnedVec(vec) => PacketData::OwnedVec(vec.clone()),
            PacketData::Borrowed(b) => {
                let data = PacketData::Owned(Arc::from(b[self.range.0 .. self.range.1].to_vec()));
                range.1 = self.range.1 - self.range.0;
                range.0 = 0;
                data
            },
            PacketData::Zero(len) => PacketData::Zero(*len),
            PacketData::Empty => PacketData::Empty,
        };
        Packet {
            ts: self.ts,
            data: pkt_data,
            range: range,
        }
    }

    pub fn to_empty(&self) -> Packet<'static> {
        Packet {
            ts: self.ts,
            data: PacketData::Empty,
            range: self.range,
        }
    }

    pub fn remaining_data(&mut self) -> &[u8] {
        let remaining_data = &self.data.as_slice()[self.range.0 .. self.range.1];
        self.range = (0, 0);
        remaining_data
    }

    pub fn peek(&self) -> &[u8] {
        &self.data.as_slice()[self.range.0 .. self.range.1]
    }

    #[inline]
    pub fn shrink(&mut self, size: usize) {
        assert!(self.remaining_len() >= size, "Trying to shrink a packet with a bigger or equal length!");
        self.range.1 -= size;
    }

    #[inline]
    // return a sub packet and mark the data as read
    pub fn sub_packet(&mut self, size: usize) -> Result<Packet<'a>, ParseErr> {

        if size == 0 {
            return Err(ParseErr::Invalid("Requested packet with 0 size"));
        }

        self.has_len(size)?;

        let pkt_data = match &self.data {
            PacketData::Owned(arc) => PacketData::Owned(arc.clone()),
            PacketData::OwnedVec(vec) => PacketData::OwnedVec(vec.clone()),
            PacketData::Borrowed(b) => PacketData::Borrowed(b),
            PacketData::Zero(len) => PacketData::Zero(*len),
            PacketData::Empty => PacketData::Empty,
        };
        let range = (self.range.0, self.range.0 + size);
        self.range.0 += size;
        Ok(Packet {
            ts: self.ts,
            data: pkt_data,
            range: range,
        })
    }

    #[inline]
    // return an owned parser
    pub fn to_parser(&mut self) -> Packet<'a> {

        let pkt_data = match &self.data {
            PacketData::Owned(arc) => PacketData::Owned(arc.clone()),
            PacketData::OwnedVec(vec) => PacketData::OwnedVec(vec.clone()),
            PacketData::Borrowed(b) => PacketData::Borrowed(b),
            PacketData::Zero(len) => PacketData::Zero(*len),
            PacketData::Empty => PacketData::Empty,
        };

        let pkt = Packet {
            ts: self.ts,
            data: pkt_data,
            range: self.range,
        };

        // Packet entirely consumed
        self.range.0 = self.range.1;

        pkt
    }

    #[inline]
    pub fn read_skip(&mut self, size: usize, skip: usize) -> Result<Cow<'_, [u8]>, ParseErr> {
        self.has_len(size + skip)?;
        let chunk = Cow::Borrowed(&self.data.as_slice()[self.range.0 .. self.range.0 + size]);
        self.range.0 += size + skip;
        Ok(chunk)
    }
}

impl Parser for Packet<'_> {

    #[inline]
    fn read(&mut self, size: usize) -> Result<Cow<'_, [u8]>, ParseErr> {
        self.has_len(size)?;
        let chunk = Cow::Borrowed(&self.data.as_slice()[self.range.0 .. self.range.0 + size]);
        self.range.0 += size;
        Ok(chunk)
    }

    #[inline]
    fn read_fixed<const N: usize>(&mut self) -> Result<[u8; N], ParseErr> {
        self.has_len(N)?;
        let (chunk, _) = self.data.as_slice()[self.range.0 ..].split_first_chunk::<N>().ok_or(ParseErr::Truncated)?;
        let ret: [u8; N] = *chunk;
        self.range.0 += N;
        Ok(ret)
    }

    #[inline]
    fn remaining_len(&self) -> usize {
        self.range.1 - self.range.0
    }

    #[inline]
    fn skip(&mut self, size: usize) -> Result<(), ParseErr> {
        self.has_len(size)?;
        self.range.0 += size;
        Ok(())
    }

    #[inline]
    fn timestamp(&self) -> PktTime {
        self.ts
    }
}




// A packet created by multiple fragments
pub struct PacketMultipart {
    data: Vec<u8>, // Concatenated data
    ranges: RangeSet<usize>, // Info tracking about data
    tot_len: Option<usize> // Total expected length of the reassembled data

}



impl PacketMultipart {

    pub fn new(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
            ranges: RangeSet::<usize>::new(),
            tot_len: None
        }
    }

    pub fn take_data(self) -> Vec<u8> {
        self.data
    }

    pub fn add(&mut self, offset: usize, data: &[u8]) {
        // This implementation only works for contiguous packets
        // Packets nested or not having proper boundaries will be dropped

        let range = offset..offset+data.len();

        // Find out if we already have this range
        if self.ranges.iter().any(|r| r.start <= range.start && r.end >= range.end) {
            trace!("Dupe part {} -> {} in multipart {:p}. Discarding", range.start, range.end, self);
        }

        // Add the range in the tracking

        // Copy the data into the buffer


        if self.data.len() == range.start {
            // Most common case, we can simply append the data
            self.data.extend_from_slice(data);
        } else {
            // Resize if needed then copy
            if self.data.len() < range.end {
                self.data.resize(range.end, 0)
            }
            self.data[range.start..range.end].copy_from_slice(data);
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
