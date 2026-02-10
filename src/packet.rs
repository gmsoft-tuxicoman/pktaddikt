use crate::proto::Protocols;
use crate::param::Param;
use crate::conntrack::{ConntrackRef, ConntrackWeakRef};
use std::sync::Arc;
use tracing::trace;
use rangemap::RangeSet;


// Time in microsecond
pub type PktTime = u64;



// All info about a packet
pub struct PktInfo<'a> {
    pub proto: Protocols,
    parent_ce: Option<ConntrackRef>,
    fields: Vec<Param<'a>>
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

}


// Packet for all your packet needs
pub struct Packet<'a> {
    pub ts: PktTime,
    pub datalink: Protocols,
    stack: Vec<PktInfo<'a>>,
    read_offset: usize,
    length: usize,
    pub data: &'a mut dyn PktData,
}


impl<'a> Packet<'a> {

    pub fn new(ts: PktTime, datalink: Protocols, data: &'a mut impl PktData) -> Self {

        Packet {
            ts: ts,
            datalink: datalink,
            stack: Vec::with_capacity(7),
            read_offset: 0,
            length: data.data().len(),
            data: data
        }

    }

    pub fn stack_push<'b>(&'b mut self, proto: Protocols, parent_ce: Option<ConntrackRef>) -> &'b PktInfo<'b> {
        let info = PktInfo {
            proto: proto,
            fields: Vec::with_capacity(5),
            parent_ce: parent_ce,
        };
        self.stack.push(info);
        self.stack.last().unwrap()
    }

    pub fn stack_last<'b>(&'b self) -> &'b PktInfo<'b> {
        self.stack.last().unwrap()
    }

    pub fn stack_last_mut(&mut self) -> &mut PktInfo<'a> {
        self.stack.last_mut().unwrap()
    }

    pub fn iter_stack<'b>(&'b self) -> impl Iterator<Item = &'b PktInfo<'b>> {
        self.stack.iter()
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
        self.length - self.read_offset
    }

    pub fn remaining_data(&mut self) -> &[u8] {
        let data = self.data.data();
        let ret = &data[self.read_offset..self.length];
        self.read_offset = self.length;
        ret
    }

    pub fn skip_bytes(&mut self, size: usize) -> Result<(),()> {
        trace!("Skipping {} bytes from pkt {:p}", size, self);
        if self.length - self.read_offset < size {
            self.read_offset = self.length;
            return Err(());
        }
        self.read_offset += size;
        return Ok(());
    }

    pub fn shrink_remaining(&mut self, new_size: usize) {
        let new_length = new_size + self.read_offset;
        trace!("Shrinking data to {} (was {})", new_length, self.length);
        assert!(self.length >= new_length, "Trying to shrink a packet with a bigger or equal length!");
        self.length = new_length;
    }

    pub fn read_bytes(&mut self, size: usize) -> Option<&[u8]> {

        trace!("Reading {} bytes from pkt {:p}i (off: {}, len: {})", size, self, self.read_offset, self.length);
        let data = self.data.data();
        assert!(data.len() >= self.length);
        if self.read_offset + size > self.length {
            return None;
        }
        let bytes = &data[self.read_offset..(self.read_offset + size)];
        self.read_offset += size;
        Some(bytes)

    }
}

// Data of a packet
pub trait PktData {

    fn data(&self) -> &[u8];
}

// A packet with a reference to some data
pub struct PktDataSimple<'a> {
    data: &'a[u8]
}

impl<'a> PktDataSimple<'a> {

    pub fn new(data: &'a[u8]) -> Self {
        PktDataSimple {
           data: data
        }
    }
}

impl<'a> PktData for PktDataSimple<'a> {

    fn data(&self) -> &'a [u8] {
        &self.data
    }

}


// A packet created by multiple fragments
pub struct PktDataMultipart {
    data: Vec<u8>, // Concatenated data
    ranges: RangeSet<usize>, // Info tracking about data
    tot_len: Option<usize> // Total expected length of the reassembled data

}


impl PktData for PktDataMultipart {

    fn data(&self) -> &[u8] {
        &self.data
    }
}

impl<'b> PktDataMultipart {

    pub fn new(capacity: usize) -> Self {
        PktDataMultipart {
            data: Vec::with_capacity(capacity),
            ranges: RangeSet::<usize>::new(),
            tot_len: None
        }
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
