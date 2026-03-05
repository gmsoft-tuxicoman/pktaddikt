use crate::proto::Protocols;
use crate::param::Param;
use crate::conntrack::{ConntrackRef, ConntrackWeakRef};
use std::sync::Arc;
use std::ops::Range;
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
    stack: Vec<PktInfo<'a>>,
    data_range: Range<usize>,
    pub data: &'a mut dyn PktData,
}


impl<'a> Packet<'a> {

    pub fn new(ts: PktTime, datalink: Protocols, data: &'a mut impl PktData) -> Self {

        let mut pkt = Packet {
            ts: ts,
            stack: Vec::with_capacity(7),
            data_range: 0 .. data.data().len(),
            data: data
        };
        pkt.stack_push(datalink, None);
        pkt

    }

    pub fn stack_push<'b>(&'b mut self, proto: Protocols, parent_ce: Option<ConntrackRef>) {
        let info = PktInfo {
            proto: proto,
            fields: Vec::with_capacity(5),
            parent_ce: parent_ce,
        };
        self.stack.push(info);
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
        self.data_range.end - self.data_range.start
    }

    pub fn remaining_data(&mut self) -> &[u8] {
        let data = self.data.data();
        let ret = &data[self.data_range.start..self.data_range.end];
        self.data_range.start = self.data_range.end;
        ret
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

    pub fn clone_data(&self) -> (PktDataOwned, Range<usize>) {

        (self.data.copy_or_clone(), self.data_range.clone())
    }
}

// Data of a packet
pub trait PktData {

    fn data(&self) -> &[u8];
    fn copy_or_clone(&self) -> PktDataOwned;
}

// A packet with a reference to some data
pub struct PktDataBorrowed<'a> {
    data: &'a[u8]
}

impl<'a> PktDataBorrowed<'a> {

    pub fn new(data: &'a[u8]) -> Self {
        PktDataBorrowed {
           data: data
        }
    }
}

impl<'a> PktData for PktDataBorrowed<'a> {

    fn data(&self) -> &'a [u8] {
        &self.data
    }

    fn copy_or_clone(&self) -> PktDataOwned {
        PktDataOwned::new(self.data)
    }

}


// A packet with owned data
pub struct PktDataOwned {
    data: Arc<Vec<u8>>
}

impl PktDataOwned {
    pub fn new(data: &[u8]) -> Self{
        PktDataOwned {
            data: Arc::new(data.to_vec())
        }
    }
}


impl PktData for PktDataOwned {

    fn data(&self) -> &[u8] {
        &self.data
    }

    fn copy_or_clone(&self) -> PktDataOwned {
        PktDataOwned {
            data: self.data.clone()
        }
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

    fn copy_or_clone(&self) -> PktDataOwned {
        PktDataOwned {
            data: self.data.clone()
        }
    }

}

impl<'b> PktDataMultipart {

    pub fn new(capacity: usize) -> Self {
        PktDataMultipart {
            data: Arc::new(Vec::with_capacity(capacity)),
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
