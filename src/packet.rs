use crate::proto::Protocols;
use crate::param::Param;
use crate::conntrack::{ConntrackRef, ConntrackWeakRef};
use std::sync::Arc;
use std::ops::Range;
use tracing::{warn, trace};


// Time in microsecond
pub type PktTime = i64;



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

    pub fn shrink(&mut self, new_size: usize) {
        trace!("Shrinking data to {} (was {})", new_size, self.length);
        assert!(self.length >= new_size, "Trying to shrink a packet with a bigger length!");
        self.length = new_size;
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
    status: PktDataMultipartStatus, // Status of the multipart
    read_offset: usize, // Current read offset
    data: Vec<u8>, // Concatenated data
    ranges: Vec<Range<usize>> // Info tracking about data
}

#[derive(PartialEq, Debug)]
enum PktDataMultipartStatus {
    Incomplete,
    Complete,
    Processed
}

impl PktData for PktDataMultipart {

    fn data(&self) -> &[u8] {
        &self.data
    }
}

impl<'b> PktDataMultipart {

    pub fn new(capacity: usize) -> Self {
        PktDataMultipart {
            status: PktDataMultipartStatus::Incomplete,
            read_offset: 0,
            data: Vec::with_capacity(capacity),
            ranges: Vec::with_capacity(2)
        }
    }

    pub fn add(&mut self, offset: usize, data: &'b [u8]) {
        // This implementation only works for contiguous packets
        // Packets nested or not having proper boundaries will be dropped

        if self.status == PktDataMultipartStatus::Processed {
            // Already been processed, discard extra part
            trace!("Multipart {:p} has already been processed. Discarding data", self);
            return
        }


        // Find out where to add the packet
        let mut found: Option<usize> = None;
        let range = Range::<usize> {
            start: offset,
            end: offset + data.len()
        };

        for (index, value) in self.ranges.iter().enumerate() {
            if value.end <= range.start { // We reached the packet after this one
                found = Some(index);
                break;
            }
            if value.start == range.start { // We found the same packet
                if value.end != range.end {
                    // FIXME should I use the biggest packet ?
                    // This scenario isn't supposed to happen, at least for IP
                    warn!("Size mismatch ({} -> {}) for multipart {:p}. Discarding part", range.start, range.end, self);
                }
                trace!("Discarded duplicate part {} -> {} for multipart {:p}", range.start, range.end, self);

                // Nothing to do
                return

            }
        }

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

        // Insert the range in the array
        if let Some(index) = found {
            self.ranges.insert(index + 1, range);
        } else {
            if offset == 0 {
               self.ranges.insert(0, range);
            }
        }

    }


    pub fn set_complete(&mut self) {

        // Check if the packet has already been marked as complete
        if self.status != PktDataMultipartStatus::Incomplete {
            trace!("Multipart {:p} cannot be marked as completed as it's already {:?}", self, self.status);
            return
        }
        self.status = PktDataMultipartStatus::Complete;
        trace!("Multipart {:p} marked complete", self);
        self.process();
    }

    fn process(&mut self) {

        // Check for gaps by checking that we have the same ammount of data than the last offset of
        // the last part
        let mut length :usize = 0;
        for part in &self.ranges {
            length += part.end - part.start;
        }

        if length != self.ranges.last().unwrap().end {
            // Not complete
            return
        }
    }
}
