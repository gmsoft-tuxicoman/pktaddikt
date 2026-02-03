use crate::proto::Protocols;
use crate::param::Param;
use crate::conntrack::{ConntrackRef, ConntrackWeakRef};
use std::sync::Arc;
use tracing::trace;


// Time in microsecond
pub type PktTime = i64;


// All info about a packet
pub struct Packet<'a> {
    pub ts: PktTime,
    pub datalink: Protocols,
    stack: Vec<PktInfo<'a>>,
    pub data: &'a mut dyn PktData
}


pub struct PktInfo<'a> {
    pub proto: Protocols,
    parent_ce: Option<ConntrackRef>,
    fields: Vec<Param<'a>>
}


impl<'a> Packet<'a> {

    pub fn new(ts: PktTime, datalink: Protocols, data: &'a mut impl PktData) -> Self {

        Packet {
            ts: ts,
            datalink: datalink,
            stack: Vec::with_capacity(7),
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
        let byte = self.data.read_bytes(1)?;
        Some(byte[0])
    }

    pub fn read_u16(&mut self) -> Option<u16> {
        let bytes = self.data.read_bytes(2)?;
        Some((bytes[0] as u16) << 8 | (bytes[1] as u16))
    }

    pub fn remaining_len(&self) -> usize {
        self.data.remaining_len()
    }

    pub fn skip_bytes(&mut self, size: usize) -> Result<(),()> {
        self.data.skip_bytes(size)
    }

    pub fn shrink(&mut self, new_size: usize) {
        self.data.shrink(new_size)
    }

    pub fn read_bytes(&mut self, size: usize) -> Option<&[u8]> {
        self.data.read_bytes(size)
    }
}

pub trait PktData {

    fn remaining_len(&self) -> usize;
    fn skip_bytes(&mut self, size: usize) -> Result<(),()>;
    fn shrink(&mut self, new_size: usize);
    fn read_bytes(&mut self, size: usize) -> Option<&[u8]>;
}

pub struct PktDataSimple<'a> {
    read_offset: usize,
    data: &'a[u8]
}

impl<'a> PktDataSimple<'a> {

    pub fn new(data: &'a[u8]) -> Self {
        PktDataSimple {
           read_offset: 0,
           data: data
        }
    }
}

impl PktData for PktDataSimple<'_> {

    fn remaining_len(&self) -> usize {
        self.data.len() - self.read_offset
    }

    fn skip_bytes(&mut self, size: usize) -> Result<(),()> {
        trace!("Skipping {} bytes from pkt {:p}", size, self);
        if self.data.len() - self.read_offset < size {
            self.read_offset = self.data.len();
            return Err(());
        }
        self.read_offset += size;
        return Ok(());
    }

    fn shrink(&mut self, new_size: usize) {
        trace!("Shrinking data to {} (was {})", new_size, self.data.len());
        assert!(self.data.len() >= new_size, "Trying to shrink a packet with a bigger length!");
        self.data = &self.data[0..new_size];
    }

    fn read_bytes(&mut self, size: usize) -> Option<&[u8]> {

        trace!("Reading {} bytes from pkt {:p}i (off: {}, len: {})", size, self, self.read_offset, self.data.len());
        if self.read_offset + size < self.data.len() {
            return None;
        }
        let bytes = &self.data[self.read_offset..(self.read_offset + size)];
        self.read_offset += size;
        Some(bytes)

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

}
