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
    data: PktData<'a>
}


pub struct PktInfo<'a> {
    pub proto: Protocols,
    parent_ce: Option<ConntrackRef>,
    fields: Vec<Param<'a>>
}


struct PktData<'a> {
    buffers: Vec<PktBuff<'a>>,
    length: usize,
    read_offset: usize
}

struct PktBuff<'a> {
    offset: usize,
    data: &'a[u8]
}


impl<'a> Packet<'a> {

    pub fn new(ts: PktTime, datalink: Protocols, data: &'a[u8]) -> Self {

        Packet {
            ts: ts,
            datalink: datalink,
            stack: Vec::with_capacity(7),
            data: PktData::new(data)
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

    pub fn remaining_len(&self) -> usize {
        self.data.length - self.data.read_offset
    }

    pub fn skip_bytes(&mut self, size: usize) -> Result<(),()> {
        trace!("Skipping {} bytes from pkt {:p}", size, self);
        if self.data.length - self.data.read_offset < size {
            self.data.read_offset = self.data.length;
            return Err(());
        }
        self.data.read_offset += size;
        return Ok(());
    }

    pub fn shrink(&mut self, new_size: usize) {
        trace!("Shrinking data to {} (was {})", new_size, self.data.length);
        assert!(self.data.length >= new_size, "Trying to shrink a packet with a bigger length!");
        self.data.length = new_size;
    }

    pub fn read_bytes(&mut self, size: usize) -> Option<&[u8]> {

        trace!("Reading {} bytes from pkt {:p}i (off: {}, len: {})", size, self, self.data.read_offset, self.data.length);

        // FIXME handle multiple buffers
        if self.data.length - self.data.read_offset < size {
            return None;
        }
        let bytes = &self.data.buffers[0].data[self.data.read_offset..(self.data.read_offset + size)];
        self.data.read_offset += size;
        Some(bytes)

    }

    pub fn read_u8(&mut self) -> Option<u8> {
        let byte = self.read_bytes(1)?;
        Some(byte[0])
    }

    pub fn read_u16(&mut self) -> Option<u16> {
        let bytes = self.read_bytes(2)?;
        Some((bytes[0] as u16) << 8 | (bytes[1] as u16))
    }
}

impl<'a> PktData<'a> {

    fn new(data: &'a[u8]) -> Self {
       let pkt_buff = PktBuff {
           offset: 0,
           data: data
        };

        PktData {
            length: data.len(),
            read_offset: 0,
            buffers: vec![pkt_buff]
        }
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
