
use crate::conntrack::ConntrackDirection;
use crate::proto::tcp::{TCP_TH_SYN, TCP_TH_ACK};
use crate::proto::tcp::seq::TcpSeq;
use crate::packet::{Packet, PktData, PktTime, PktDataOwned};
use crate::stream::PktStream;
use crate::proto::Protocols;

use std::collections::BTreeMap;
use std::ops::Range;
use tracing::{debug, trace};

struct TcpPacket {

    seq: TcpSeq,
    ack: TcpSeq,
    ts: PktTime,
    flags: u8,
    data: PktDataOwned,
    data_range: Range<usize>
}


struct ConntrackTcpQueue {

    start_seq: Option<TcpSeq>,
    cur_seq: Option<TcpSeq>,
    pkts: BTreeMap<TcpSeq, TcpPacket>,
}

pub struct ConntrackTcp {

    forward: ConntrackTcpQueue,
    reverse: ConntrackTcpQueue,
    buff_size: usize, // Current amount of data in both forward and reverse queues
    stream_id: usize
}

impl ConntrackTcp {

    pub fn new(proto: Protocols) -> Self {

        let ct = ConntrackTcp {
            forward: ConntrackTcpQueue {
                start_seq: None,
                cur_seq: None,
                pkts: BTreeMap::new(),
            },
            reverse: ConntrackTcpQueue {
                start_seq: None,
                cur_seq: None,
                pkts: BTreeMap::new()
            },
            buff_size: 0,
            stream_id: PktStream::open(proto, Protocols::Tcp)
        };
        ct
    }

    fn get_queue(&self, dir: ConntrackDirection) -> &ConntrackTcpQueue {
        match dir {
            ConntrackDirection::Forward => &self.forward,
            ConntrackDirection::Reverse => &self.reverse,

        }
    }

    fn get_queue_mut(&mut self, dir: ConntrackDirection) -> &mut ConntrackTcpQueue {
        match dir {
            ConntrackDirection::Forward => &mut self.forward,
            ConntrackDirection::Reverse => &mut self.reverse,

        }
    }

    fn send_packet(&mut self, dir: ConntrackDirection, pkt: TcpPacket) {

        let queue = self.get_queue_mut(dir);
        *queue.cur_seq.as_mut().unwrap() += pkt.data_range.len() as u32;
        debug!("Sending packet with ts {}, seq {:?} and ack {:?}", pkt.ts, pkt.seq, pkt.ack);
        PktStream::send_data_async(self.stream_id, dir, pkt.data, pkt.data_range);
    }

    fn queue_packet(&mut self, dir: ConntrackDirection, seq: TcpSeq, ack: TcpSeq, flags: u8, pkt: &mut Packet) {

        let (data, data_range) = pkt.clone_data();
        self.buff_size += data.data().len();
        self.get_queue_mut(dir).pkts.insert(seq, TcpPacket {
            seq: seq,
            ack: ack,
            ts: pkt.ts,
            flags: flags,
            data: data,
            data_range: data_range
        });
    }

    pub fn process_packet(&mut self, dir: ConntrackDirection, seq_u32: u32, ack_u32: u32, flags: u8, pkt: &mut Packet) {

        let mut seq = TcpSeq(seq_u32);
        let ack = TcpSeq(ack_u32);
        let op_dir = dir.opposite();


        // Let's handle the SYN flag first
        if (flags & TCP_TH_SYN) != 0 {
            seq += 1;


            match self.get_queue(dir).start_seq {
                // We knew about the start seq but we have a new SYN with a different start seq
                Some(start_seq) => if start_seq != seq {
                    debug!("Possible reused TCP connection {:p} in direction {:?}: old seq {:?}, new seq {:?}", &self, dir, start_seq, seq);
                },

                // We just learned the start sequence
                None => {
                    let queue = self.get_queue_mut(dir);
                    queue.start_seq = Some(seq);
                    queue.cur_seq = Some(seq); // We can start in this direction since we have a packet
                    trace!("TCP connection {:p}: start seq {:?} in direction {:?} from SYN", &self, seq, dir);
                }
            }


            // Check the ACK flag
            if (flags & TCP_TH_ACK) != 0 {
                // We got a SYN+ACK !

                match self.get_queue(op_dir).start_seq {
                    Some(start_seq) => if start_seq != ack {
                        debug!("Most definitely a reused TCP connection {:p} in direction {:?}: old seq {:?}, new seq {:?}", &self, dir, start_seq, ack);
                    },
                    None => {
                        let queue = self.get_queue_mut(dir);
                        queue.start_seq = Some(ack);
                        trace!("TCP connection {:p}: start seq {:?} from SYN+ACK in direction {:?}", &self, seq, dir);
                    }
                }
            }
        } else {
            // Check if we have the ACK right after the SYN in case we have a uni directional
            // capture
            if self.get_queue(op_dir).start_seq.is_none() && (flags & TCP_TH_ACK) != 0 && self.get_queue(dir).start_seq == Some(seq) {
                let op_queue = self.get_queue_mut(op_dir).start_seq = Some(ack);
                trace!("TCP connection {:p}: start seq {:?} from ACK after SYN", &self, seq);
            }
        }


        // Now, let's check what to do with this packet

        if pkt.remaining_len() == 0 {
            // No payload, skip
            return;
        }


        if self.forward.cur_seq.is_none() || self.reverse.cur_seq.is_none() {

            // We don't know the sequences in both direction so let's queue the packet
            trace!("Queuing TCP packet (start_seq not known) seq: {:?}, ack: {:?}, dir: {:?}", seq, ack, dir);
            self.queue_packet(dir, seq, ack, flags, pkt);
            return
        }

        // At this point we should know about sequences in both directions


        let cur_seq = self.get_queue(dir).cur_seq.unwrap();
        let end_seq = cur_seq + pkt.remaining_len() as u32;
        let cur_ack = self.get_queue(op_dir).cur_seq.unwrap();


        // Let's see if we can process it

        if end_seq < cur_seq {
            // Old dupe packet, the whole payload is before the sequence we expected
            return;
        }

        if seq < cur_seq {
            // Some payload was already process
            let dupe: usize = (cur_seq - seq).into();

            // Skip the part we know about
            pkt.skip_bytes(dupe).unwrap();
            seq += dupe as u32;
        }


        // Let's see if it's the packet that we expected
        if seq != cur_seq {
            // Sequence doesn't match
            trace!("TCP connection {:p}: gap: cur_seq {:?}, pkt_seq {:?}", &self, cur_seq, seq);
            self.queue_packet(dir, seq, ack, flags, pkt);
            return
        }

        if cur_ack < ack {
            // The host processed some data in the reverse direction which we haven't processed yet
            trace!("TCP connection {:p}: reverse missing: cur_ack {:?}, pkt_ack {:?}", &self, cur_ack, ack);
            self.queue_packet(dir, seq, ack, flags, pkt);
        }

        // Packet is ready to be sent !
        let (data, data_range) = pkt.clone_data();
        self.send_packet(dir, TcpPacket{
            seq: seq,
            ack: ack,
            ts: pkt.ts,
            flags: flags,
            data: data,
            data_range: data_range
        });
    }
}

impl Drop for ConntrackTcp {

    fn drop(&mut self) {
        PktStream::close(self.stream_id);
    }

}

#[cfg(test)]
mod tests {

    use super::*;
    use tracing_test::traced_test;


    fn queue_pkt(ct: &mut ConntrackTcp, dir: ConntrackDirection, seq: u32, ack: u32, flags: u8, data: &[u8]) {

        let mut pkt_data = PktDataOwned::new(&data);
        let mut pkt = Packet::new(0, Protocols::Test, &mut pkt_data);
        ct.process_packet(dir, seq, ack, flags, &mut pkt);

    }

    #[test]
    #[traced_test]
    fn conntrack_tcp_basic() {
        let mut ct = ConntrackTcp::new(Protocols::Test);
        // Normal 3 way handshake
        queue_pkt(&mut ct, ConntrackDirection::Forward, 0, 0, TCP_TH_SYN, &[]);
        queue_pkt(&mut ct, ConntrackDirection::Reverse, 0, 1, TCP_TH_SYN | TCP_TH_ACK, &[]);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 1, 1, TCP_TH_ACK, &[]);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 1, 1, 0, &[ 0 ]);

    }

}
