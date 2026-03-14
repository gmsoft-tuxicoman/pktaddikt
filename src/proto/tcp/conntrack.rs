
use crate::conntrack::ConntrackDirection;
use crate::proto::tcp::{TCP_TH_SYN, TCP_TH_ACK, TCP_TH_FIN, TCP_TH_RST};
use crate::proto::tcp::seq::TcpSeq;
use crate::packet::{Packet, PktTime, PktDataZero};
use crate::stream::PktStream;
use crate::proto::Protocols;

use std::collections::BTreeMap;
use tracing::{debug, trace};

struct TcpPacket {

    seq: TcpSeq,
    ack: TcpSeq,
    flags: u8,
    data: Packet<'static>
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum TcpState {
    New,
    SynSent,
    SynRecv,
    Established,
    HalfClosedFwd,
    HalfClosedRev,
    Closed
}

struct ConntrackTcpQueue {

    start_seq: Option<TcpSeq>,
    cur_seq: Option<TcpSeq>,
    pkts: BTreeMap<TcpSeq, TcpPacket>,
}

pub struct ConntrackTcp {

    forward: ConntrackTcpQueue,
    reverse: ConntrackTcpQueue,
    stream_id: usize,
    state: TcpState
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
            stream_id: PktStream::open(proto, Protocols::Tcp),
            state: TcpState::New
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
        self.update_state(dir, pkt.flags);
        let queue = self.get_queue_mut(dir);
        *queue.cur_seq.as_mut().unwrap() += pkt.data.remaining_len() as u32;
        if pkt.flags & TCP_TH_FIN != 0 {
            // FIN packet increase seq by 1
            *queue.cur_seq.as_mut().unwrap() += 1;
        }

        if pkt.data.remaining_len() == 0 {
            // Discard empty FIN or RST packet
            return;
        }
        debug!("Sending packet with ts {}, seq {:?} and ack {:?}", pkt.data.ts, pkt.seq, pkt.ack);
        PktStream::send_data_async(self.stream_id, dir, pkt.data);
    }

    fn queue_packet(&mut self, dir: ConntrackDirection, seq: TcpSeq, ack: TcpSeq, flags: u8, data: &mut Packet) {

        let queue = self.get_queue_mut(dir);
        let new_size = data.remaining_len();
        let old_pkt_opt = queue.pkts.insert(seq, TcpPacket {
            seq: seq,
            ack: ack,
            flags: flags,
            data: data.clone(),
        });

        if let Some(old_pkt) = old_pkt_opt {
            if old_pkt.data.remaining_len() > new_size {
                // Another packet with the same sequence but bigger was already present
                // Put it back in the queue
                queue.pkts.insert(seq, old_pkt);
            }
        }
    }

    fn update_state(&mut self, dir: ConntrackDirection, flags: u8) {

        let new_state;

        if flags & TCP_TH_SYN != 0 {
            if flags & TCP_TH_ACK != 0 {
                new_state = TcpState::SynRecv;
            } else {
                new_state = TcpState::SynSent;
            }
        } else if flags & TCP_TH_FIN != 0 {
            match dir {
                ConntrackDirection::Forward => {
                    if self.state == TcpState::HalfClosedRev {
                        new_state = TcpState::Closed;
                    } else {
                        new_state = TcpState::HalfClosedFwd;
                    }
                },
                ConntrackDirection::Reverse => {
                    if self.state == TcpState::HalfClosedFwd {
                        new_state = TcpState::Closed;
                    } else {
                        new_state = TcpState::HalfClosedRev;
                    }

                }
            }
        } else if flags & TCP_TH_RST != 0 {
            new_state = TcpState::Closed;
        } else {
            new_state = TcpState::Established;
        }
        
        if new_state > self.state {
            self.state = new_state;
        }

    }

    pub fn get_state(&self) -> TcpState {
        self.state
    }

    pub fn process_packet(&mut self, dir: ConntrackDirection, seq_u32: u32, ack_u32: u32, flags: u8, data: &mut Packet) {

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
                        debug!("Most definitely a reused TCP connection {:p} in direction {:?}: old seq {:?}, new seq {:?}", &self, op_dir, start_seq, ack);
                    },
                    None => {
                        let queue = self.get_queue_mut(op_dir);
                        queue.start_seq = Some(ack);
                        queue.cur_seq = Some(seq); // Reverse direction is confirmed
                        trace!("TCP connection {:p}: start seq {:?} from SYN+ACK in direction {:?}", &self, seq, op_dir);
                    }
                }
            }

            // SYN packets won't get queue so update the state now
            self.update_state(dir, flags);
        } else {
            // Check if we have the ACK right after the SYN in case we have a uni directional
            // capture
            if (flags & TCP_TH_ACK) != 0 && self.get_queue(dir).start_seq == Some(seq) {
                self.update_state(dir, flags);
                if self.get_queue(op_dir).start_seq.is_none() {
                    self.get_queue_mut(op_dir).start_seq = Some(ack);
                    trace!("TCP connection {:p}: start seq {:?} from ACK after SYN", &self, seq);
                }
            }
        }


        // Now, let's check what to do with this packet

        if (data.remaining_len() == 0) && (flags & (TCP_TH_FIN | TCP_TH_RST) == 0) {
            // No payload, skip unless it's FIN or RST
            return;
        }


        if self.forward.cur_seq.is_none() || self.reverse.cur_seq.is_none() {

            // We don't know the sequences in both direction so let's queue the packet
            trace!("Queuing TCP packet (start_seq not known) seq: {:?}, ack: {:?}, dir: {:?}", seq, ack, dir);
            self.queue_packet(dir, seq, ack, flags, data);
            return
        }

        // At this point we should know about sequences in both directions


        let cur_seq = self.get_queue(dir).cur_seq.unwrap();
        let end_seq = seq + data.remaining_len() as u32;
        let cur_ack = self.get_queue(op_dir).cur_seq.unwrap();


        // Let's see if we can process it

        if end_seq <= cur_seq {
            // Old dupe packet, the whole payload is before the sequence we expected
            return;
        }

        if seq < cur_seq {
            // Some payload was already process
            let dupe: usize = (cur_seq - seq).into();

            // Skip the part we know about
            data.skip_bytes(dupe).unwrap();
            seq += dupe as u32;
        }


        // Let's see if it's the packet that we expected
        if seq != cur_seq {
            // Sequence doesn't match
            trace!("TCP connection {:p}: gap: cur_seq {:?}, pkt_seq {:?}", &self, cur_seq, seq);
            self.queue_packet(dir, seq, ack, flags, data);
            return
        }

        if cur_ack < ack {
            // The host processed some data in the reverse direction which we haven't processed yet
            trace!("TCP connection {:p}: reverse missing: cur_ack {:?}, pkt_ack {:?}", &self, cur_ack, ack);
            self.queue_packet(dir, seq, ack, flags, data);
            return;
        }

        // Packet is ready to be sent !
        self.send_packet(dir, TcpPacket{
            seq: seq,
            ack: ack,
            flags: flags,
            data: data.clone(),
        });

        // Check if this packet filled a gap
        self.process_more_packets();
    }

    fn process_more_packets(&mut self) {


        let mut tries = 2; // Try once in each direction
        let mut next_dir = ConntrackDirection::Forward;
        while tries > 0 {

            tries -= 1;
            let dir = next_dir;
            next_dir = next_dir.opposite();


            let (queue, queue_op) = match dir {
                ConntrackDirection::Forward => (&mut self.forward, &mut self.reverse),
                ConntrackDirection::Reverse => (&mut self.reverse, &mut self.forward),
            };

            let pkt = loop {
                let mut entry = match queue.pkts.first_entry() {
                    Some(e) => e,
                    None => break None
                };
                let cur_seq = queue.cur_seq.unwrap();
                let cur_ack = queue_op.cur_seq.unwrap();
                let pkt = entry.get_mut();

                let end_seq = pkt.seq + (pkt.data.remaining_len() as u32);
                if end_seq <= cur_seq {
                    // Duplicate
                    //trace!("TCP connection {:p}: gap: cur_seq {:?}, pkt_seq {:?}", &self, cur_seq, pkt.seq);
                    entry.remove();
                    continue;
                }

                if pkt.seq < cur_seq {
                    // Trim data
                    let dupe: usize = (cur_seq - pkt.seq).into();
                    pkt.data.skip_bytes(dupe).unwrap();
                    pkt.seq += dupe as u32;

                }

                if pkt.seq != cur_seq {
                    // Not the expected sequence
                    //trace!("TCP connection {:p}: gap: cur_seq {:?}, pkt_seq {:?}", &self, cur_seq, pkt.seq);
                    break None;
                }

                if cur_ack < pkt.ack {
                    // The host processed some data in the reverse direction which we haven't processed yet
                    //trace!("TCP connection {:p}: reverse missing: cur_ack {:?}, pkt_ack {:?}", &self, cur_ack, pkt.ack);
                    break None;
                }

                // Remove this packet from the list
                break Some(entry.remove());

            };

            if pkt.is_some() {
                let pkt = pkt.unwrap();
                debug!("Sending additional packet with ts {}, seq {:?} and ack {:?}", pkt.data.ts, pkt.seq, pkt.ack);
                self.send_packet(dir, pkt);
                tries = 2; // We unblocked some packets, let's keep trying in both directions
            }
        }

    }

    fn force_dequeue(&mut self) {

        if self.forward.pkts.len() == 0 && self.reverse.pkts.len() == 0 {
            // Nothing to do
            return;
        }

        // Find out which direction has a gap
        let mut gap_fwd: usize = 0;
        let mut gap_rev: usize = 0;
        let mut ts_fwd: Option<PktTime> = None;
        let mut ts_rev: Option<PktTime> = None;

        let mut dir = ConntrackDirection::Forward;

        // Check if we have a gap in the forward direction
        if let Some(entry) = self.forward.pkts.first_entry() {
            if let Some(cur_seq) = self.forward.cur_seq {
                let pkt = entry.get();
                ts_fwd = Some(pkt.data.ts);
                gap_fwd = usize::from(pkt.seq - cur_seq)
            }
        }

        // Check if we have a gap in the reverse direction
        if let Some(entry) = self.reverse.pkts.first_entry() {
            if let Some(cur_seq) = self.reverse.cur_seq {
                let pkt = entry.get();
                ts_rev = Some(pkt.data.ts);
                gap_rev = usize::from(pkt.seq - cur_seq);
                if gap_rev > 0 {
                    dir = ConntrackDirection::Reverse;
                }
            }
        }

        // We have gap in both, use the first packet we received
        if gap_fwd > 0 && gap_rev > 0 {
            dir = match ts_fwd < ts_rev {
                true => ConntrackDirection::Forward,
                false => ConntrackDirection::Reverse,
            }
        }

        let (mut gap, ts) = match dir {
            ConntrackDirection::Forward => (gap_fwd, ts_fwd.unwrap()),
            ConntrackDirection::Reverse => (gap_rev, ts_rev.unwrap())
        };

        while gap > 0 {
            let filler_len = match gap > PktDataZero::max_len() {
                true => PktDataZero::max_len(),
                false => gap,

            };

            let data = PktDataZero::new(filler_len);

            self.send_packet(dir, TcpPacket{
                seq: TcpSeq(0),
                ack: TcpSeq(0),
                flags: 0,
                data: Packet::new(ts, data)
            });

            gap -= filler_len;
        }

        // Gap was filled. process some more
        self.process_more_packets();
    }

}

impl Drop for ConntrackTcp {

    fn drop(&mut self) {

        // Make sure all the packets get processed
        while self.forward.pkts.len() > 0 || self.reverse.pkts.len() > 0 {
            self.force_dequeue();
        }

        PktStream::close(self.stream_id);
    }

}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::proto::ProtoTest;
    use crate::packet::PktDataOwned;
    use tracing_test::traced_test;


    fn queue_pkt(ct: &mut ConntrackTcp, dir: ConntrackDirection, seq: u32, ack: u32, flags: u8, data: &[u8]) {

        let pkt_data = PktDataOwned::new(&data);
        let mut pkt = Packet::new(0, pkt_data);
        ct.process_packet(dir, seq, ack, flags, &mut pkt);

    }

    #[test]
    fn conntrack_tcp_basic() {

        ProtoTest::add_expectation(&[ 0 ], 0);

        let mut ct = ConntrackTcp::new(Protocols::Test);
        // Normal 3 way handshake
        queue_pkt(&mut ct, ConntrackDirection::Forward, 0, 0, TCP_TH_SYN, &[]);
        queue_pkt(&mut ct, ConntrackDirection::Reverse, 0, 1, TCP_TH_SYN | TCP_TH_ACK, &[]);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 1, 1, TCP_TH_ACK, &[]);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 1, 1, 0, &[ 0 ]);

        ProtoTest::assert_empty();

    }

    #[test]
    fn conntrack_tcp_missed_syn() {

        ProtoTest::add_expectation(&[ 0 ], 0);

        let mut ct = ConntrackTcp::new(Protocols::Test);
        queue_pkt(&mut ct, ConntrackDirection::Reverse, 0, 1, TCP_TH_SYN | TCP_TH_ACK, &[]);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 1, 1, 0, &[ 0 ]);

        ProtoTest::assert_empty();

    }

    #[test]
    fn conntrack_tcp_out_of_order_one_direction() {

        ProtoTest::add_expectation(&[ 0 ], 0);
        ProtoTest::add_expectation(&[ 1 ], 0);

        let mut ct = ConntrackTcp::new(Protocols::Test);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 0, 0, TCP_TH_SYN, &[]);
        queue_pkt(&mut ct, ConntrackDirection::Reverse, 0, 1, TCP_TH_SYN | TCP_TH_ACK, &[]);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 1, 1, TCP_TH_ACK, &[]);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 2, 1, 0, &[ 1 ]);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 1, 1, 0, &[ 0 ]);

        ProtoTest::assert_empty();
    }

    #[test]
    #[traced_test]
    fn conntrack_tcp_complex() {

        ProtoTest::add_expectation(&[ 1 ], 0);
        ProtoTest::add_expectation(&[ 2 ], 0);
        ProtoTest::add_expectation(&[ 3 ], 0);
        ProtoTest::add_expectation(&[ 4, 5 ], 0); // Bigger dupe has precedence
        ProtoTest::add_expectation(&[ 6 ], 0);

        let mut ct = ConntrackTcp::new(Protocols::Test);
        // Normal 3 way handshake
        queue_pkt(&mut ct, ConntrackDirection::Forward, 0, 0, TCP_TH_SYN, &[]);
        queue_pkt(&mut ct, ConntrackDirection::Reverse, 0, 1, TCP_TH_SYN | TCP_TH_ACK, &[]);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 1, 1, TCP_TH_ACK, &[]);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 1, 1, 0, &[ 1 ]);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 1, 1, 0, &[ 1 ]); // Dupe
        queue_pkt(&mut ct, ConntrackDirection::Forward, 1, 1, 0, &[ 1, 2 ]); // Needs trimming

        queue_pkt(&mut ct, ConntrackDirection::Forward, 4, 1, 0, &[ 4 ]); // Out of oder
        queue_pkt(&mut ct, ConntrackDirection::Forward, 4, 1, 0, &[ 4 ]); // Dupe
        queue_pkt(&mut ct, ConntrackDirection::Forward, 4, 1, 0, &[ 4, 5 ]); // Should replace the smalle dupes
        queue_pkt(&mut ct, ConntrackDirection::Forward, 4, 1, 0, &[ 4 ]); // Dupe
        queue_pkt(&mut ct, ConntrackDirection::Forward, 5, 1, 0, &[ 5, 6 ]); // Needs trimming
        queue_pkt(&mut ct, ConntrackDirection::Forward, 3, 1, 0, &[ 3 ]); //  Missing packet


        ProtoTest::assert_empty();

    }

    #[test]
    #[traced_test]
    fn conntrack_tcp_reverse_missing() {

        ProtoTest::add_expectation(&[ 1 ], 0);
        ProtoTest::add_expectation(&[ 11 ], 0);
        ProtoTest::add_expectation(&[ 2 ], 0);
        ProtoTest::add_expectation(&[ 3 ], 0);
        ProtoTest::add_expectation(&[ 4 ], 0);
        ProtoTest::add_expectation(&[ 5 ], 0);
        ProtoTest::add_expectation(&[ 12 ], 0);
        ProtoTest::add_expectation(&[ 6 ], 0);
        ProtoTest::add_expectation(&[ 7 ], 0);

        let mut ct = ConntrackTcp::new(Protocols::Test);
        // Normal 3 way handshake
        queue_pkt(&mut ct, ConntrackDirection::Forward, 0, 10, TCP_TH_SYN, &[]);
        queue_pkt(&mut ct, ConntrackDirection::Reverse, 10, 1, TCP_TH_SYN | TCP_TH_ACK, &[]);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 1, 11, TCP_TH_ACK, &[]);

        queue_pkt(&mut ct, ConntrackDirection::Forward, 1, 11, 0, &[ 1 ]); // First data packet
        queue_pkt(&mut ct, ConntrackDirection::Forward, 2, 12, 0, &[ 2 ]); // Needs to wait for packet with seq 11 in reverse dir
        queue_pkt(&mut ct, ConntrackDirection::Reverse, 11, 1, 0, &[ 11 ]); // The awaited packet
        queue_pkt(&mut ct, ConntrackDirection::Forward, 3, 12, 0, &[ 3 ]); // Some more data


        queue_pkt(&mut ct, ConntrackDirection::Forward, 5, 12, 0, &[ 5 ]); // Create a gap to queue packets
        queue_pkt(&mut ct, ConntrackDirection::Forward, 6, 13, 0, &[ 6 ]); // Needs to wait for seq 13
        queue_pkt(&mut ct, ConntrackDirection::Reverse, 12, 5, 0, &[ 12 ]); // Our awaited ack
        queue_pkt(&mut ct, ConntrackDirection::Forward, 7, 13, 0, &[ 7 ]); // One more queued packet
        queue_pkt(&mut ct, ConntrackDirection::Forward, 4, 12, 0, &[ 4 ]); // Our awaited packet !

        ProtoTest::assert_empty();

    }

    #[test]
    #[traced_test]
    fn conntrack_tcp_gap() {

        ProtoTest::add_expectation(&[ 1 ], 0);
        ProtoTest::add_expectation(&[ 0 ], 0); // Gap filled for missing packet
        ProtoTest::add_expectation(&[ 3 ], 0);

        let mut ct = ConntrackTcp::new(Protocols::Test);
        // Normal 3 way handshake
        queue_pkt(&mut ct, ConntrackDirection::Forward, 0, 0, TCP_TH_SYN, &[]);
        queue_pkt(&mut ct, ConntrackDirection::Reverse, 0, 1, TCP_TH_SYN | TCP_TH_ACK, &[]);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 1, 1, TCP_TH_ACK, &[]);

        queue_pkt(&mut ct, ConntrackDirection::Forward, 1, 1, 0, &[ 1 ]); // First data packet
        queue_pkt(&mut ct, ConntrackDirection::Forward, 3, 1, 0, &[ 3 ]); // Data packet with a missing byte

        // Fill the gap
        ct.force_dequeue();

        ProtoTest::assert_empty();
    }

    #[test]
    #[traced_test]
    fn conntrack_tcp_state() {

        ProtoTest::add_expectation(&[ 1 ], 0);
        ProtoTest::add_expectation(&[ 2 ], 0);
        ProtoTest::add_expectation(&[ 3 ], 0);
        ProtoTest::add_expectation(&[ 11 ], 0);

        let mut ct = ConntrackTcp::new(Protocols::Test);
        assert_eq!(ct.state, TcpState::New);
        // Normal 3 way handshake
        queue_pkt(&mut ct, ConntrackDirection::Forward, 0, 10, TCP_TH_SYN, &[]);
        assert_eq!(ct.state, TcpState::SynSent);
        queue_pkt(&mut ct, ConntrackDirection::Reverse, 10, 0, TCP_TH_SYN | TCP_TH_ACK, &[]);
        assert_eq!(ct.state, TcpState::SynRecv);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 1, 11, TCP_TH_ACK, &[]);
        assert_eq!(ct.state, TcpState::Established);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 1, 11, 0, &[ 1 ]);
        assert_eq!(ct.state, TcpState::Established);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 2, 11, 0, &[ 2 ]);
        assert_eq!(ct.state, TcpState::Established);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 3, 11, TCP_TH_FIN, &[ 3 ]);
        assert_eq!(ct.state, TcpState::HalfClosedFwd);
        queue_pkt(&mut ct, ConntrackDirection::Reverse, 11, 5, TCP_TH_FIN, &[ 11 ]);
        assert_eq!(ct.state, TcpState::Closed);

        ProtoTest::assert_empty();
    }
}

