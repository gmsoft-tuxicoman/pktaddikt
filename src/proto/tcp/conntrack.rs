
use crate::conntrack::ConntrackDirection;
use crate::proto::tcp::{TCP_TH_SYN, TCP_TH_ACK, TCP_TH_FIN, TCP_TH_RST};
use crate::proto::tcp::seq::TcpSeq;
use crate::packet::{Packet, PktTime, PktDataZero, PktInfoStack};
use crate::stream::PktStream;
use crate::proto::Protocols;
use crate::event::{Event, EventId, EventPayload};
use crate::param::ParamValue;

use std::collections::BTreeMap;
use std::time::Duration;
use tracing::{debug, trace};
use serde::Serialize;

const CONNTRACK_TCP_MAX_BUFFER :usize = 1024 * 1024;

#[derive(Debug, Serialize)]
pub struct NetTcpConnectionStart {
    #[serde(flatten)]
    conn_id: EventId,
    src_host: Option<ParamValue>,
    dst_host: Option<ParamValue>,
    src_port: u16,
    dst_port: u16,
}

#[derive(Debug, Serialize)]
pub struct NetTcpConnectionEnd {
    #[serde(flatten)]
    conn_id: EventId,
    duration: Duration,
    src_host: Option<ParamValue>,
    dst_host: Option<ParamValue>,
    src_port: u16,
    dst_port: u16,
    fwd_bytes: usize,
    rev_bytes: usize,
    fwd_ip_bytes: usize,
    rev_ip_bytes: usize,
    fwd_pkts: usize,
    rev_pkts: usize,
    fwd_missed_bytes: usize,
    rev_missed_bytes: usize,
}

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

struct ConntrackTcpDir {

    start_seq: Option<TcpSeq>,
    cur_seq: Option<TcpSeq>,
    pkts: BTreeMap<TcpSeq, TcpPacket>,
    buff_size: usize,
    tot_bytes: usize,
    tot_ip_bytes: usize,
    tot_pkts: usize,
    missed_bytes: usize,
}

#[derive(Debug, PartialEq)]
enum ConntrackTcpFlowState {
    Probing,
    Unidirectional,
    Bidirectional,
}

pub struct ConntrackTcp {

    forward: ConntrackTcpDir,
    reverse: ConntrackTcpDir,
    stream: Option<PktStream>,
    state: TcpState,
    start_ts: Option<PktTime>,
    last_ts: PktTime,
    conn_id: Option<EventId>,
    flow_state: ConntrackTcpFlowState,
    src_port: u16,
    dst_port: u16,
    src_host: Option<ParamValue>,
    dst_host: Option<ParamValue>,
}

impl ConntrackTcp {

    pub fn new(proto: Protocols, infos: &PktInfoStack) -> Self {

        let ct = ConntrackTcp {
            forward: ConntrackTcpDir {
                start_seq: None,
                cur_seq: None,
                pkts: BTreeMap::new(),
                buff_size: 0,
                tot_bytes: 0,
                tot_ip_bytes: 0,
                tot_pkts: 0,
                missed_bytes: 0,
            },
            reverse: ConntrackTcpDir {
                start_seq: None,
                cur_seq: None,
                pkts: BTreeMap::new(),
                buff_size: 0,
                tot_bytes: 0,
                tot_ip_bytes: 0,
                tot_pkts: 0,
                missed_bytes: 0,
            },
            stream: PktStream::new(proto, infos),
            state: TcpState::New,
            start_ts: None,
            last_ts: PktTime::from_nanos(0),
            conn_id: None,
            flow_state: ConntrackTcpFlowState::Probing,
            src_port: infos.proto_from_last(2).unwrap().get_field(0).value.unwrap().get_u16(),
            dst_port: infos.proto_from_last(2).unwrap().get_field(1).value.unwrap().get_u16(),
            src_host: infos.proto_from_last(3).and_then(|p| p.get_field(0).value),
            dst_host: infos.proto_from_last(3).and_then(|p| p.get_field(1).value),
        };
        ct
    }

    fn get_dir(&self, dir: ConntrackDirection) -> &ConntrackTcpDir {
        match dir {
            ConntrackDirection::Forward => &self.forward,
            ConntrackDirection::Reverse => &self.reverse,

        }
    }

    fn get_dir_mut(&mut self, dir: ConntrackDirection) -> &mut ConntrackTcpDir {
        match dir {
            ConntrackDirection::Forward => &mut self.forward,
            ConntrackDirection::Reverse => &mut self.reverse,

        }
    }

    fn send_packet(&mut self, dir: ConntrackDirection, flags: u8, data: &mut Packet, is_missed: bool) {
        self.update_state(dir, flags);
        let queue = self.get_dir_mut(dir);
        let mut seq_advance = data.remaining_len() as u32;
        if (flags & TCP_TH_FIN) != 0 {
            seq_advance += 1;
        }

        queue.tot_bytes += data.remaining_len();
        *queue.cur_seq.as_mut().unwrap() += seq_advance;

        if data.remaining_len() == 0 {
            // Discard empty FIN or RST packet
            return;
        }
        debug!("Sending packet with ts {}", data.ts);
        if self.stream.is_some() {
            self.stream.as_mut().unwrap().process_packet(dir, data);
        }
    }

    fn queue_packet(&mut self, dir: ConntrackDirection, seq: TcpSeq, ack: TcpSeq, flags: u8, data: &mut Packet) {

        let new_size = data.remaining_len();
        let new_data = match self.stream {
            Some(ref s) =>  match s.is_active() {
                true => data.clone(),
                false => data.clone_zero(),
            },
            None => data.clone_zero(),
        };
        let queue = self.get_dir_mut(dir);
        let old_pkt_opt = queue.pkts.insert(seq, TcpPacket {
            seq: seq,
            ack: ack,
            flags: flags,
            data: new_data,
        });

        if let Some(old_pkt) = old_pkt_opt {
            if old_pkt.data.remaining_len() > new_size {
                // Another packet with the same sequence but bigger was already present
                // Put it back in the queue
                queue.pkts.insert(seq, old_pkt);
            }
        } else {
            queue.buff_size += new_size;
            if queue.buff_size > CONNTRACK_TCP_MAX_BUFFER {
                self.force_dequeue();
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
            if self.flow_state == ConntrackTcpFlowState::Bidirectional {
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
            } else {
                // If we have a uni directional stream or we didn't get anyhing in the reverse
                // direction yet, consider the stream closed
                new_state = TcpState::Closed;
            }
        } else if flags & TCP_TH_RST != 0 {
            new_state = TcpState::Closed;
        } else {
            new_state = TcpState::Established;
        }
        
        if new_state > self.state {
            self.state = new_state;
            if new_state == TcpState::Closed {
                self.send_conn_end_evt();
            }

        }
    }

    fn send_conn_end_evt(&self) {
        // Send the end event
        let evt_pload = NetTcpConnectionEnd {
            conn_id: self.conn_id.clone().unwrap(),
            duration: (self.last_ts - self.start_ts.unwrap()).into(),
            src_host: self.src_host,
            dst_host: self.dst_host,
            src_port: self.src_port,
            dst_port: self.dst_port,
            fwd_bytes: self.forward.tot_bytes,
            rev_bytes: self.reverse.tot_bytes,
            fwd_ip_bytes: self.forward.tot_ip_bytes,
            rev_ip_bytes: self.reverse.tot_ip_bytes,
            fwd_pkts: self.forward.tot_pkts,
            rev_pkts: self.reverse.tot_pkts,
            fwd_missed_bytes: self.forward.missed_bytes,
            rev_missed_bytes: self.reverse.missed_bytes,

        };
        let evt = Event::new(self.last_ts, EventPayload::NetTcpConnectionEnd(evt_pload));
        evt.send();
    }

    pub fn get_state(&self) -> TcpState {
        self.state
    }

    pub fn process_packet(&mut self, dir: ConntrackDirection, seq_u32: u32, ack_u32: u32, flags: u8, data: &mut Packet, ip_len: u32) {

        let mut seq = TcpSeq(seq_u32);
        let ack = TcpSeq(ack_u32);
        let op_dir = dir.opposite();

        {
            // Update stats
            let queue = self.get_dir_mut(dir);
            queue.tot_pkts += 1;
            queue.tot_ip_bytes += ip_len as usize;
        }

        // Send the start event
        if self.start_ts.is_none() {
            self.start_ts = Some(data.ts);
            self.conn_id = Some(EventId::new(data.ts));
            let evt_pload = NetTcpConnectionStart {
                conn_id: self.conn_id.clone().unwrap(),
                src_host: self.src_host,
                dst_host: self.dst_host,
                src_port: self.src_port,
                dst_port: self.dst_port,
            };

            let evt = Event::new(data.ts, EventPayload::NetTcpConnectionStart(evt_pload));
            evt.send();
        }

        if self.last_ts < data.ts {
            self.last_ts = data.ts;
        }

        let mut end_seq = seq + data.remaining_len() as u32;

        // Let's handle the SYN flag first
        if (flags & TCP_TH_SYN) != 0 {
            seq += 1;
            end_seq += 1;


            match self.get_dir(dir).start_seq {
                // We knew about the start seq but we have a new SYN with a different start seq
                Some(start_seq) => if start_seq != seq {
                    debug!("Possible reused TCP connection {:p} in direction {:?}: old seq {:?}, new seq {:?}", &self, dir, start_seq, seq);
                },

                // We just learned the start sequence
                None => {
                    let queue = self.get_dir_mut(dir);
                    queue.start_seq = Some(seq);
                    queue.cur_seq = Some(seq); // We can start in this direction since we have a packet
                    trace!("TCP connection {:p}: start seq {:?} in direction {:?} from SYN", &self, seq, dir);
                }
            }


            // Check the ACK flag
            if (flags & TCP_TH_ACK) != 0 {
                // We got a SYN+ACK !

                match self.get_dir(op_dir).start_seq {
                    Some(start_seq) => if start_seq != ack {
                        debug!("Most definitely a reused TCP connection {:p} in direction {:?}: old seq {:?}, new seq {:?}", &self, op_dir, start_seq, ack);
                    },
                    None => {
                        let queue = self.get_dir_mut(op_dir);
                        queue.start_seq = Some(ack);
                        trace!("TCP connection {:p}: start seq {:?} from SYN+ACK in direction {:?}", &self, seq, op_dir);
                    }
                }
            }

            // SYN packets won't get queue so update the state now
            self.update_state(dir, flags);

            if self.flow_state == ConntrackTcpFlowState::Probing && self.forward.cur_seq.is_some() && self.reverse.cur_seq.is_some() {
                // We have a bidir stream
                self.flow_state = ConntrackTcpFlowState::Bidirectional;
            }
        } else {
            // Check if we have the ACK right after the SYN in case we have a uni directional
            // capture
            if (flags & TCP_TH_ACK) != 0 && self.get_dir(dir).start_seq == Some(seq) {
                self.update_state(dir, flags);
                if self.get_dir(op_dir).start_seq.is_none() {
                    self.get_dir_mut(op_dir).start_seq = Some(ack);
                    trace!("TCP connection {:p}: start seq {:?} from ACK after SYN", &self, ack);
                }
            }
        }

        if (flags & TCP_TH_FIN) != 0 {
            end_seq += 1;
        }

        // Now, let's check what to do with this packet

        if (data.remaining_len() == 0) && (flags & (TCP_TH_FIN | TCP_TH_RST) == 0) {
            // No payload, skip unless it's FIN or RST
            return;
        }

        // At this point we should know about sequences in both directions

        let cur_seq = match self.get_dir(dir).cur_seq {
            Some(s) => s,
            None => {
                // We don't know the start sequences so let's queue the packet
                trace!("Queuing TCP packet (start_seq not known) seq: {:?}, ack: {:?}, dir: {:?}", seq, ack, dir);
                self.queue_packet(dir, seq, ack, flags, data);

                if self.flow_state != ConntrackTcpFlowState::Bidirectional && self.get_dir(op_dir).cur_seq.is_some() {
                    // Mark stream as bidir
                    self.flow_state = ConntrackTcpFlowState::Bidirectional;
                }
                return
            }
        };



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


        if (self.flow_state != ConntrackTcpFlowState::Unidirectional) && ((flags & TCP_TH_SYN) == 0) {
            // Let's check the ack now
            let cur_ack = match self.get_dir(op_dir).cur_seq {
                Some(a) => a,
                None => {
                    // We don't know the ack so let's queue the packet
                    trace!("Queuing TCP packet (ack not known) seq: {:?}, ack: {:?}, dir: {:?}", seq, ack, dir);
                    self.queue_packet(dir, seq, ack, flags, data);
                    return
                }
            };

            if cur_ack < ack {
                // The host processed some data in the reverse direction which we haven't processed yet
                trace!("TCP connection {:p}: reverse missing: cur_ack {:?}, pkt_ack {:?}", &self, cur_ack, ack);
                self.queue_packet(dir, seq, ack, flags, data);
                return;
            }
        }

        // Packet is ready to be sent !
        self.send_packet(dir, flags, data, false);

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
                let pkt = entry.get_mut();

                let end_seq = pkt.seq + (pkt.data.remaining_len() as u32);
                if end_seq <= cur_seq {
                    // Duplicate
                    //trace!("TCP connection {:p}: gap: cur_seq {:?}, pkt_seq {:?}", &self, cur_seq, pkt.seq);
                    queue.buff_size -= entry.remove().data.remaining_len();
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

                if self.flow_state == ConntrackTcpFlowState::Probing {
                    self.flow_state = match queue_op.cur_seq {
                        Some(_) => ConntrackTcpFlowState::Bidirectional,
                        None => ConntrackTcpFlowState::Unidirectional,
                    }
                }

                if self.flow_state != ConntrackTcpFlowState::Unidirectional {
                    let cur_ack = queue_op.cur_seq.unwrap();
                    if cur_ack < pkt.ack {
                        // The host processed some data in the reverse direction which we haven't processed yet
                        //trace!("TCP connection {:p}: reverse missing: cur_ack {:?}, pkt_ack {:?}", &self, cur_ack, pkt.ack);
                        break None;
                    }
                }

                // Remove this packet from the list
                let ret = entry.remove();
                queue.buff_size -= ret.data.remaining_len();
                break Some(ret);

            };

            if pkt.is_some() {
                let mut pkt = pkt.unwrap();
                debug!("Sending additional packet with ts {}, seq {:?} and ack {:?}", pkt.data.ts, pkt.seq, pkt.ack);
                self.send_packet(dir, pkt.flags, &mut pkt.data, false);
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
            let pkt = entry.get();
            ts_fwd = Some(pkt.data.ts);
            if let Some(cur_seq) = self.forward.cur_seq {
                gap_fwd = usize::from(pkt.seq - cur_seq)
            } else {
                // We didn't capture the start of the connections, let's start it now
                self.forward.start_seq = Some(pkt.seq);
                self.forward.cur_seq = Some(pkt.seq);
            }
        }

        // Check if we have a gap in the reverse direction
        if let Some(entry) = self.reverse.pkts.first_entry() {
            let pkt = entry.get();
            ts_rev = Some(pkt.data.ts);
            if let Some(cur_seq) = self.reverse.cur_seq {
                gap_rev = usize::from(pkt.seq - cur_seq);
                if gap_rev > 0 {
                    dir = ConntrackDirection::Reverse;
                }
            } else {
                // We didn't capture the start of the connections, let's start it now
                self.reverse.start_seq = Some(pkt.seq);
                self.reverse.cur_seq = Some(pkt.seq);
            }
        }

        // Check if there is a gap to fill
        if gap_fwd > 0 || gap_rev > 0 {

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

            self.get_dir_mut(dir).missed_bytes += gap;

            trace!("Filling gap of {} bytes", gap);

            while gap > 0 {
                let filler_len = match gap > PktDataZero::max_len() {
                    true => PktDataZero::max_len(),
                    false => gap,

                };

                let data = PktDataZero::new(filler_len);

                self.send_packet(dir, 0, &mut Packet::new(ts, data), true);

                gap -= filler_len;
            }
        }

        self.process_more_packets();
    }

}

impl Drop for ConntrackTcp {

    fn drop(&mut self) {

        // Make sure all the packets get processed
        while self.forward.pkts.len() > 0 || self.reverse.pkts.len() > 0 {
            self.force_dequeue();
        }

        if self.state != TcpState::Closed {
            self.send_conn_end_evt();
        }
    }

}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::packet::PktDataOwned;
    use crate::param::{Param,    ParamValue};
    use tracing_test::traced_test;

    fn dummy_infos() -> PktInfoStack {
        let mut infos = PktInfoStack::new(Protocols::Tcp);
        let info = infos.proto_last_mut();
        info.field_push(Param { name: "sport", value: Some(ParamValue::U16(1234)) });
        info.field_push(Param { name: "dport", value: Some(ParamValue::U16(80)) });
        infos.proto_push(Protocols::Test, None);
        infos

    }

    fn queue_pkt(ct: &mut ConntrackTcp, dir: ConntrackDirection, seq: u32, ack: u32, flags: u8, data: &[u8]) {

        let pkt_data = PktDataOwned::new(&data);
        let mut pkt = Packet::new(PktTime::from_nanos(0), pkt_data);
        ct.process_packet(dir, seq, ack, flags, &mut pkt, 0);

    }

    #[test]
    fn conntrack_tcp_basic() {

        let mut ct = ConntrackTcp::new(Protocols::Test, &dummy_infos());
        ct.stream.as_mut().unwrap().add_expectation(&[ 0 ], PktTime::from_nanos(0));

        // Normal 3 way handshake
        queue_pkt(&mut ct, ConntrackDirection::Forward, 0, 0, TCP_TH_SYN, &[]);
        queue_pkt(&mut ct, ConntrackDirection::Reverse, 0, 1, TCP_TH_SYN | TCP_TH_ACK, &[]);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 1, 1, TCP_TH_ACK, &[]);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 1, 1, 0, &[ 0 ]);

    }

    #[test]
    fn conntrack_tcp_missed_syn() {

        let mut ct = ConntrackTcp::new(Protocols::Test, &dummy_infos());
        ct.stream.as_mut().unwrap().add_expectation(&[ 0 ], PktTime::from_nanos(0));
        queue_pkt(&mut ct, ConntrackDirection::Reverse, 0, 1, TCP_TH_SYN | TCP_TH_ACK, &[]);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 1, 1, 0, &[ 0 ]);
        ct.force_dequeue(); // Force dequeuing

    }

    #[test]
    fn conntrack_tcp_out_of_order_one_direction() {

        let mut ct = ConntrackTcp::new(Protocols::Test, &dummy_infos());
        ct.stream.as_mut().unwrap().add_expectation(&[ 0 ], PktTime::from_nanos(0));
        ct.stream.as_mut().unwrap().add_expectation(&[ 1 ], PktTime::from_nanos(0));
        queue_pkt(&mut ct, ConntrackDirection::Forward, 0, 0, TCP_TH_SYN, &[]);
        queue_pkt(&mut ct, ConntrackDirection::Reverse, 0, 1, TCP_TH_SYN | TCP_TH_ACK, &[]);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 1, 1, TCP_TH_ACK, &[]);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 2, 1, 0, &[ 1 ]);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 1, 1, 0, &[ 0 ]);

    }

    #[test]
    #[traced_test]
    fn conntrack_tcp_complex() {

        let mut ct = ConntrackTcp::new(Protocols::Test, &dummy_infos());
        ct.stream.as_mut().unwrap().add_expectation(&[ 1 ], PktTime::from_nanos(0));
        ct.stream.as_mut().unwrap().add_expectation(&[ 2 ], PktTime::from_nanos(0));
        ct.stream.as_mut().unwrap().add_expectation(&[ 3 ], PktTime::from_nanos(0));
        ct.stream.as_mut().unwrap().add_expectation(&[ 4, 5 ], PktTime::from_nanos(0)); // Bigger dupe has precedence
        ct.stream.as_mut().unwrap().add_expectation(&[ 6 ], PktTime::from_nanos(0));

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

    }

    #[test]
    #[traced_test]
    fn conntrack_tcp_reverse_missing() {

        let mut ct = ConntrackTcp::new(Protocols::Test, &dummy_infos());
        ct.stream.as_mut().unwrap().add_expectation(&[ 1 ], PktTime::from_nanos(0));
        ct.stream.as_mut().unwrap().add_expectation(&[ 11 ], PktTime::from_nanos(0));
        ct.stream.as_mut().unwrap().add_expectation(&[ 2 ], PktTime::from_nanos(0));
        ct.stream.as_mut().unwrap().add_expectation(&[ 3 ], PktTime::from_nanos(0));
        ct.stream.as_mut().unwrap().add_expectation(&[ 4 ], PktTime::from_nanos(0));
        ct.stream.as_mut().unwrap().add_expectation(&[ 5 ], PktTime::from_nanos(0));
        ct.stream.as_mut().unwrap().add_expectation(&[ 12 ], PktTime::from_nanos(0));
        ct.stream.as_mut().unwrap().add_expectation(&[ 6 ], PktTime::from_nanos(0));
        ct.stream.as_mut().unwrap().add_expectation(&[ 7 ], PktTime::from_nanos(0));

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

    }

    #[test]
    #[traced_test]
    fn conntrack_tcp_gap() {

        let mut ct = ConntrackTcp::new(Protocols::Test, &dummy_infos());
        ct.stream.as_mut().unwrap().add_expectation(&[ 1 ], PktTime::from_nanos(0));
        ct.stream.as_mut().unwrap().add_expectation(&[ 0 ], PktTime::from_nanos(0)); // Gap filled for missing packet
        ct.stream.as_mut().unwrap().add_expectation(&[ 3 ], PktTime::from_nanos(0));

        // Normal 3 way handshake
        queue_pkt(&mut ct, ConntrackDirection::Forward, 0, 0, TCP_TH_SYN, &[]);
        queue_pkt(&mut ct, ConntrackDirection::Reverse, 0, 1, TCP_TH_SYN | TCP_TH_ACK, &[]);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 1, 1, TCP_TH_ACK, &[]);

        queue_pkt(&mut ct, ConntrackDirection::Forward, 1, 1, 0, &[ 1 ]); // First data packet
        queue_pkt(&mut ct, ConntrackDirection::Forward, 3, 1, 0, &[ 3 ]); // Data packet with a missing byte

        // Fill the gap
        ct.force_dequeue();
    }

    #[test]
    #[traced_test]
    fn conntrack_tcp_state() {

        let mut ct = ConntrackTcp::new(Protocols::Test, &dummy_infos());
        ct.stream.as_mut().unwrap().add_expectation(&[ 1 ], PktTime::from_nanos(0));
        ct.stream.as_mut().unwrap().add_expectation(&[ 2 ], PktTime::from_nanos(0));
        ct.stream.as_mut().unwrap().add_expectation(&[ 11 ], PktTime::from_nanos(0));

        assert_eq!(ct.state, TcpState::New);
        // Normal 3 way handshake
        queue_pkt(&mut ct, ConntrackDirection::Forward, 0, 10, TCP_TH_SYN, &[]);
        assert_eq!(ct.state, TcpState::SynSent);
        queue_pkt(&mut ct, ConntrackDirection::Reverse, 10, 1, TCP_TH_SYN | TCP_TH_ACK, &[]);
        assert_eq!(ct.state, TcpState::SynRecv);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 1, 11, TCP_TH_ACK, &[]);
        assert_eq!(ct.state, TcpState::Established);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 1, 11, 0, &[ 1 ]);
        assert_eq!(ct.state, TcpState::Established);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 2, 11, 0, &[ 2 ]);
        assert_eq!(ct.state, TcpState::Established);
        queue_pkt(&mut ct, ConntrackDirection::Reverse, 11, 2, 0, &[ 11 ]);
        assert_eq!(ct.state, TcpState::Established);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 3, 12, TCP_TH_FIN, &[ ]);
        assert_eq!(ct.state, TcpState::HalfClosedFwd);
        queue_pkt(&mut ct, ConntrackDirection::Reverse, 12, 4, TCP_TH_FIN, &[ ]);
        assert_eq!(ct.state, TcpState::Closed);
    }

    #[test]
    fn conntrack_tcp_syn_then_fin() {

        let mut ct = ConntrackTcp::new(Protocols::Test, &dummy_infos());
        queue_pkt(&mut ct, ConntrackDirection::Forward, 0, 10, TCP_TH_SYN, &[]);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 0, 10, TCP_TH_FIN, &[]);

    }

    #[test]
    fn conntrack_tcp_single_data_packet() {


        let mut ct = ConntrackTcp::new(Protocols::Test, &dummy_infos());
        ct.stream.as_mut().unwrap().add_expectation(&[ 1 ], PktTime::from_nanos(0));

        queue_pkt(&mut ct, ConntrackDirection::Forward, 1, 11, 0, &[ 1 ]);
        ct.force_dequeue();
    }

    #[test]
    #[traced_test]
    fn conntrack_tcp_uni_dir_fwd() {

        let mut ct = ConntrackTcp::new(Protocols::Test, &dummy_infos());
        ct.stream.as_mut().unwrap().add_expectation(&[ 1 ], PktTime::from_nanos(0));
        ct.stream.as_mut().unwrap().add_expectation(&[ 2 ], PktTime::from_nanos(0));

        assert_eq!(ct.state, TcpState::New);
        // Normal 3 way handshake
        queue_pkt(&mut ct, ConntrackDirection::Forward, 0, 10, TCP_TH_SYN, &[]);
        assert_eq!(ct.state, TcpState::SynSent);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 1, 11, TCP_TH_ACK, &[]);
        assert_eq!(ct.state, TcpState::Established);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 1, 11, 0, &[ 1 ]);
        ct.force_dequeue(); // Force dequeuing the first packet early
        assert_eq!(ct.state, TcpState::Established);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 2, 11, 0, &[ 2 ]);
        assert_eq!(ct.state, TcpState::Established);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 3, 12, TCP_TH_FIN, &[ ]);
        assert_eq!(ct.state, TcpState::Closed);
    }


    #[test]
    #[traced_test]
    fn conntrack_tcp_uni_dir_rev() {

        let mut ct = ConntrackTcp::new(Protocols::Test, &dummy_infos());
        ct.stream.as_mut().unwrap().add_expectation(&[ 11 ], PktTime::from_nanos(0));

        assert_eq!(ct.state, TcpState::New);
        // Normal 3 way handshake
        queue_pkt(&mut ct, ConntrackDirection::Reverse, 10, 1, TCP_TH_SYN | TCP_TH_ACK, &[]);
        assert_eq!(ct.state, TcpState::SynRecv);
        queue_pkt(&mut ct, ConntrackDirection::Reverse, 11, 2, 0, &[ 11 ]);
        ct.force_dequeue(); // Force dequeuing the first packet early
        assert_eq!(ct.state, TcpState::Established);
        queue_pkt(&mut ct, ConntrackDirection::Reverse, 12, 4, TCP_TH_FIN, &[ ]);
        assert_eq!(ct.state, TcpState::Closed);
    }

    #[test]
    fn conntrack_tcp_rst() {

        let mut ct = ConntrackTcp::new(Protocols::Test, &dummy_infos());
        queue_pkt(&mut ct, ConntrackDirection::Forward, 0, 10, TCP_TH_RST, &[]);
    }

    #[test]
    #[traced_test]
    fn conntrack_tcp_syn_fin_payload() {

        let mut ct = ConntrackTcp::new(Protocols::Test, &dummy_infos());
        ct.stream.as_mut().unwrap().add_expectation(&[ 0 ], PktTime::from_nanos(0));
        ct.stream.as_mut().unwrap().add_expectation(&[ 10 ], PktTime::from_nanos(0));
        ct.stream.as_mut().unwrap().add_expectation(&[ 1 ], PktTime::from_nanos(0));
        ct.stream.as_mut().unwrap().add_expectation(&[ 11 ], PktTime::from_nanos(0));
        ct.stream.as_mut().unwrap().add_expectation(&[ 2 ], PktTime::from_nanos(0));
        ct.stream.as_mut().unwrap().add_expectation(&[ 12 ], PktTime::from_nanos(0));

        assert_eq!(ct.state, TcpState::New);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 0, 0, TCP_TH_SYN, &[ 0 ]);
        queue_pkt(&mut ct, ConntrackDirection::Reverse, 10, 2, TCP_TH_SYN | TCP_TH_ACK, &[ 10 ]);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 2, 12, 0, &[ 1 ]);
        queue_pkt(&mut ct, ConntrackDirection::Reverse, 12, 2, 0, &[ 11 ]);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 3, 12, TCP_TH_FIN, &[ 2 ]);
        queue_pkt(&mut ct, ConntrackDirection::Reverse, 13, 4, TCP_TH_FIN, &[ 12 ]);
    }
}

