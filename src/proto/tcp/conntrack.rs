use crate::base::Parser;
use crate::conntrack::ConntrackDirection;
use crate::proto::tcp::{TCP_TH_SYN, TCP_TH_ACK, TCP_TH_FIN, TCP_TH_RST};
use crate::proto::tcp::seq::TcpSeq;
use crate::packet::{Packet, PktTime, PktInfoStack};
use crate::stream::PktStream;
use crate::proto::{Protocols, ProtoInfo};
use crate::event::{Event, EventPayload};
use crate::base::UniqueId;
use crate::messagebus::MessageBus;

use std::collections::BTreeMap;
use tracing::{debug, trace};
use serde::Serialize;
use std::net::IpAddr;

const CONNTRACK_TCP_MAX_BUFFER :u32 = 1024 * 1024;

#[derive(Debug, Serialize)]
pub struct NetTcpConnectionStart {
    pub conn_id: UniqueId,
    pub client_addr: IpAddr,
    pub server_addr: IpAddr,
    pub client_port: u16,
    pub server_port: u16,
}

#[derive(Debug, Serialize)]
pub struct NetTcpConnectionEnd {
    pub conn_id: UniqueId,
    pub duration: PktTime,
    pub client_addr: IpAddr,
    pub server_addr: IpAddr,
    pub client_port: u16,
    pub server_port: u16,
    pub fwd_bytes: u64,
    pub rev_bytes: u64,
    pub fwd_ip_bytes: u64,
    pub rev_ip_bytes: u64,
    pub fwd_pkts: u64,
    pub rev_pkts: u64,
    pub fwd_missed_bytes: u64,
    pub rev_missed_bytes: u64,
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
    buff_size: u32,
    tot_bytes: u64,
    tot_ip_bytes: u64,
    tot_pkts: u64,
    missed_bytes: u64,
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
    conn_id: UniqueId,
    flow_state: ConntrackTcpFlowState,
    client_port: u16,
    server_port: u16,
    client_addr: IpAddr,
    server_addr: IpAddr,
    pub next_proto: Protocols,
}

impl ConntrackTcp {

    pub fn new(proto: Protocols, infos: &PktInfoStack) -> Self {

        let ip_info = infos.proto_from_last(1).map(|p| p.proto_info.as_ref().unwrap());

        let (client_addr, server_addr) = match ip_info {
            Some(ProtoInfo::Ipv4(v4)) => (IpAddr::V4(v4.src), IpAddr::V4(v4.dst)),
            Some(ProtoInfo::Ipv6(v6)) => (IpAddr::V6(v6.src), IpAddr::V6(v6.dst)),
            _ => unreachable!("TCP conntrack requires an IP layer"),
        };

        let Some(ProtoInfo::Tcp(tcp_info)) = infos.proto_from_last(0).map(|p| p.proto_info.as_ref().unwrap()) else {
            unreachable!();
        };

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
            last_ts: PktTime::from_micros(0),
            conn_id: infos.get_conn_id().unwrap().clone(),
            flow_state: ConntrackTcpFlowState::Probing,
            client_port: tcp_info.sport,
            server_port: tcp_info.dport,
            client_addr,
            server_addr,
            next_proto: proto,
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

        if ! is_missed {
            queue.tot_bytes += data.remaining_len() as u64;
        }
        *queue.cur_seq.as_mut().unwrap() += seq_advance;

        if data.remaining_len() == 0 {
            // Discard empty FIN or RST packet
            return;
        }
        trace!("Sending packet with ts {}", data.timestamp());
        if self.stream.is_some() {
            self.stream.as_mut().unwrap().process_packet(dir, data);
        }
    }

    fn queue_packet(&mut self, dir: ConntrackDirection, seq: TcpSeq, ack: TcpSeq, flags: u8, data: &mut Packet) {

        let new_size = data.remaining_len();
        let new_data = match self.stream {
            Some(ref s) =>  match s.is_active() {
                true => data.to_owned(),
                false => data.to_empty(),
            },
            None => data.to_empty(),
        };
        let queue = self.get_dir_mut(dir);
        let old_pkt_opt = queue.pkts.insert(seq, TcpPacket {
            seq: seq,
            ack: ack,
            flags: flags,
            data: new_data,
        });

        if let Some(old_pkt) = old_pkt_opt {
            let old_size = old_pkt.data.remaining_len();
            if old_size > new_size {
                // Another packet with the same sequence but bigger was already present
                // Put it back in the queue
                queue.pkts.insert(seq, old_pkt);
            } else {
                // We dequeued a packet but added a new one, adjust the size
                queue.buff_size += new_size - old_size;
            }
        } else {
            queue.buff_size += new_size;
        }

        if queue.buff_size > CONNTRACK_TCP_MAX_BUFFER {
            self.force_dequeue();
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
            conn_id: self.conn_id.clone(),
            duration: self.last_ts - self.start_ts.unwrap(),
            client_addr: self.client_addr,
            server_addr: self.server_addr,
            client_port: self.client_port,
            server_port: self.server_port,
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
        MessageBus::publish_event(evt);
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
            queue.tot_ip_bytes += ip_len as u64;
        }

        // Send the start event
        if self.start_ts.is_none() {
            self.start_ts = Some(data.timestamp());
            let evt_pload = NetTcpConnectionStart {
                conn_id: self.conn_id.clone(),
                client_addr: self.client_addr,
                server_addr: self.server_addr,
                client_port: self.client_port,
                server_port: self.server_port,
            };

            let evt = Event::new(data.timestamp(), EventPayload::NetTcpConnectionStart(evt_pload));
            MessageBus::publish_event(evt);
        }

        if self.last_ts < data.timestamp() {
            self.last_ts = data.timestamp();
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

        if (flags & (TCP_TH_FIN | TCP_TH_RST)) != 0 {
            // FIN consumes a sequence number; RST does not, but both must survive the
            // duplicate check below so the control packet is queued and processed in
            // order rather than discarded (send_packet only advances cur_seq for FIN).
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
            let dupe: u32 = (cur_seq - seq).into();

            // Skip the part we know about
            data.skip(dupe).unwrap();
            seq += dupe;
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
        self.process_more_packets(false);
    }

    pub fn get_conn_id(&self) -> &UniqueId {
        &self.conn_id
    }

    fn process_more_packets(&mut self, relax_ack: bool) {


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

                let mut end_seq = pkt.seq + (pkt.data.remaining_len() as u32);
                if (pkt.flags & (TCP_TH_FIN | TCP_TH_RST)) != 0 {
                    // A control flag must survive the duplicate check: an empty FIN/RST
                    // sitting exactly at cur_seq would otherwise look like a duplicate
                    // and get dropped, so the close would never be processed. The FIN
                    // also genuinely consumes the sequence number (advanced in
                    // send_packet); the RST does not.
                    end_seq += 1;
                }
                if end_seq <= cur_seq {
                    // Duplicate
                    //trace!("TCP connection {:p}: gap: cur_seq {:?}, pkt_seq {:?}", &self, cur_seq, pkt.seq);
                    queue.buff_size -= entry.remove().data.remaining_len();
                    continue;
                }

                if pkt.seq < cur_seq {
                    // Trim data
                    let dupe: u32 = (cur_seq - pkt.seq).into();
                    pkt.data.skip(dupe).unwrap();
                    pkt.seq += dupe;
                    // The trimmed bytes were counted when the packet was queued; drop
                    // them now so buff_size doesn't leak upward on each overlap.
                    queue.buff_size -= dupe;
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

                if self.flow_state != ConntrackTcpFlowState::Unidirectional && !relax_ack {
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
                trace!("Sending additional packet with ts {}, seq {:?} and ack {:?}", pkt.data.timestamp(), pkt.seq, pkt.ack);
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
        let mut gap_fwd: u32 = 0;
        let mut gap_rev: u32 = 0;
        let mut ts_fwd: Option<PktTime> = None;
        let mut ts_rev: Option<PktTime> = None;

        let mut dir = ConntrackDirection::Forward;

        // Check if we have a gap in the forward direction
        if let Some(entry) = self.forward.pkts.first_entry() {
            let pkt = entry.get();
            ts_fwd = Some(pkt.data.timestamp());
            if let Some(cur_seq) = self.forward.cur_seq {
                // Only a packet *ahead* of cur_seq is a gap. A dupe (seq < cur_seq)
                // would wrap the subtraction into a ~4GB "gap"; leave it at 0 and let
                // process_more_packets discard it.
                if cur_seq < pkt.seq {
                    gap_fwd = (pkt.seq - cur_seq).into();
                }
            } else {
                // We didn't capture the start of the connections, let's start it now
                self.forward.start_seq = Some(pkt.seq);
                self.forward.cur_seq = Some(pkt.seq);
            }
        }

        // Check if we have a gap in the reverse direction
        if let Some(entry) = self.reverse.pkts.first_entry() {
            let pkt = entry.get();
            ts_rev = Some(pkt.data.timestamp());
            if let Some(cur_seq) = self.reverse.cur_seq {
                if cur_seq < pkt.seq {
                    gap_rev = (pkt.seq - cur_seq).into();
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

            self.get_dir_mut(dir).missed_bytes += gap as u64;

            trace!("Filling gap of {} bytes", gap);

            while gap > 0 {
                let filler_len = match gap > Packet::PKT_ZERO_MAX_LEN as u32 {
                    true => Packet::PKT_ZERO_MAX_LEN as u32,
                    false => gap,

                };

                self.send_packet(dir, 0, &mut Packet::from_zero(ts, filler_len), true);

                gap -= filler_len;
            }
        }

        // If there was no sequence gap to fill yet packets remain queued, they are
        // stuck on the ack ordering constraint: a head packet is ready by sequence
        // but acks opposite-direction data we never captured (and never will, since
        // force_dequeue is the safety valve at the buffer cap / connection teardown).
        // Relax the ack constraint so the queue actually drains -- otherwise the
        // buffer cap is defeated mid-connection and Drop's drain loop spins forever.
        let relax_ack = gap_fwd == 0 && gap_rev == 0;
        self.process_more_packets(relax_ack);
    }

}

impl Drop for ConntrackTcp {

    fn drop(&mut self) {

        // Make sure all the packets get processed
        while self.forward.pkts.len() > 0 || self.reverse.pkts.len() > 0 {
            self.force_dequeue();
        }

        // start_ts is only set once a packet has been processed (which also emits the
        // start event). Without it there is no connection to end, and send_conn_end_evt
        // would panic unwrapping start_ts.
        if self.state != TcpState::Closed && self.start_ts.is_some() {
            self.send_conn_end_evt();
        }
    }

}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::proto::tcp::ProtoTcpInfo;
    use crate::proto::ipv4::ProtoIpv4Info;
    use tracing_test::traced_test;
    use std::net::Ipv4Addr;

    fn dummy_infos() -> PktInfoStack {
        let mut infos = PktInfoStack::new(Protocols::Ipv4);
        infos.set_conn_id(UniqueId::new(PktTime::from_micros(0)));

        let mut info = infos.proto_last_mut();

        info.proto_info = Some(ProtoInfo::Ipv4(ProtoIpv4Info {
            src: Ipv4Addr::new(10, 0, 0, 1),
            dst: Ipv4Addr::new(10, 0, 0, 2),
            id: 0,
            hdr_len: 0,
            ttl: 0,
            proto: 17,
        }));

        infos.proto_push(Protocols::Tcp, None);

        info = infos.proto_last_mut();

        info.proto_info = Some(ProtoInfo::Tcp(ProtoTcpInfo {
            sport: 1234,
            dport: 80,
            seq: 0,
            ack: 0,
            window: 0,
            flags: 0,
        }));
        //infos.proto_push(Protocols::Test, None);
        infos

    }

    fn queue_pkt(ct: &mut ConntrackTcp, dir: ConntrackDirection, seq: u32, ack: u32, flags: u8, data: &[u8]) {

        let mut pkt = Packet::from_slice(PktTime::from_micros(0), &data);
        ct.process_packet(dir, seq, ack, flags, &mut pkt, 0);

    }

    #[test]
    fn conntrack_tcp_basic() {

        let mut ct = ConntrackTcp::new(Protocols::Test, &dummy_infos());
        ct.stream.as_mut().unwrap().add_expectation(&[ 0 ], PktTime::from_micros(0));

        // Normal 3 way handshake
        queue_pkt(&mut ct, ConntrackDirection::Forward, 0, 0, TCP_TH_SYN, &[]);
        queue_pkt(&mut ct, ConntrackDirection::Reverse, 0, 1, TCP_TH_SYN | TCP_TH_ACK, &[]);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 1, 1, TCP_TH_ACK, &[]);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 1, 1, 0, &[ 0 ]);

    }

    #[test]
    fn conntrack_tcp_missed_syn() {

        let mut ct = ConntrackTcp::new(Protocols::Test, &dummy_infos());
        ct.stream.as_mut().unwrap().add_expectation(&[ 0 ], PktTime::from_micros(0));
        queue_pkt(&mut ct, ConntrackDirection::Reverse, 0, 1, TCP_TH_SYN | TCP_TH_ACK, &[]);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 1, 1, 0, &[ 0 ]);
        ct.force_dequeue(); // Force dequeuing

    }

    #[test]
    fn conntrack_tcp_out_of_order_one_direction() {

        let mut ct = ConntrackTcp::new(Protocols::Test, &dummy_infos());
        ct.stream.as_mut().unwrap().add_expectation(&[ 0 ], PktTime::from_micros(0));
        ct.stream.as_mut().unwrap().add_expectation(&[ 1 ], PktTime::from_micros(0));
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
        ct.stream.as_mut().unwrap().add_expectation(&[ 1 ], PktTime::from_micros(0));
        ct.stream.as_mut().unwrap().add_expectation(&[ 2 ], PktTime::from_micros(0));
        ct.stream.as_mut().unwrap().add_expectation(&[ 3 ], PktTime::from_micros(0));
        ct.stream.as_mut().unwrap().add_expectation(&[ 4, 5 ], PktTime::from_micros(0)); // Bigger dupe has precedence
        ct.stream.as_mut().unwrap().add_expectation(&[ 6 ], PktTime::from_micros(0));

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
        ct.stream.as_mut().unwrap().add_expectation(&[ 1 ], PktTime::from_micros(0));
        ct.stream.as_mut().unwrap().add_expectation(&[ 11 ], PktTime::from_micros(0));
        ct.stream.as_mut().unwrap().add_expectation(&[ 2 ], PktTime::from_micros(0));
        ct.stream.as_mut().unwrap().add_expectation(&[ 3 ], PktTime::from_micros(0));
        ct.stream.as_mut().unwrap().add_expectation(&[ 4 ], PktTime::from_micros(0));
        ct.stream.as_mut().unwrap().add_expectation(&[ 5 ], PktTime::from_micros(0));
        ct.stream.as_mut().unwrap().add_expectation(&[ 12 ], PktTime::from_micros(0));
        ct.stream.as_mut().unwrap().add_expectation(&[ 6 ], PktTime::from_micros(0));
        ct.stream.as_mut().unwrap().add_expectation(&[ 7 ], PktTime::from_micros(0));

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
        ct.stream.as_mut().unwrap().add_expectation(&[ 1 ], PktTime::from_micros(0));
        ct.stream.as_mut().unwrap().add_expectation(&[ 0 ], PktTime::from_micros(0)); // Gap filled for missing packet
        ct.stream.as_mut().unwrap().add_expectation(&[ 3 ], PktTime::from_micros(0));

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
        ct.stream.as_mut().unwrap().add_expectation(&[ 1 ], PktTime::from_micros(0));
        ct.stream.as_mut().unwrap().add_expectation(&[ 2 ], PktTime::from_micros(0));
        ct.stream.as_mut().unwrap().add_expectation(&[ 11 ], PktTime::from_micros(0));

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
        ct.stream.as_mut().unwrap().add_expectation(&[ 1 ], PktTime::from_micros(0));

        queue_pkt(&mut ct, ConntrackDirection::Forward, 1, 11, 0, &[ 1 ]);
        ct.force_dequeue();
    }

    #[test]
    #[traced_test]
    fn conntrack_tcp_uni_dir_fwd() {

        let mut ct = ConntrackTcp::new(Protocols::Test, &dummy_infos());
        ct.stream.as_mut().unwrap().add_expectation(&[ 1 ], PktTime::from_micros(0));
        ct.stream.as_mut().unwrap().add_expectation(&[ 2 ], PktTime::from_micros(0));

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
        ct.stream.as_mut().unwrap().add_expectation(&[ 11 ], PktTime::from_micros(0));

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
        ct.stream.as_mut().unwrap().add_expectation(&[ 0 ], PktTime::from_micros(0));
        ct.stream.as_mut().unwrap().add_expectation(&[ 10 ], PktTime::from_micros(0));
        ct.stream.as_mut().unwrap().add_expectation(&[ 1 ], PktTime::from_micros(0));
        ct.stream.as_mut().unwrap().add_expectation(&[ 11 ], PktTime::from_micros(0));
        ct.stream.as_mut().unwrap().add_expectation(&[ 2 ], PktTime::from_micros(0));
        ct.stream.as_mut().unwrap().add_expectation(&[ 12 ], PktTime::from_micros(0));

        assert_eq!(ct.state, TcpState::New);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 0, 0, TCP_TH_SYN, &[ 0 ]);
        queue_pkt(&mut ct, ConntrackDirection::Reverse, 10, 2, TCP_TH_SYN | TCP_TH_ACK, &[ 10 ]);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 2, 12, 0, &[ 1 ]);
        queue_pkt(&mut ct, ConntrackDirection::Reverse, 12, 2, 0, &[ 11 ]);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 3, 12, TCP_TH_FIN, &[ 2 ]);
        queue_pkt(&mut ct, ConntrackDirection::Reverse, 13, 4, TCP_TH_FIN, &[ 12 ]);
    }

    // A queued, out-of-order packet that partially overlaps data delivered in the
    // meantime gets trimmed inside process_more_packets. buff_size must account for the
    // trimmed bytes; otherwise it leaks upward on every overlapping retransmission and
    // eventually defeats the buffer cap.
    #[test]
    #[traced_test]
    fn conntrack_tcp_trim_buff_size() {

        let mut ct = ConntrackTcp::new(Protocols::Test, &dummy_infos());
        ct.stream.as_mut().unwrap().add_expectation(&[ 1, 2, 3 ], PktTime::from_micros(0));
        ct.stream.as_mut().unwrap().add_expectation(&[ 4 ], PktTime::from_micros(0));

        // Bidirectional handshake
        queue_pkt(&mut ct, ConntrackDirection::Forward, 0, 10, TCP_TH_SYN, &[]);
        queue_pkt(&mut ct, ConntrackDirection::Reverse, 10, 1, TCP_TH_SYN | TCP_TH_ACK, &[]);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 1, 11, TCP_TH_ACK, &[]);

        // Out-of-order segment covering seq 3..5 is queued (gap at seq 1..3).
        queue_pkt(&mut ct, ConntrackDirection::Forward, 3, 11, 0, &[ 3, 4 ]);
        assert_eq!(ct.forward.buff_size, 2);

        // Segment covering seq 1..4 fills the gap and overlaps the queued one by 1 byte,
        // so the queued segment is trimmed (seq 3 -> 4) before being delivered.
        queue_pkt(&mut ct, ConntrackDirection::Forward, 1, 11, 0, &[ 1, 2, 3 ]);

        // Everything was delivered; the buffer accounting must be back to zero.
        assert_eq!(ct.forward.pkts.len(), 0);
        assert_eq!(ct.forward.buff_size, 0);
    }

    // An empty FIN that arrives out of order (before the data segment that precedes
    // it) gets queued, then must still be processed once the gap is filled. The state
    // must transition to HalfClosedFwd. Regression: process_more_packets used to omit
    // the FIN's sequence number from end_seq and drop the queued FIN as a "duplicate".
    #[test]
    #[traced_test]
    fn conntrack_tcp_fin_out_of_order() {

        let mut ct = ConntrackTcp::new(Protocols::Test, &dummy_infos());
        ct.stream.as_mut().unwrap().add_expectation(&[ 1 ], PktTime::from_micros(0));
        ct.stream.as_mut().unwrap().add_expectation(&[ 2 ], PktTime::from_micros(0));

        // Bidirectional handshake
        queue_pkt(&mut ct, ConntrackDirection::Forward, 0, 10, TCP_TH_SYN, &[]);
        queue_pkt(&mut ct, ConntrackDirection::Reverse, 10, 1, TCP_TH_SYN | TCP_TH_ACK, &[]);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 1, 11, TCP_TH_ACK, &[]);
        assert_eq!(ct.state, TcpState::Established);

        queue_pkt(&mut ct, ConntrackDirection::Forward, 1, 11, 0, &[ 1 ]); // first data byte
        queue_pkt(&mut ct, ConntrackDirection::Forward, 3, 11, TCP_TH_FIN, &[]); // FIN ahead of seq 2
        assert_eq!(ct.state, TcpState::Established); // FIN is queued, not processed yet

        queue_pkt(&mut ct, ConntrackDirection::Forward, 2, 11, 0, &[ 2 ]); // fills the gap
        // The queued FIN must now be processed and close the forward direction.
        assert_eq!(ct.state, TcpState::HalfClosedFwd);
        assert_eq!(ct.forward.pkts.len(), 0);
    }

    // An RST must not cause queued stream data to be discarded. It is queued and
    // processed in sequence order: data ahead of it drains first, then the RST closes
    // the connection. Regression: an empty RST used to be dropped as a "duplicate" and
    // never transitioned the state.
    #[test]
    #[traced_test]
    fn conntrack_tcp_rst_out_of_order() {

        let mut ct = ConntrackTcp::new(Protocols::Test, &dummy_infos());
        ct.stream.as_mut().unwrap().add_expectation(&[ 1 ], PktTime::from_micros(0));
        ct.stream.as_mut().unwrap().add_expectation(&[ 2 ], PktTime::from_micros(0));

        // Bidirectional handshake
        queue_pkt(&mut ct, ConntrackDirection::Forward, 0, 10, TCP_TH_SYN, &[]);
        queue_pkt(&mut ct, ConntrackDirection::Reverse, 10, 1, TCP_TH_SYN | TCP_TH_ACK, &[]);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 1, 11, TCP_TH_ACK, &[]);
        assert_eq!(ct.state, TcpState::Established);

        // Byte at seq 2 arrives before byte at seq 1, so it is queued, and an RST
        // arrives while that data is still pending. The data must not be discarded.
        queue_pkt(&mut ct, ConntrackDirection::Forward, 2, 11, 0, &[ 2 ]);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 3, 11, TCP_TH_RST, &[]);
        assert_eq!(ct.state, TcpState::Established); // RST waits its turn in the queue
        assert_eq!(ct.forward.pkts.len(), 2);

        // The missing byte arrives: queued data drains in order, then the RST closes.
        queue_pkt(&mut ct, ConntrackDirection::Forward, 1, 11, 0, &[ 1 ]);
        assert_eq!(ct.state, TcpState::Closed);
        assert_eq!(ct.forward.pkts.len(), 0); // all queued data processed, nothing discarded
    }

    // A bidirectional connection where a forward packet acks reverse data we never
    // capture. The packet is ready by sequence but held back by the ack ordering
    // rule, and no sequence gap exists to fill. force_dequeue (the buffer-cap /
    // teardown safety valve) must drain it by relaxing the ack constraint, instead
    // of looping forever.
    #[test]
    #[traced_test]
    fn conntrack_tcp_ack_stall_force_dequeue() {

        let mut ct = ConntrackTcp::new(Protocols::Test, &dummy_infos());
        ct.stream.as_mut().unwrap().add_expectation(&[ 1 ], PktTime::from_micros(0));

        // Bidirectional handshake
        queue_pkt(&mut ct, ConntrackDirection::Forward, 0, 10, TCP_TH_SYN, &[]);
        queue_pkt(&mut ct, ConntrackDirection::Reverse, 10, 1, TCP_TH_SYN | TCP_TH_ACK, &[]);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 1, 11, TCP_TH_ACK, &[]);

        // Forward data acking reverse byte 20 - but reverse only ever reached 11.
        // The acked reverse data is never delivered, so this packet wedges.
        queue_pkt(&mut ct, ConntrackDirection::Forward, 1, 20, 0, &[ 1 ]);
        assert_eq!(ct.forward.pkts.len(), 1); // confirmed stuck on the ack constraint
        assert_eq!(ct.forward.buff_size, 1);

        // The safety valve must break the ack stall and drain the queue.
        ct.force_dequeue();
        assert_eq!(ct.forward.pkts.len(), 0);
        assert_eq!(ct.forward.buff_size, 0);
    }

    // Same wedge, but left in place so Drop has to drain it. Before the fix this
    // test would hang: Drop's `while pkts.len() > 0 { force_dequeue() }` never made
    // progress because force_dequeue could not break an ack stall.
    #[test]
    #[traced_test]
    fn conntrack_tcp_ack_stall_drop() {

        let mut ct = ConntrackTcp::new(Protocols::Test, &dummy_infos());
        ct.stream.as_mut().unwrap().add_expectation(&[ 1 ], PktTime::from_micros(0));

        queue_pkt(&mut ct, ConntrackDirection::Forward, 0, 10, TCP_TH_SYN, &[]);
        queue_pkt(&mut ct, ConntrackDirection::Reverse, 10, 1, TCP_TH_SYN | TCP_TH_ACK, &[]);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 1, 11, TCP_TH_ACK, &[]);
        queue_pkt(&mut ct, ConntrackDirection::Forward, 1, 20, 0, &[ 1 ]);
        assert_eq!(ct.forward.pkts.len(), 1);

        // ct is dropped at end of scope: the drain loop must terminate.
    }
}

