use crate::packet::Packet;
use crate::proto::Protocols;
use crate::proto::test::ProtoTest;
use crate::param::Param;
use crate::conntrack::ConntrackDirection;

use std::sync::{LazyLock, RwLock};
use slab::Slab;
use crossbeam_channel::unbounded;
use tracing::trace;


static STREAM_CHANNELS: LazyLock<PktStreamChannels<PktStreamMsg>> = LazyLock::new(|| PktStreamChannels::new());

static STREAMS: LazyLock<RwLock<Slab<PktStream>>> = LazyLock::new(|| RwLock::new(Slab::new()));

pub struct PktStreamChannels<T> {
    tx: crossbeam_channel::Sender<T>,
    rx: crossbeam_channel::Receiver<T>
}

impl<T> PktStreamChannels<T> {

    fn new() -> Self {
        let (tx, rx) = unbounded();
        PktStreamChannels {
            rx: rx,
            tx: tx,
        }

    }
}


struct PktStreamMsg {
    stream_id: usize,
    dir: ConntrackDirection,
    pkt: Packet<'static>,
}
    
pub trait ProtoStreamProcessor {
    fn new<'a>(parent_proto: Protocols, metadata: &Vec<Param<'a>>) -> Self;
    fn process(&self,  dir: ConntrackDirection, pkt: Packet);

}

pub enum PktStreamProto {
    Test(ProtoTest)
}

pub struct PktStream {
    processor: PktStreamProto
}

impl PktStream {


    pub fn init() {   

        std::thread::spawn(|| PktStream::recv_thread(STREAM_CHANNELS.rx.clone()));
        
    }

    pub fn open(proto: Protocols, parent_proto: Protocols) -> usize {
        // Open is synchronous for now
        STREAMS.write().unwrap().insert(PktStream{
            processor: match proto {
                #[cfg(test)]
                Protocols::Test => PktStreamProto::Test(ProtoTest::new(parent_proto, &Vec::new())),
                _ => panic!("Stream protocol not implemented")
            }
        })
    }

    #[cfg(not(test))]
    pub fn send_data_async(stream_id: usize, dir: ConntrackDirection, pkt: Packet<'static>) {
        // Send data async
        let msg = PktStreamMsg {
            stream_id: stream_id,
            dir: dir,
            pkt: pkt,
        };
        STREAM_CHANNELS.tx.send(msg).unwrap();

    }

    #[cfg(test)]
    // Send data synchronously when testing
    pub fn send_data_async(stream_id: usize, dir: ConntrackDirection, pkt: Packet<'static>) {
        PktStream::send_data(stream_id, dir, pkt)
    }

    pub fn send_data(stream_id: usize, dir: ConntrackDirection, pkt: Packet<'static>){
        // Send data synchronously
        let msg = PktStreamMsg      {
            stream_id: stream_id,
            dir: dir,
            pkt: pkt,
        };
        PktStream::recv(msg);

    }

    pub fn close(stream_id: usize) {
        // Close is synchronous for now
        STREAMS.write().unwrap().remove(stream_id);
    }

    fn recv(msg: PktStreamMsg) {
        trace!("New data for stream {} : {} bytes, {:?}", msg.stream_id, msg.pkt.remaining_len(), msg.dir);
        let stream = STREAMS.read().unwrap();
        match &stream[msg.stream_id].processor {
            #[cfg(test)]
            PktStreamProto::Test(p) => p.process(msg.dir, msg.pkt),
            _ => panic!("Stream protocol not implemented")
        }
    }

    fn recv_thread(rx: crossbeam_channel::Receiver<PktStreamMsg>) {

        while let Ok(msg) = rx.recv() {
            PktStream::recv(msg);
        }

    }

}
