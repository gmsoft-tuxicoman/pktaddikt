use crate::packet::{PktData, PktDataOwned};
use crate::proto::Protocols;
use crate::param::Param;
use crate::conntrack::ConntrackDirection;

use std::sync::{LazyLock, RwLock};
use slab::Slab;
use std::ops::Range;
use crossbeam_channel::unbounded;
use tracing::trace;


static STREAM_CHANNELS: LazyLock<PktStreamChannels<PktStreamMsg>> = LazyLock::new(|| PktStreamChannels::new());

// FIXME, if nothing is stored in PktStream, maybe an atomic increasing ID would be enough
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

struct PktStreamMsgOpen<'a> {
    stream_id: usize,
    proto: Protocols,
    parent_proto: Protocols,
    metadata: Vec<Param<'a>>
}

struct PktStreamMsgData {
    stream_id: usize,
    dir: ConntrackDirection,
    data: PktDataOwned,
    data_range: Range<usize>,
}
    
struct PktStreamMsgClose {
    stream_id: usize,
}

enum PktStreamMsg<'a> {
    Open(PktStreamMsgOpen<'a>),
    Data(PktStreamMsgData),
    Close(PktStreamMsgClose),
}

pub struct PktStream {}

impl PktStream {


    pub fn init() {   

        std::thread::spawn(|| PktStream::recv_thread(STREAM_CHANNELS.rx.clone()));
        
    }

    pub fn open(proto: Protocols, parent_proto: Protocols) -> usize {
        // Open is synchronous for now
        let stream_id = STREAMS.write().unwrap().insert(PktStream{});
        let msg = PktStreamMsgOpen {
            stream_id: stream_id,
            proto: proto,
            parent_proto: parent_proto,
            metadata: Vec::new(),
        };
        PktStream::recv(PktStreamMsg::Open(msg));
        stream_id
    }

    #[cfg(not(test))]
    pub fn send_data_async(stream_id: usize, dir: ConntrackDirection, data: PktDataOwned, data_range: Range<usize>) {
        // Send data async
        let msg = PktStreamMsgData {
            stream_id: stream_id,
            dir: dir,
            data: data,
            data_range: data_range,
        };
        STREAM_CHANNELS.tx.send(PktStreamMsg::Data(msg)).unwrap();

    }

    #[cfg(test)]
    // Send data synchronously when testing
    pub fn send_data_async(stream_id: usize, dir: ConntrackDirection, data: PktDataOwned, data_range: Range<usize>) {
        PktStream::send_data(stream_id, dir, data, data_range)
    }

    pub fn send_data(stream_id: usize, dir: ConntrackDirection, data: PktDataOwned, data_range: Range<usize>){
        // Send data synchronously
        let msg = PktStreamMsgData {
            stream_id: stream_id,
            dir: dir,
            data: data,
            data_range: data_range,
        };
        PktStream::recv(PktStreamMsg::Data(msg));

    }

    pub fn close(stream_id: usize) {
        // Close is synchronous for now
        let msg = PktStreamMsgClose {
            stream_id: stream_id,
        };
        PktStream::recv(PktStreamMsg::Close(msg));
        let stream_id = STREAMS.write().unwrap().remove(stream_id);
    }

    fn recv(msg: PktStreamMsg) {
        match msg {
            PktStreamMsg::Open(open_msg) => {
                trace!("New stream with id {} proto {:?} and parent_proto {:?}", open_msg.stream_id, open_msg.proto, open_msg.parent_proto);
            }
            PktStreamMsg::Data(data_msg) => {
                trace!("New data for stream {} : {} bytes, {:?}", data_msg.stream_id, data_msg.data_range.len(), data_msg.dir);
            }
            PktStreamMsg::Close(close_msg) => {
                trace!("Stream {} closed", close_msg.stream_id);
            }
        }
    }

    fn recv_thread(rx: crossbeam_channel::Receiver<PktStreamMsg>) {

        while let Ok(msg) = rx.recv() {
            PktStream::recv(msg);
        }

    }

}
