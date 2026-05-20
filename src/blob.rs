use crate::base::UniqueId;
use crate::packet::{PktTime, Packet};
use crate::base::Parser;
use crate::messagebus::MessageBus;

use std::sync::atomic::{AtomicU64, Ordering};
use tracing::trace;

static BLOB_ID_COUNTER: AtomicU64 = AtomicU64::new(0);


pub struct BlobMsgBegin {
    pub blob_id: UniqueId,
    pub id: u64,
    pub tot_size: Option<u64>,
}

pub struct BlobMsgData {
    pub id: u64,
    pub offset: u64,
    pub data: Packet<'static>
}

pub struct BlobMsgEnd {
    pub id: u64,
}

pub enum BlobMsg {
    Begin(BlobMsgBegin),
    Data(BlobMsgData),
    End(BlobMsgEnd),
}

#[derive(Debug)]
pub struct Blob {
    blob_id: UniqueId,
    id: Option<u64>,
    tot_size: Option<u64>,
}

impl Blob {

    pub fn new(ts: PktTime) -> Self {
        Self {
            blob_id: UniqueId::new(ts),
            id: None,
            tot_size: None,
        }
    }

    pub fn set_size(mut self, tot_size: u64) -> Self {
        self.tot_size = Some(tot_size);
        self
    }


    pub fn data(&mut self, offset: u64, pkt: Packet) {

        if self.id.is_none() {
            self.id = Some(BLOB_ID_COUNTER.fetch_add(1, Ordering::Relaxed));
            let msg = BlobMsg::Begin( BlobMsgBegin {
                blob_id: self.blob_id.clone(),
                id: self.id.unwrap(),
                tot_size: self.tot_size,
            });
            trace!("New blob with id {:?}", self.blob_id);
            MessageBus::publish_blobmsg(msg);
        }

        let msg = BlobMsg::Data( BlobMsgData {
            id: self.id.unwrap(),
            offset,
            data: pkt.to_owned(),
        });

        MessageBus::publish_blobmsg(msg);

        trace!("Got {} of blob data at offset {}", pkt.remaining_len(), offset);

    }

    fn end(&self) {
        trace!("Blob finished");

    }
}


impl Drop for Blob {

    fn drop(&mut self) {
        self.end()
    }

}
