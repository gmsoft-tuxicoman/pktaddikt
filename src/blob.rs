use crate::base::{UniqueId, Parser};
use crate::packet::{PktTime, Packet};
use crate::messagebus::MessageBus;
use crate::event::EventRef;
use crate::decoder::{DecoderKind, Decoder};
use crate::decoder::gzip::DecoderGzip;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::trace;

static BLOB_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone)]
pub struct BlobMsgBegin {
    pub blob_id: UniqueId,
    pub timestamp: PktTime,
    pub id: u64,
    pub tot_size: Option<u64>,
    pub event: Option<EventRef>,
}

pub struct BlobMsgData {
    pub id: u64,
    pub offset: u64,
    pub data: Packet<'static>
}

#[derive(Clone)]
pub struct BlobMsgEnd {
    pub id: u64,
}

#[derive(Clone)]
pub enum BlobMsg {
    Begin(BlobMsgBegin),
    Data(Arc<BlobMsgData>),
    End(BlobMsgEnd),
}

pub struct BlobMetadata {}

#[derive(Debug)]
pub struct Blob {
    blob_id: UniqueId,
    id: Option<u64>,
    tot_size: Option<u64>,
    event: Option<EventRef>,
    decoder: Option<Decoder>,
}

impl Blob {

    pub fn new(ts: PktTime, event: Option<EventRef>) -> Self { // FIXME, remove option
        Self {
            blob_id: UniqueId::new(ts),
            id: None,
            tot_size: None,
            event,
            decoder: None,
        }
    }

    pub fn set_decoder(mut self, decoder_opt: &Option<DecoderKind>) -> Self {
        let Some(decoder_kind) = decoder_opt else { return self; };

        self.decoder = Some(match decoder_kind {
            DecoderKind::Gzip => Decoder::Gzip(DecoderGzip::new_gzip()),
            DecoderKind::Deflate => Decoder::Gzip(DecoderGzip::new_deflate()),
        });
        self
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
                timestamp: pkt.timestamp(),
                event: self.event.take(), // No need to keep a reference
            });
            trace!("New blob with id {:?}", self.blob_id);
            MessageBus::publish_blobmsg(msg);
        }

        if let Some(decoder) = &mut self.decoder {
            match decoder {
                Decoder::Gzip(d) => d.process_blob(self.id.unwrap(), offset, pkt),
            };
            // The decoder will send the BlobMsg::Data with the decoded data
            return;
        }

        let msg = BlobMsg::Data( Arc::new(BlobMsgData {
            id: self.id.unwrap(),
            offset,
            data: pkt.to_owned(),
        }));

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
