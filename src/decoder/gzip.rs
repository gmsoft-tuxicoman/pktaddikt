use crate::packet::Packet;
use crate::base::Parser;
use crate::blob::{BlobMsg, BlobMsgData};
use crate::messagebus::MessageBus;

use flate2::{Decompress, FlushDecompress};
use std::sync::Arc;
use tracing::{debug, trace};


#[derive(Debug)]
pub struct DecoderGzip {

    decompress: Decompress,
    in_offset: u64,
    out_offset: u64,
    in_error: bool,
}


impl DecoderGzip {


    pub fn new_gzip() -> Self {
        Self {
            decompress: Decompress::new_gzip(15),
            in_error: false,
            in_offset: 0,
            out_offset: 0,
        }
    }

    pub fn new_deflate() -> Self {
        Self {
            decompress: Decompress::new(true),
            in_error: false,
            in_offset: 0,
            out_offset: 0,
        }
    }

    pub fn process_blob(&mut self, blob_id: u64, offset: u64, data: Packet) {
       
        if self.in_error { return; };

        if self.in_offset != offset {
            debug!("GZIP content not contiguous. Aborting.");
            self.in_error = true;
            return;
        }

        let input = data.peek();
        let input_len = data.remaining_len() as u64;
        self.in_offset += input_len;

        let in_pos = self.decompress.total_in();

        let mut consumed = 0;

        while consumed < input_len {
            let mut output = Vec::with_capacity(4096); // FIXME use real page size instead
            match self.decompress.decompress_vec(&input[consumed as usize ..], &mut output, FlushDecompress::None) {
                Err(e) => {
                    debug!("Error while decompressing payload: {}", e);
                    self.in_error = true;
                    return;
                },
                Ok(status) => {
                    trace!("Decompress status: {:?}", status);
                },
            }

            let output_len = output.len() as u64;
            trace!("Decompressed len: {}", output_len);
            consumed = self.decompress.total_in() as u64 - in_pos;


            let msg = BlobMsg::Data( Arc::new(BlobMsgData {
                id: blob_id,
                offset: self.out_offset,
                data: Packet::from_vec(data.timestamp(), Arc::new(output)),
            }));

            self.out_offset += output_len;

            MessageBus::publish_blobmsg(msg);

        }

    }

}
