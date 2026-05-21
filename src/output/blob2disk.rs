use crate::messagebus::{MessageBus, MessageTxChannel, MessageRxChannel, Message};
use crate::config::Config;
use crate::output::{Output, OutputConfig};
use crate::blob::{BlobMsg, BlobMsgBegin, BlobMsgData, BlobMsgEnd};
use crate::base::Parser;


use std::fs::File;
use std::io::{Write, Seek, SeekFrom};
use std::path::PathBuf;
use serde::Deserialize;
use std::collections::HashMap;
use std::hash::{Hasher, BuildHasherDefault};
use tracing::{error, trace};

#[derive(Default)]
struct NoopHasher(u64);

impl Hasher for NoopHasher {
    fn write_u64(&mut self, i: u64) { self.0 = i; }
    fn write(&mut self, _: &[u8]) { panic!("only u64 keys supported"); }
    fn finish(&self) -> u64 { self.0 }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct Blob2DiskConfig {
    pub path: String,
}

impl Default for Blob2DiskConfig {
    
    fn default() -> Self {
        Self {
            path: "".to_string(),
        }
    }
}



pub struct OutputBlob2Disk {
    blobs: HashMap<u64, File, BuildHasherDefault<NoopHasher>>,
    path: PathBuf,
}

impl OutputBlob2Disk {

    pub fn new(name: &str, msg_bus: &mut MessageBus, tx: &MessageTxChannel) -> Box<dyn Output> {
        let main_cfg = Config::get();
        let OutputConfig::Blob2Disk(cfg) = main_cfg.outputs.get(name).unwrap() else {
            panic!("Config is not blob2file");
        };

        msg_bus.blob_subscribe(tx);

        let path = PathBuf::from(cfg.path.clone());

        Box::new(Self {
            blobs: HashMap::default(),
            path: path,
        })
    }

    fn process_begin(&mut self, msg: &BlobMsgBegin) {

        let path = self.path.join(msg.blob_id.as_str());
        let Ok(file) = File::create(&path) else {
            error!("Unable to open file {} for writing", path.display());
            return;
        };

        if let Some(tot_size) = msg.tot_size {
            if file.set_len(tot_size).is_err() {
                error!("Unable to send file length to {} on file {}", tot_size, path.display());
                return;
            }
            trace!("Created file {} for blob {} with len {}", path.display(), msg.id, tot_size);
        } else {
            trace!("Created file {} for blob {}", path.display(), msg.id);
        }
        self.blobs.insert(msg.id, file);

    }

    fn process_data(&mut self, msg: &BlobMsgData) {
        let Some(mut file) = self.blobs.get(&msg.id) else {
            // Something went wrong when creating the file
            return;
        };
        if let Err(e) = file.seek(SeekFrom::Start(msg.offset)) {
            error!("Error while seeking to offset {} in file for blob {}: {}", msg.offset, msg.id, e);
            self.blobs.remove(&msg.id); // Close the file
            return;
        }
        trace!("Writing {} of data at offset {} for blob {}", msg.data.remaining_len(), msg.offset, msg.id);
        if let Err(e) = file.write_all(msg.data.peek()) {
            error!("Error writing to file: {}", e);
            self.blobs.remove(&msg.id); // Close the file
            return;
        }
    }

    fn process_end(&mut self, msg: &BlobMsgEnd) {
        trace!("Blob {} ended", msg.id);
        self.blobs.remove(&msg.id);
    }

    fn process_blobmsg(&mut self, msg: &BlobMsg) {
        match msg {
            BlobMsg::Begin(b) => self.process_begin(b),
            BlobMsg::Data(d) => self.process_data(d),
            BlobMsg::End(e) => self.process_end(e),
        }
    }

}

impl Output for OutputBlob2Disk {

    fn run(mut self: Box<Self>, rx: MessageRxChannel) {

        for msg in rx {

            match msg {
                Message::Shutdown => break,
                Message::BlobMsg(msg) => self.process_blobmsg(&msg),
                _ => panic!("Uknown message type"),
            }
        }

    }

}
