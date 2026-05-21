use crate::output::{Output, OutputConfig};
use crate::messagebus::{MessageBus, MessageTxChannel, MessageRxChannel, Message};
use crate::config::Config;
use crate::blob::{BlobMsg, BlobMsgBegin, BlobMsgData, BlobMsgEnd};
use crate::event::EventPayload;
use crate::base::Parser;


use std::collections::HashMap;
use std::path::PathBuf;
use serde::Deserialize;
use std::fs::{File, create_dir_all};
use std::io::{Seek, SeekFrom, Write};
use tracing::{error, trace};



#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct NfsMirrorConfig {
    pub path: String,
    pub keep_deleted: bool
}

impl Default for NfsMirrorConfig {

    fn default() -> Self {
        Self {
            path: "".to_string(),
            keep_deleted: true
        }
    }
}


pub struct OutputNfsMirror {

    blobs: HashMap<u64, File>,
    path: PathBuf,
}


impl OutputNfsMirror {

    pub fn new(name: &str, msg_bus: &mut MessageBus, tx: &MessageTxChannel) -> Box<dyn Output> {
        
        let main_cfg = Config::get();

        let OutputConfig::NfsMirror(cfg) = main_cfg.outputs.get(name).unwrap() else {
            panic!("Config is not nfsmirror");
        };

        msg_bus.blob_subscribe(tx);
        msg_bus.event_subscribe_glob("net.nfs.*", tx).unwrap();

        let path = PathBuf::from(cfg.path.clone());

        Box::new(Self {
            blobs: HashMap::new(),
            path,
        })
    }

    fn process_blob_begin(&mut self, msg: &BlobMsgBegin) {
        let Some(event) = &msg.event else { return };
        let EventPayload::NetNfsCallWrite(pload) = &event.payload else { return };
        trace!("Got new blob for file handle {:?}", pload.filehandle);

        let Some(server) = &pload.base.server else { return };

        let filename = pload.filehandle.iter().map(|b| format!("{:02X}", b)).collect::<String>();
        let path = self.path.clone().join(server.to_string()).join("by-fh").join(filename);

        if let Some(parent) = path.parent() {
            if let Err(e) = create_dir_all(parent) {
                error!("Error while creating the parent directories for {}: {}", path.display(), e);
                return;
            }
        }
        let Ok(file) = File::create(&path) else {
            error!("Unable to open file {} for writing", path.display());
            return;
        };

        self.blobs.insert(msg.id, file);
    }
    fn process_blob_data(&mut self, msg: &BlobMsgData) {

        let Some(mut file) = self.blobs.get(&msg.id) else {
            // Something when wrong when creating the fil
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

    fn process_blob_end(&mut self, msg: &BlobMsgEnd) {
        self.blobs.remove(&msg.id);
    }
}


impl Output for OutputNfsMirror {


    fn run(mut self: Box<Self>, rx: MessageRxChannel) {

        for msg in rx {
            match msg {
                Message::Shutdown => break,
                Message::Event(_) => continue, // Wil implement later
                Message::BlobMsg(BlobMsg::Begin(b)) => self.process_blob_begin(&b),
                Message::BlobMsg(BlobMsg::Data(d)) => self.process_blob_data(&d),
                Message::BlobMsg(BlobMsg::End(e)) => self.process_blob_end(&e),
            }
        }
    }

}
