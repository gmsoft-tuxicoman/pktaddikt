use crate::output::{Output, OutputConfig};
use crate::messagebus::{MessageBus, MessageTxChannel, MessageRxChannel, Message};
use crate::config::Config;
use crate::blob::{BlobMsg, BlobMsgBegin, BlobMsgData, BlobMsgEnd};
use crate::event::{EventPayload, EventRef, EventKind};
use crate::base::Parser;


use std::collections::HashMap;
use strict_path::{StrictPath, PathBoundary};
use serde::Deserialize;
use std::fs::{File, OpenOptions, hard_link, rename};
use std::io::{Seek, SeekFrom, Write, ErrorKind};
use std::net::IpAddr;
use tracing::{error, debug, trace};



type NfsFileHandleKey = (IpAddr, Vec<u8>);

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
    pathmap: HashMap<NfsFileHandleKey, StrictPath>,
    path: PathBoundary,
}


impl OutputNfsMirror {

    pub fn new(name: &str, msg_bus: &mut MessageBus, tx: &MessageTxChannel) -> Box<dyn Output> {
        
        let main_cfg = Config::get();

        let OutputConfig::NfsMirror(cfg) = main_cfg.outputs.get(name).unwrap() else {
            panic!("Config is not nfsmirror");
        };

        msg_bus.blob_subscribe(tx);
        msg_bus.event_subscribe_kind(EventKind::NetMountReplyMnt, tx);
        msg_bus.event_subscribe_kind(EventKind::NetNfsV3ReplyLookup, tx);
        msg_bus.event_subscribe_kind(EventKind::NetNfsV3ReplyCreate, tx);
        msg_bus.event_subscribe_kind(EventKind::NetNfsV3ReplyMkdir, tx);
        msg_bus.event_subscribe_kind(EventKind::NetNfsV3ReplyRename, tx);

        let path = PathBoundary::<()>::try_new_create(cfg.path.clone()).unwrap();

        Box::new(Self {
            blobs: HashMap::new(),
            pathmap: HashMap::new(),
            path,
        })
    }

    fn process_blob_begin(&mut self, msg: &BlobMsgBegin) {
        let Some(event) = &msg.event else { return };

        let (server, filehandle) = match &event.payload {
            EventPayload::NetNfsV3CallWrite(pload) => (&pload.base.server, &pload.filehandle),
            EventPayload::NetNfsV3ReplyRead(pload) => (&pload.base.server, &pload.filehandle),
            _ => return,
        };

        let Some(server) = server else { return };

        trace!("Got new blob for file handle {:?}", filehandle);

        let filename = filehandle.iter().map(|b| format!("{:02X}", b)).collect::<String>();
        let filepath = self.path.clone().strict_join(server.to_string()).unwrap().strict_join("by-fh").unwrap().strict_join(filename).unwrap();

        if let Err(e) = filepath.create_parent_dir_all() {
            error!("Unable to create parent path : {}", e);
            return;
        };

        let file = match OpenOptions::new().write(true).create(true).truncate(false).open(&filepath.interop_path()) {
            Ok(file) => file,
            Err(e) => {
                error!("Unable to open file {} for writing: {}", filepath.strictpath_display(), e);
                return;
            }
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

    fn process_event(&mut self, event: &EventRef) {

        match event.kind() {
            EventKind::NetMountReplyMnt => self.process_mnt(event),
            EventKind::NetNfsV3ReplyLookup => self.process_v3_lookup(event),
            EventKind::NetNfsV3ReplyCreate => self.process_v3_create(event),
            EventKind::NetNfsV3ReplyMkdir => self.process_v3_mkdir(event),
            EventKind::NetNfsV3ReplyRename => self.process_v3_rename(event),
            _ => unreachable!()
        }

    }

    fn process_mnt(&mut self, event: &EventRef) {

        // Save the mount point file handle and tries to create the basic directory structure

        let EventPayload::NetMountReplyMnt(ref pload) = event.as_ref().payload else { unreachable!(); };
        let Some(filehandle) = &pload.filehandle else { return; };
        let key: NfsFileHandleKey =(pload.server.clone(), filehandle.clone());
        let server = pload.server.to_string();

        if pload.path.len() < 1 {
            debug!("Empty path in mount");
            return;
        }

        // Create the by-path directory and insert it in the hashmap

        let path_str = String::from_utf8_lossy(&pload.path);
        let path = match self.path.clone().strict_join(&server).unwrap().strict_join("by-path").unwrap().strict_join(&path_str[1..]) {
            Ok(path) => path,
            Err(e) => {
                debug!("Invalid path \"{}\" in mount request : {}", path_str, e);
                return;
            }
        };

        if let Err(e) = path.create_dir_all() {
            error!("Unable to create directory {}: {}", path.strictpath_display(), e);
        }

        self.pathmap.insert(key, path);


        // Create the by-fh directory

        let byfh_path = self.path.clone().strict_join(&server).unwrap().strict_join("by-fh").unwrap();
        if let Err(e) = byfh_path.create_dir_all() {
            error!("Unable to create directory {}: {}", byfh_path.strictpath_display(), e);
        }

        trace!("Mount of {} with handle {:?}", path_str, filehandle);
    }

    fn process_v3_lookup(&mut self, event: &EventRef) {

        // Store the mapping in the pathmap

        let EventPayload::NetNfsV3ReplyLookup(ref pload) = event.as_ref().payload else { unreachable!(); };
        let name = String::from_utf8_lossy(&pload.name);

        let Some(server) = pload.base.server else { return };
        let Some(filehandle) = &pload.filehandle else { return };
        let Some(ftype) = pload.r#type else { return };
        let key: NfsFileHandleKey = (server, pload.parent.clone());

        let Some(parent) = self.pathmap.get(&key) else {
            debug!("Parent directory not known for {:?}", key);
            return;
        };

        let new_path = parent.clone().strict_join(&*name).unwrap(); // FIXME don't unwrap


        if ftype == 2 {
            debug!("Found new directory {}", new_path.strictpath_display());
            let new_key: NfsFileHandleKey = (server, filehandle.clone());
            self.pathmap.insert(new_key, new_path);
            return;
        } else if ftype != 1 {
            debug!("Not tracking non regular file {}", new_path.strictpath_display());
            return;
        }

        // Create the file in by-fh to make sure it exists. truncate it if needed.
        let byfh_name = filehandle.iter().map(|b| format!("{:02X}", b)).collect::<String>();
        let by_fh = self.path.clone().strict_join(server.to_string()).unwrap().strict_join("by-fh").unwrap().strict_join(byfh_name).unwrap();


        let _fh_file = match OpenOptions::new().write(true).create(true).truncate(false).open(&by_fh.interop_path()) {
            Ok(file) => file,
            Err(e) => {
                error!("Unable to open file {} for writing: {}", by_fh.strictpath_display(), e);
                return;
            }
        };

        // Create the hard link in by-path to the file in by-fh
        if let Err(e) = new_path.create_parent_dir_all() {
            error!("Unable to create parent path : {}", e);
            return;
        };

        trace!("Creating file {} -> {}", by_fh.strictpath_display(), new_path.strictpath_display());

        if let Err(e) = hard_link(by_fh.interop_path(), new_path.interop_path()) {
            if e.kind() != ErrorKind::AlreadyExists {
                error!("Unable to hardlink {} -> {}: {}", new_path.strictpath_display(), by_fh.strictpath_display(), e);
            }
            return;
        }
    }

    fn process_v3_create(&mut self, event: &EventRef) {

        // Create an empty file in by-fh and the corresponding hard link in by-path

        let EventPayload::NetNfsV3ReplyCreate(ref pload) = event.as_ref().payload else { unreachable!(); };
        let filename = String::from_utf8_lossy(&pload.filename);

        let Some(server) = pload.base.server else { return };
        let Some(filehandle) = &pload.filehandle else { return };
        let key: NfsFileHandleKey = (server, pload.parent.clone());

        let Some(parent) = self.pathmap.get(&key) else {
            debug!("Parent directory not known for {:?}", key);
            return;
        };

        let mut truncate = false;

        if let Some(size) = &pload.size {
            if *size == 0 {
                truncate = true;
            }
        }

        // Create the file in by-fh to make sure it exists. truncate it if needed.
        let byfh_name = filehandle.iter().map(|b| format!("{:02X}", b)).collect::<String>();
        let by_fh = self.path.clone().strict_join(server.to_string()).unwrap().strict_join("by-fh").unwrap().strict_join(byfh_name).unwrap();


        let _fh_file = match OpenOptions::new().write(true).create(true).truncate(truncate).open(&by_fh.interop_path()) {
            Ok(file) => file,
            Err(e) => {
                error!("Unable to open file {} for writing: {}", by_fh.strictpath_display(), e);
                return;
            }
        };

        // Create the hard link in by-path to the file in by-fh
        let by_path = parent.clone().strict_join(&*filename).unwrap(); // FIXME don't unwrap
        if let Err(e) = by_path.create_parent_dir_all() {
            error!("Unable to create parent path : {}", e);
            return;
        };

        trace!("Creating file {} -> {}", by_fh.strictpath_display(), by_path.strictpath_display());

        if let Err(e) = hard_link(by_fh.interop_path(), by_path.interop_path()) {
            if e.kind() != ErrorKind::AlreadyExists {
                error!("Unable to hardlink {} -> {}: {}", by_path.strictpath_display(), by_fh.strictpath_display(), e);
            }
            return;
        }
    }

    fn process_v3_mkdir(&mut self, event: &EventRef) {

        let EventPayload::NetNfsV3ReplyMkdir(ref pload) = event.as_ref().payload else { unreachable!(); };
        if pload.status != 0 { return; }; // Mkdir didn't happen
        let dirname = String::from_utf8_lossy(&pload.dirname);

        let Some(server) = pload.base.server else { return };
        let Some(dirhandle) = &pload.dirhandle else { return };
        let parent_key: NfsFileHandleKey = (server, pload.parent.clone());

        let Some(parent) = self.pathmap.get(&parent_key) else {
            debug!("Mkdir parent directory not known for {:?}", parent_key);
            return;
        };

        let dir_path = parent.clone().strict_join(&*dirname).unwrap();
        if let Err(e) = dir_path.create_dir_all() {
            error!("Unable to create directory {}: {}", dir_path.strictpath_display(), e);
        }

        let new_key: NfsFileHandleKey = (server, dirhandle.clone());

        trace!("Created directory {} ({:?})", dir_path.strictpath_display(), &new_key);

        self.pathmap.insert(new_key, dir_path);

    }

    fn process_v3_rename(&mut self, event: &EventRef) {

        let EventPayload::NetNfsV3ReplyRename(ref pload) = event.as_ref().payload else { unreachable!(); };
        if pload.status != 0 { return; }; // Rename didn't happen

        let Some(server) = pload.base.server else { return };

        let from_key: NfsFileHandleKey = (server, pload.from_fh.clone());
        let Some(from_parent) = self.pathmap.get(&from_key) else {
            debug!("Rename from parent directory not known for {:?}", from_key);
            return;
        };

        let to_key: NfsFileHandleKey = (server, pload.to_fh.clone());
        let Some(to_parent) = self.pathmap.get(&to_key) else {
            debug!("Rename to parent directory not known for {:?}", to_key);
            return;
        };

        let from_filename = String::from_utf8_lossy(&pload.from_name);
        let from_name = from_parent.clone().strict_join(&*from_filename).unwrap();


        let to_filename = String::from_utf8_lossy(&pload.to_name);
        let to_name = to_parent.clone().strict_join(&*to_filename).unwrap();

        if let Err(e) = rename(from_name.interop_path(), to_name.interop_path()) {
            error!("Unable to rename {} to {}: {}", from_name.strictpath_display(), to_name.strictpath_display(), e);
            return;
        }

        trace!("Renamed {} -> {}", from_name.strictpath_display(), to_name.strictpath_display());

    }
}


impl Output for OutputNfsMirror {


    fn run(mut self: Box<Self>, rx: MessageRxChannel) {

        for msg in rx {
            match msg {
                Message::Shutdown => break,
                Message::Event(e) => self.process_event(&e),
                Message::BlobMsg(BlobMsg::Begin(b)) => self.process_blob_begin(&b),
                Message::BlobMsg(BlobMsg::Data(d)) => self.process_blob_data(&d),
                Message::BlobMsg(BlobMsg::End(e)) => self.process_blob_end(&e),
            }
        }
    }

}
