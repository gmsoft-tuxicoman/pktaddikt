use crate::output::{Output, OutputConfig};
use crate::messagebus::{MessageBus, MessageTxChannel, MessageRxChannel, Message};
use crate::config::Config;
use crate::blob::{BlobMsg, BlobMsgBegin, BlobMsgData, BlobMsgEnd};
use crate::event::{EventPayload, EventRef, EventKind};
use crate::base::Parser;
use crate::packet::PktTime;


use std::collections::HashMap;
use strict_path::{StrictPath, PathBoundary};
use serde::Deserialize;
use std::fs::{File, OpenOptions, hard_link, rename, remove_file, remove_dir_all};
use std::io::{Seek, SeekFrom, Write, ErrorKind};
use std::net::IpAddr;
use tracing::{error, debug, trace};

#[cfg(unix)]
use std::os::unix::fs::symlink;


type NfsFileHandleKey = (IpAddr, Vec<u8>);

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct NfsMirrorConfig {
    pub path: String,
    pub path_expiry: u32,
    pub keep_deleted: bool,
}

impl Default for NfsMirrorConfig {

    fn default() -> Self {
        Self {
            path: "".to_string(),
            path_expiry: 60,
            keep_deleted: true
        }
    }
}

#[derive(Clone)]
struct OutputNfsMirrorPath {

    path: StrictPath,
    last_seen: PktTime,
    is_root: bool,
}

pub struct OutputNfsMirror {

    blobs: HashMap<u64, File>,
    pathmap: HashMap<NfsFileHandleKey, OutputNfsMirrorPath>,
    path: PathBoundary,
    keep_deleted: bool,
    path_expiry: u32,
    last_purge: PktTime,
}


impl OutputNfsMirror {

    pub fn new(name: &str, tx: &MessageTxChannel) -> Box<dyn Output> {

        let main_cfg = Config::get();

        let OutputConfig::NfsMirror(cfg) = main_cfg.outputs.get(name).unwrap() else {
            panic!("Config is not nfsmirror");
        };

        MessageBus::blob_subscribe(tx);
        MessageBus::event_subscribe_kind(EventKind::NetMountReplyMnt, tx);
        MessageBus::event_subscribe_kind(EventKind::NetNfsV3ReplyLookup, tx);
        MessageBus::event_subscribe_kind(EventKind::NetNfsV3ReplyCreate, tx);
        MessageBus::event_subscribe_kind(EventKind::NetNfsV3ReplyMkdir, tx);
        MessageBus::event_subscribe_kind(EventKind::NetNfsV3ReplySymlink, tx);
        MessageBus::event_subscribe_kind(EventKind::NetNfsV3ReplyRemove, tx);
        MessageBus::event_subscribe_kind(EventKind::NetNfsV3ReplyRmdir, tx);
        MessageBus::event_subscribe_kind(EventKind::NetNfsV3ReplyRename, tx);
        MessageBus::event_subscribe_kind(EventKind::NetNfsV3ReplyLink, tx);
        MessageBus::event_subscribe_kind(EventKind::NetNfsV3ReplyReaddirplus, tx);

        let path = PathBoundary::<()>::try_new_create(cfg.path.clone()).unwrap();

        Box::new(Self {
            blobs: HashMap::new(),
            pathmap: HashMap::new(),
            path,
            keep_deleted: cfg.keep_deleted,
            path_expiry: cfg.path_expiry,
            last_purge: PktTime::from_secs(0),
        })
    }

    fn process_blob_begin(&mut self, msg: &BlobMsgBegin) {
        let Some(event) = &msg.event else { return };

        let (server, filehandle) = match &event.payload {
            EventPayload::NetNfsV3CallWrite(pload) => (pload.base.server_addr, &pload.filehandle),
            EventPayload::NetNfsV3ReplyRead(pload) => (pload.base.server_addr, &pload.filehandle),
            _ => return,
        };

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
            EventKind::NetNfsV3ReplySymlink => self.process_v3_symlink(event),
            EventKind::NetNfsV3ReplyRemove => self.process_v3_remove(event),
            EventKind::NetNfsV3ReplyRmdir => self.process_v3_rmdir(event),
            EventKind::NetNfsV3ReplyRename => self.process_v3_rename(event),
            EventKind::NetNfsV3ReplyLink => self.process_v3_link(event),
            EventKind::NetNfsV3ReplyReaddirplus => self.process_v3_readdirplus(event),
            _ => unreachable!()
        }

        self.purge_pathmap(event.ts);

    }

    fn purge_pathmap(&mut self, now: PktTime) {

        let threshold = PktTime::from_secs(self.path_expiry as u64);

        // Only purge every path_expiry
        if self.last_purge + threshold > now { return; };
        self.last_purge = now;

        self.pathmap.retain(|_k, entry| {

            let expiry = entry.last_seen + PktTime::from_secs(self.path_expiry as u64);
            if !entry.is_root && expiry < now {
                trace!("Purging path {}", entry.path.strictpath_display());
                return false;
            }
            true
        });

    }

    fn process_mnt(&mut self, event: &EventRef) {

        // Save the mount point file handle and tries to create the basic directory structure

        let EventPayload::NetMountReplyMnt(ref pload) = event.as_ref().payload else { unreachable!(); };
        let Some(filehandle) = &pload.filehandle else { return; };
        let key: NfsFileHandleKey =(pload.server_addr.clone(), filehandle.clone());
        let server = pload.server_addr.to_string();

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

        let path_entry = OutputNfsMirrorPath {
            path,
            last_seen: event.ts,
            is_root: true,
        };

        self.pathmap.entry(key).or_insert(path_entry);


        // Create the by-fh directory

        let byfh_path = self.path.clone().strict_join(&server).unwrap().strict_join("by-fh").unwrap();
        if let Err(e) = byfh_path.create_dir_all() {
            error!("Unable to create directory {}: {}", byfh_path.strictpath_display(), e);
        }

        trace!("Mount of {} with handle {:?}", path_str, filehandle);
    }

    fn process_v3_lookup(&mut self, event: &EventRef) {

        // Create hard links for new known files and update filehandle map for directories

        let EventPayload::NetNfsV3ReplyLookup(ref pload) = event.as_ref().payload else { unreachable!(); };
        let name = String::from_utf8_lossy(&pload.name);

        let server = pload.base.server_addr;
        let Some(filehandle) = &pload.filehandle else { return };
        let Some(fattr) = &pload.fattr else { return };
        let key: NfsFileHandleKey = (server, pload.parent.clone());

        let Some(parent) = self.pathmap.get_mut(&key) else {
            debug!("Parent directory not known for {:?}", key);
            return;
        };
        parent.last_seen = event.ts;

        let new_path = parent.path.clone().strict_join(&*name).unwrap(); // FIXME don't unwrap


        if fattr.r#type == 2 { // Directory
            trace!("Found new directory {}", new_path.strictpath_display());
            if let Err(e) = new_path.create_dir_all() {
                error!("Unable to create directory {}: {}", new_path.strictpath_display(), e);
            }

            let path_entry = OutputNfsMirrorPath {
                path: new_path,
                last_seen: event.ts,
                is_root: false,
            };

            let new_key: NfsFileHandleKey = (server, filehandle.clone());
            self.pathmap.entry(new_key).or_insert(path_entry);
            return;
        } else if fattr.r#type != 1 { // Non regular file
            debug!("Not tracking non regular file {}", new_path.strictpath_display());
            return;
        }

        // Regular file handling

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

        let server = pload.base.server_addr;
        let Some(filehandle) = &pload.filehandle else { return };
        let Some(fattr) = &pload.fattr else { return };
        let key: NfsFileHandleKey = (server, pload.parent.clone());

        let Some(parent) = self.pathmap.get_mut(&key) else {
            debug!("Parent directory not known for {:?}", key);
            return;
        };
        parent.last_seen = event.ts;

        let mut truncate = false;

        if fattr.size == 0 {
            truncate = true;
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
        let by_path = parent.path.clone().strict_join(&*filename).unwrap(); // FIXME don't unwrap
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

        let server = pload.base.server_addr;
        let Some(dirhandle) = &pload.dirhandle else { return };
        let parent_key: NfsFileHandleKey = (server, pload.parent.clone());

        let Some(parent) = self.pathmap.get_mut(&parent_key) else {
            debug!("Mkdir parent directory not known for {:?}", parent_key);
            return;
        };
        parent.last_seen = event.ts;

        let dir_path = parent.path.clone().strict_join(&*dirname).unwrap();
        if let Err(e) = dir_path.create_dir_all() {
            error!("Unable to create directory {}: {}", dir_path.strictpath_display(), e);
        }

        let new_key: NfsFileHandleKey = (server, dirhandle.clone());

        trace!("Created directory {} ({:?})", dir_path.strictpath_display(), &new_key);

        let path_entry = OutputNfsMirrorPath {
            path: dir_path,
            last_seen: event.ts,
            is_root: false,
        };
        self.pathmap.entry(new_key).or_insert(path_entry);

    }

    fn process_v3_symlink(&mut self, event: &EventRef) {

        #[cfg(windows)]
        {
            debug!("Symlink are not supported yet on windows. Patch welcome");
            return;
        }

        let EventPayload::NetNfsV3ReplySymlink(ref pload) = event.as_ref().payload else { unreachable!(); };
        if pload.status != 0 { return; }; // Symlink wasn't created

        let linkname = String::from_utf8_lossy(&pload.linkname);
        let to = String::from_utf8_lossy(&pload.to);
        let server = pload.base.server_addr;

        let parent_key: NfsFileHandleKey = (server, pload.parent.clone());

        let Some(parent) = self.pathmap.get_mut(&parent_key) else {
            debug!("Symlink parent directory not known for {:?}", parent_key);
            return;
        };
        parent.last_seen = event.ts;


        // FIXME: should I check where "to" points ?
        let link_path = parent.path.clone().strict_join(&*linkname).unwrap();
        if let Err(e) = symlink(&*to, link_path.interop_path()) {
            if e.kind() != ErrorKind::AlreadyExists {
                error!("Unable to symlink {} -> {}: {}", link_path.strictpath_display(), to, e);
                return;
            }
        }

        trace!("Created symlink {} -> {}", link_path.strictpath_display(), to);
    }

    fn process_v3_remove(&mut self, event: &EventRef) {

        if self.keep_deleted { return; };

        let EventPayload::NetNfsV3ReplyRemove(ref pload) = event.as_ref().payload else { unreachable!{}; };
        if pload.status != 0 { return; }; // File wasn't removed

        let name = String::from_utf8_lossy(&pload.name);
        let server = pload.base.server_addr;
        let parent_key: NfsFileHandleKey = (server, pload.parent.clone());

        let Some(parent) = self.pathmap.get_mut(&parent_key) else {
            debug!("Remove parent directory not known for {:?}", parent_key);
            return;
        };
        parent.last_seen = event.ts;

        let remove_path = parent.path.clone().strict_join(&*name).unwrap();
        if let Err(e) = remove_file(remove_path.interop_path()) {
            if e.kind() != ErrorKind::NotFound {
                error!("Unable to remove file {}: {}", remove_path.strictpath_display(), e);
                return;
            }
        }
        trace!("Removed file {}", remove_path.strictpath_display());
    }

    fn process_v3_rmdir(&mut self, event: &EventRef) {

        if self.keep_deleted { return; };

        let EventPayload::NetNfsV3ReplyRmdir(ref pload) = event.as_ref().payload else { unreachable!{}; };
        if pload.status != 0 { return; }; // Directory wasn't removed

        let name = String::from_utf8_lossy(&pload.name);
        let server = pload.base.server_addr;
        let parent_key: NfsFileHandleKey = (server, pload.parent.clone());

        let Some(parent) = self.pathmap.get_mut(&parent_key) else {
            debug!("Rmdir parent directory not known for {:?}", parent_key);
            return;
        };
        parent.last_seen = event.ts;

        let remove_path = parent.path.clone().strict_join(&*name).unwrap();
        if let Err(e) = remove_dir_all(remove_path.interop_path()) {
            if e.kind() != ErrorKind::NotFound {
                error!("Unable to remove directory {}: {}", remove_path.strictpath_display(), e);
                return;
            }
        }
        trace!("Removed directory {}", remove_path.strictpath_display());
    }

    fn process_v3_rename(&mut self, event: &EventRef) {

        let EventPayload::NetNfsV3ReplyRename(ref pload) = event.as_ref().payload else { unreachable!(); };
        if pload.status != 0 { return; }; // Rename didn't happen

        let server = pload.base.server_addr;

        let from_key: NfsFileHandleKey = (server, pload.from_fh.clone());
        let Some(from_parent) = self.pathmap.get_mut(&from_key) else {
            debug!("Rename from parent directory not known for {:?}", from_key);
            return;
        };
        from_parent.last_seen = event.ts;
        let from_filename = String::from_utf8_lossy(&pload.from_name);
        let from_name = from_parent.path.clone().strict_join(&*from_filename).unwrap();

        let to_key: NfsFileHandleKey = (server, pload.to_fh.clone());
        let Some(to_parent) = self.pathmap.get_mut(&to_key) else {
            debug!("Rename to parent directory not known for {:?}", to_key);
            return;
        };
        to_parent.last_seen = event.ts;



        let to_filename = String::from_utf8_lossy(&pload.to_name);
        let to_name = to_parent.path.clone().strict_join(&*to_filename).unwrap();

        if let Err(e) = rename(from_name.interop_path(), to_name.interop_path()) {
            error!("Unable to rename {} to {}: {}", from_name.strictpath_display(), to_name.strictpath_display(), e);
            return;
        }

        trace!("Renamed {} -> {}", from_name.strictpath_display(), to_name.strictpath_display());

    }

    fn process_v3_link(&mut self, event: &EventRef) {

        let EventPayload::NetNfsV3ReplyLink(ref pload) = event.as_ref().payload else { unreachable!(); };
        if pload.status != 0 { return; }; // Symlink wasn't created

        let dst_name = String::from_utf8_lossy(&pload.dst_name);
        let server = pload.base.server_addr;


        // Create the file in by-fh to make sure it exists. truncate it if needed.
        let src_name = pload.filehandle.iter().map(|b| format!("{:02X}", b)).collect::<String>();
        let src_path = self.path.clone().strict_join(server.to_string()).unwrap().strict_join("by-fh").unwrap().strict_join(src_name).unwrap();

        let parent_key: NfsFileHandleKey = (server, pload.dst_parent.clone());

        let Some(parent) = self.pathmap.get_mut(&parent_key) else {
            debug!("Link parent directory not known for {:?}", parent_key);
            return;
        };
        parent.last_seen = event.ts;

        let dst_path = parent.path.clone().strict_join(&*dst_name).unwrap();
        if let Err(e) = hard_link(&*src_path.interop_path(), dst_path.interop_path()) {
            if e.kind() != ErrorKind::AlreadyExists {
                error!("Unable to link {} -> {}: {}", src_path.strictpath_display(), dst_path.strictpath_display(), e);
                return;
            }
        }

        trace!("Created hardlink {} -> {}", src_path.strictpath_display(), dst_path.strictpath_display());
    }
    fn process_v3_readdirplus(&mut self, event: &EventRef) {

        let EventPayload::NetNfsV3ReplyReaddirplus(ref pload) = event.as_ref().payload else { unreachable!(); };
        if pload.status != 0 { return; };

        let server = pload.base.server_addr;
        let parent_key: NfsFileHandleKey = (server, pload.dirhandle.clone());

        let Some(mut parent) = self.pathmap.get_mut(&parent_key).cloned() else {
            debug!("READDIRPLUS parent directory not known for {:?}", parent_key);
            return;
        };
        parent.last_seen = event.ts;

        for entry in &pload.entries {
            let name = String::from_utf8_lossy(&entry.name);
            trace!("Found entry {}", name);

            let Some(filehandle) = &entry.filehandle else { continue; };

            let Some(fattr) = &entry.fattr else { continue; };

            let new_path = parent.path.clone().strict_join(&*name).unwrap(); // FIXME don't unwrap


            if fattr.r#type == 2 { // Directory
                trace!("Found new directory {}", new_path.strictpath_display());
                if let Err(e) = new_path.create_dir_all() {
                    error!("Unable to create directory {}: {}", new_path.strictpath_display(), e);
                }
                let path_entry = OutputNfsMirrorPath {
                    path: new_path,
                    last_seen: event.ts,
                    is_root: false,
                };

                let new_key: NfsFileHandleKey = (server, filehandle.clone());
                self.pathmap.entry(new_key).or_insert(path_entry);
                continue;
            } else if fattr.r#type != 1 { // Non regular file
                debug!("Not tracking non regular file {}", new_path.strictpath_display());
                continue;
            }

            // Regular file handling

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
                continue;
            }
        }
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
