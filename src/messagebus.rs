use crate::event::{EventKind, EventRef};
use crate::blob::BlobMsg;

use std::sync::OnceLock;
use strum::{EnumCount, IntoEnumIterator};
use tracing::{debug, trace};


pub type MessageTxChannel = crossbeam_channel::Sender<Message>;
pub type MessageRxChannel = crossbeam_channel::Receiver<Message>;


static MESSAGE_BUS: OnceLock<MessageBus> = OnceLock::new();

#[derive(Debug)]
pub struct MessageBus {
    event_subs: Vec<Vec<MessageTxChannel>>,
    blob_subs: Vec<MessageTxChannel>,
}

impl MessageBus {

    pub fn new() -> Self {
        let mut event_subs = Vec::with_capacity(EventKind::COUNT);

        for _ in 0..EventKind::COUNT {
            event_subs.push(Vec::new());
        }

        MessageBus {
            event_subs,
            blob_subs: Vec::new(),
        }

    }

    pub fn init(self) {
        MESSAGE_BUS.set(self).unwrap();
    }

    pub fn event_subscribe_glob(&mut self, evt_glob: &str, tx: &MessageTxChannel) -> Result<(), ()> {

        let mut found = false;

        for evt in EventKind::iter() {
            let id = evt as usize;
            let name = evt.as_ref();

            if ! Self::event_match_glob(evt_glob, name) {
                continue;
            }

            found = true;

            debug!("Adding one subscriber to event {} ({})", name, id);
            self.event_subs[id].push(tx.clone());
        }

        if found {
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn event_subscribe_kind(&mut self, evt_kind: EventKind, tx: &MessageTxChannel) {

        let evt_id = evt_kind as usize;
        self.event_subs[evt_id].push(tx.clone());

    }

    fn event_match_glob(evt_glob: &str, evt_name: &str) -> bool {

        if evt_glob == "*" {
            return true; // Catch all
        }

        let g_parts: Vec<&str> = evt_glob.split('.').collect();
        let n_parts: Vec<&str> = evt_name.split('.').collect();

        for (i, p) in g_parts.iter().enumerate() {
            // Check each part

            if *p == "*" {
                // We got a wildcard
                return true;
            }

            if i >= n_parts.len() || p != &n_parts[i] {
                // More parts in our glob
                // Or part in our glob doesn't match the event name part
                return false;
            }

        }

        // Everything matched and we have the same number of parts
        g_parts.len() == n_parts.len()

    }

    pub fn event_has_subscribers(evt_kind: EventKind) -> bool {
        let id = evt_kind as usize;
        let Some(msg_bus) = MESSAGE_BUS.get() else {
            // Happens during test when event bus is not initialized
            // So pretend there is a subscriber so that parsing etc is done
            return true;
        };

        msg_bus.event_subs[id].len() > 0
    }

    pub fn blob_has_subscribers() -> bool {
        let Some(msg_bus) = MESSAGE_BUS.get() else {
            // Happens during test when event bus is not initialized
            // So pretend there is a subscriber so that parsing etc is done
            return true;
        };
        msg_bus.blob_subs.len() != 0
    }

    pub fn blob_subscribe(&mut self, tx: &MessageTxChannel) {
        self.blob_subs.push(tx.clone());
    }

    #[cfg(test)]
    pub fn publish_event(evt: EventRef) {
        trace!("Publishing message {:?}", evt.kind());
    }

    #[cfg(not(test))]
    pub fn publish_event(evt: EventRef) {

        trace!("Publishing event {:?}", evt.kind());
        let msg_bus = MESSAGE_BUS.get().unwrap();

        let evt_kind = evt.kind();

        let id = evt_kind as usize;
        for sub in &msg_bus.event_subs[id] {
            sub.send(Message::Event(evt.clone())).unwrap();
        }

    }

    pub fn publish_blobmsg(blob_msg: BlobMsg) {
        
        trace!("Publishing BlobMsg");
        let msg_bus = MESSAGE_BUS.get().unwrap();

        for sub in & msg_bus.blob_subs {
            sub.send(Message::BlobMsg(blob_msg.clone())).unwrap();
        }
    }
}



pub enum Message {

    Shutdown,
    Event(EventRef),
    BlobMsg(BlobMsg),
}
