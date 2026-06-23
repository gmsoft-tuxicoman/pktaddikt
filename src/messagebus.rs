use crate::event::{EventKind, EventRef};
use crate::blob::BlobMsg;

use arc_swap::ArcSwap;
use std::sync::{Arc, OnceLock};
use strum::{EnumCount, IntoEnumIterator};
use tracing::{debug, trace};


pub type MessageTxChannel = crossbeam_channel::Sender<Message>;
pub type MessageRxChannel = crossbeam_channel::Receiver<Message>;


static MESSAGE_BUS: OnceLock<ArcSwap<MessageBus>> = OnceLock::new();

#[derive(Debug, Clone)]
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
        MESSAGE_BUS.set(ArcSwap::new(Arc::new(self))).unwrap();
    }

    pub fn event_subscribe_glob(evt_glob: &str, tx: &MessageTxChannel) -> Result<(), ()> {

        let arc_swap = MESSAGE_BUS.get().unwrap();
        let mut new_bus = (**arc_swap.load()).clone();
        let mut found = false;

        for evt in EventKind::iter() {
            let id = evt as usize;
            let name = evt.as_ref();

            if ! Self::event_match_glob(evt_glob, name) {
                continue;
            }

            found = true;

            debug!("Adding one subscriber to event {} ({})", name, id);
            new_bus.event_subs[id].push(tx.clone());
        }

        if found {
            arc_swap.store(Arc::new(new_bus));
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn event_subscribe_kind(evt_kind: EventKind, tx: &MessageTxChannel) {

        let arc_swap = MESSAGE_BUS.get().unwrap();
        let mut new_bus = (**arc_swap.load()).clone();
        new_bus.event_subs[evt_kind as usize].push(tx.clone());
        arc_swap.store(Arc::new(new_bus));

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
        let Some(arc_swap) = MESSAGE_BUS.get() else {
            // Happens during test when event bus is not initialized
            // So pretend there is a subscriber so that parsing etc is done
            return true;
        };

        arc_swap.load().event_subs[id].len() > 0
    }

    pub fn blob_has_subscribers() -> bool {
        let Some(arc_swap) = MESSAGE_BUS.get() else {
            // Happens during test when event bus is not initialized
            // So pretend there is a subscriber so that parsing etc is done
            return true;
        };
        arc_swap.load().blob_subs.len() != 0
    }

    pub fn blob_subscribe(tx: &MessageTxChannel) {
        let arc_swap = MESSAGE_BUS.get().unwrap();
        let mut new_bus = (**arc_swap.load()).clone();
        new_bus.blob_subs.push(tx.clone());
        arc_swap.store(Arc::new(new_bus));
    }

    pub fn event_unsubscribe_kind(evt_kind: EventKind, tx: &MessageTxChannel) {
        let arc_swap = MESSAGE_BUS.get().unwrap();
        let mut new_bus = (**arc_swap.load()).clone();
        new_bus.event_subs[evt_kind as usize].retain(|s| !s.same_channel(tx));
        arc_swap.store(Arc::new(new_bus));
    }

    pub fn blob_unsubscribe(tx: &MessageTxChannel) {
        let arc_swap = MESSAGE_BUS.get().unwrap();
        let mut new_bus = (**arc_swap.load()).clone();
        new_bus.blob_subs.retain(|s| !s.same_channel(tx));
        arc_swap.store(Arc::new(new_bus));
    }

    pub fn unsubscribe_all(tx: &MessageTxChannel) {
        let arc_swap = MESSAGE_BUS.get().unwrap();
        let mut new_bus = (**arc_swap.load()).clone();
        for subs in &mut new_bus.event_subs {
            subs.retain(|s| !s.same_channel(tx));
        }
        new_bus.blob_subs.retain(|s| !s.same_channel(tx));
        arc_swap.store(Arc::new(new_bus));
    }

    #[cfg(test)]
    pub fn publish_event(evt: EventRef) {
        trace!("Publishing message {:?}", evt.kind());
    }

    #[cfg(not(test))]
    pub fn publish_event(evt: EventRef) {

        trace!("Publishing event {:?}", evt.kind());
        let bus = MESSAGE_BUS.get().unwrap().load();

        let id = evt.kind() as usize;
        for sub in &bus.event_subs[id] {
            sub.send(Message::Event(evt.clone())).unwrap();
        }

    }

    pub fn publish_blobmsg(blob_msg: BlobMsg) {

        trace!("Publishing BlobMsg");
        let bus = MESSAGE_BUS.get().unwrap().load();

        for sub in &bus.blob_subs {
            sub.send(Message::BlobMsg(blob_msg.clone())).unwrap();
        }
    }
}



pub enum Message {

    Shutdown,
    Event(EventRef),
    BlobMsg(BlobMsg),
}
