
use crate::packet::PktTime;

use std::any::Any;
use std::fmt::Debug;
extern crate base62;

#[derive(Debug,Clone)]
pub struct EventId {
    id: String,
}

impl EventId {
    pub fn new(ts: PktTime, ptr: *const u8) -> EventId {

        let val: u128 = ((u64::from(ts) as u128) << 64) | ((ptr as u128));
        EventId {
            id: base62::encode(val)
        }
    }
}

pub trait EventData: Any + Debug {
    fn as_any(&self) -> &dyn Any;
}

impl <T: Any + Debug> EventData for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[derive(Debug)]
pub struct Event {

    id: EventId,
    ts: PktTime,
    name: &'static str,
    data: Box<dyn EventData>,

}

impl Event {

    pub fn new(name: &'static str, ts: PktTime, data: Box<dyn EventData>) -> Self {
        Event {
            id: EventId::new(ts, &data as *const Box<dyn EventData> as *const u8),
            ts: ts,
            name: name,
            data: data,
        }
    }

    pub fn send(&self) {
        println!("Got event {:?}", self);
    }

}
