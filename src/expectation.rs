
use crate::packet::{PktInfoStack, PktTime};
use crate::proto::{Protocols, ProtoInfo};
use crate::timer::{TimerManager, TimerId};

use std::net::{Ipv4Addr, Ipv6Addr};
use arc_swap::ArcSwap;
use std::sync::{Arc, Mutex, OnceLock};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tracing::{debug, trace};


static UDP_EXPECTATIONS: OnceLock<ExpectationTable> = OnceLock::new();
static TCP_EXPECTATIONS: OnceLock<ExpectationTable> = OnceLock::new();


pub struct ExpectationTable {

    entries: ArcSwap<Vec<ExpectationEntry>>,
    write_lock: Mutex<()>,
    next_id: AtomicU64,
}

impl ExpectationTable {

    fn new() -> Self {
        Self {
            entries: ArcSwap::from_pointee(Vec::new()),
            write_lock: Mutex::new(()),
            next_id: AtomicU64::new(0),
        }
    }

    pub fn init(proto: Protocols) -> &'static ExpectationTable {
        match proto {
            Protocols::Udp => UDP_EXPECTATIONS.get_or_init(ExpectationTable::new),
            Protocols::Tcp => TCP_EXPECTATIONS.get_or_init(ExpectationTable::new),
            _ => panic!("No expectation table to init for given protocol")
        }
    }


    pub fn add(proto: Protocols, mut entry: ExpectationEntry, now: PktTime, expiry: Duration) {

        let table = match proto {
            Protocols::Udp => UDP_EXPECTATIONS.get().unwrap(),
            Protocols::Tcp => TCP_EXPECTATIONS.get().unwrap(),
            _ => panic!("No expectation table for given protocol")
        };

        let _guard = table.write_lock.lock().unwrap();
        let mut new_entries = Vec::clone(&table.entries.load());
        entry.id = table.next_id.fetch_add(1, Ordering::Relaxed);
        entry.timer_id = TimerManager::queue_new(expiry, now, Arc::new(move || table.remove(entry.id)));

        new_entries.push(entry);
        table.entries.store(Arc::new(new_entries));
    }

    pub fn check(&self, infos: &PktInfoStack) -> Option<Protocols> {

        let entries = self.entries.load();

        'outer: for entry in entries.iter() {

            let mut info = infos.iter().rev();

            let mut matched = false;
            for proto_match in entry.matches.iter() {

                let Some(pkt_info) = info.next() else {
                    continue;
                };

                let Some(proto_info) = pkt_info.proto_info.as_ref() else {
                    continue;
                };

                matched = match (proto_match, proto_info) {
                    (ExpectationType::Udp  { dport, sport: Some(s) }, ProtoInfo::Udp(u))   => (u.dport == *dport && u.sport == *s) || (u.sport == *dport && u.dport == *s),
                    (ExpectationType::Udp  { dport, sport: None }   , ProtoInfo::Udp(u))   => (u.dport == *dport) || (u.sport == *dport),

                    (ExpectationType::Tcp  { dport, sport: Some(s) }, ProtoInfo::Tcp(t))   => (t.dport == *dport && t.sport == *s) || (t.sport == *dport && t.dport == *s),
                    (ExpectationType::Tcp  { dport, sport: None }   , ProtoInfo::Tcp(t))   => t.dport == *dport || t.sport == *dport,

                    (ExpectationType::Ipv4 { daddr, saddr: Some(s)},  ProtoInfo::Ipv4(v4)) => (v4.dst == *daddr && v4.src == *s) || (v4.src == *daddr && v4.dst == *s),
                    (ExpectationType::Ipv4 { daddr, saddr: None }   , ProtoInfo::Ipv4(v4)) => v4.dst == *daddr || v4.src == *daddr,

                    (ExpectationType::Ipv6 { daddr, saddr: Some(s)},  ProtoInfo::Ipv6(v6)) => (v6.dst == *daddr && v6.src == *s) || (v6.src == *daddr && v6.dst == *s),
                    (ExpectationType::Ipv6 { daddr, saddr: None }   , ProtoInfo::Ipv6(v6)) => v6.dst == *daddr || v6.src == *daddr,
                    _ => false

                };
                if ! matched {
                    continue 'outer;
                }
            }

            if matched {
                let next_proto = entry.next_proto;

                if ! entry.persistent {
                    let entry_id = entry.id;

                    // Drop the guard
                    drop(entries);

                    // Remove the entry from the list
                    self.remove(entry_id);
                }


                trace!("Expectation matched with proto {:?}", next_proto);
                return Some(next_proto);
            }
        }

        None
    }

    pub fn remove(&self, id: u64) {

        let _guard = self.write_lock.lock().unwrap();
        let mut new_entries = Vec::clone(&self.entries.load());
        if let Some(pos) = new_entries.iter().position(|e| e.id == id) {
            let entry = new_entries.swap_remove(pos);
            TimerManager::destroy(entry.timer_id);
        } else {
            debug!("Entry {} not found in expectations", id);
        }
        self.entries.store(Arc::new(new_entries));
    }
}

#[derive(Clone)]
pub struct ExpectationEntry {
    matches: Vec<ExpectationType>,
    next_proto: Protocols,
    id: u64,
    timer_id: TimerId,
    persistent: bool,
}

impl ExpectationEntry {

    pub fn new(next_proto: Protocols, persistent: bool) -> Self {
        Self {
            matches: Vec::new(),
            next_proto,
            id: 0,
            timer_id: 0,
            persistent,
        }
    }

    pub fn add(mut self, expt: ExpectationType) -> Self {
        self.matches.push(expt);
        self
    }

}

#[derive(Clone)]
pub enum ExpectationType {
    Udp { dport: u16, sport: Option<u16> },
    Tcp { dport: u16, sport: Option<u16> },
    Ipv4 { daddr: Ipv4Addr, saddr: Option<Ipv4Addr> },
    Ipv6 { daddr: Ipv6Addr, saddr: Option<Ipv6Addr> },
}
