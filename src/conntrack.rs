use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::any::Any;
use std::collections::hash_map::Entry;

//#[derive(Eq, Hash, PartialEq)]


type ConntrackRef = Arc<Mutex<Conntrack>>;



pub trait ConntrackKey : Copy {
    fn bidir_key(&self) -> u64;
    fn fwd_eq(&self, other: &Self) -> bool;
    fn rev_eq(&self, other: &Self) -> bool;
}

pub type ConntrackData = Box<dyn Any + Send + Sync>;

pub struct Conntrack {
    data: ConntrackData,
    parent: Option<ConntrackRef>,
    children: Vec<ConntrackRef>
}

type ConntrackList<K> = Vec<ConntrackEntry<K>>;

struct ConntrackEntry<K: ConntrackKey> {
    key: K,
    ce: ConntrackRef,
}

pub struct ConntrackTable<K: ConntrackKey> {
    entries: HashMap<u64, ConntrackList<K>>
}


impl Conntrack {

    pub fn new() -> ConntrackRef {
        Arc::new(Mutex::new(
            Conntrack {
                data: Box::new(()),
                parent: None,
                children: Vec::new()
            }
        ))

    }
}


impl<K: ConntrackKey> ConntrackTable<K> {

    pub fn new() -> Self {
        ConntrackTable { entries: HashMap::new() }
    }


    pub fn get(&mut self, key: K) -> ConntrackRef {


        // Calculate the bi-directional key and try to find it in the hash map
        let bidir_key = key.bidir_key();

        println!("Searching for conntrack with key {}", bidir_key);


        match self.entries.entry(bidir_key) {
            Entry::Occupied(mut entry) => {

                let ct_list = entry.get_mut();

                for ct_entry in ct_list.iter() { // Try to find the exact conntrack in the ConntrackList
                    if ct_entry.key.fwd_eq(&key) {
                        // Conntrack found, forward direction
                        println!("Conntrack found in forward direction");
                        return ct_entry.ce.clone();
                    } else if ct_entry.key.rev_eq(&key) {
                        // Conntrack found, reverse direction
                        println!("Conntrack found in reverse direction");
                        return ct_entry.ce.clone();
                    }
                }

                // Not found, create and add to the ConntrackList
                let ce = Conntrack::new();
                let ct_entry = ConntrackEntry {
                    key: key,
                    ce: ce.clone()
                };
                ct_list.push(ct_entry);
                println!("New conntrack in an existing list");
                ce

            }

            Entry::Vacant(entry) => {
                let ce = Conntrack::new();
                let ct_entry = ConntrackEntry {
                    key: key,
                    ce: ce.clone()
                };
                entry.insert(vec![ct_entry]);
                println!("New conntrack with a new list");
                ce
            }

        }

    }
}

