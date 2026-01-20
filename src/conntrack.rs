use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::any::Any;

//#[derive(Eq, Hash, PartialEq)]


type ConntrackRef = Arc<Mutex<Conntrack>>;



pub trait ConntrackKey {
    fn bidir_hash(&self) -> u64;
}

pub type ConntrackData = Box<dyn Any + Send + Sync>;

pub struct Conntrack {
    data: ConntrackData,
    parent: Option<ConntrackRef>,
    children: Vec<ConntrackRef>
}

type ConntrackList = Vec<ConntrackRef>;

pub struct ConntrackTable {
    entries: HashMap<u64, ConntrackList>
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


impl ConntrackTable {

    pub fn new() -> Self {
        ConntrackTable { entries: HashMap::new() }
    }


    pub fn get<K: ConntrackKey>(&mut self, key: K) -> ConntrackRef {

        let mut ct: Option<ConntrackRef> = None;


        let bidir_hash = key.bidir_hash();

        ct = match self.entries.get(&bidir_hash) {
            Some (cts) => {
                for ct in cts {
                    if ct.key == key {
                        // Conntrack found, return it
                        return ct.clone();
                    }
                }

                None
            }

            None => None
        };

        ct.unwrap()
    }
}

