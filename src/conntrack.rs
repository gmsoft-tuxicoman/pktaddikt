use std::sync::{Arc, Weak, Mutex};
use std::any::Any;


type ConntrackRef = Arc<Mutex<Conntrack>>;
pub type ConntrackWeakRef = Weak<Mutex<Conntrack>>;

pub trait ConntrackKey {
    fn key(&self) -> u64;
    fn fwd_eq(&self, other: &Self) -> bool;
    fn rev_eq(&self, other: &Self) -> bool;
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct ConntrackKeyBidir<T> {
    pub a: T,
    pub b: T,
}

impl<T> ConntrackKey for ConntrackKeyBidir<T>
    where T: Copy + PartialEq + Into<u64>
{
    fn key(&self) -> u64 {
        self.a.into() * self.b.into()
    }

    fn fwd_eq(&self, other: &Self) -> bool {
        self == other
    }

    fn rev_eq(&self, other: &Self) -> bool {
        self.a == other.b && self.b == other.a
    }
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
    entries: Vec<Mutex<ConntrackList<K>>>
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

    pub fn new(size: usize) -> Self {

        let mut entries = Vec::with_capacity(size);

        for _ in 0..size {
            entries.push(Mutex::new(ConntrackList::new()));
        }

        Self { entries }
    }


    pub fn get(&self, key: K) -> ConntrackRef {


        // Calculate the key and try to find it in the array
        let hash_key = key.key();
        let ct_index : usize = (((hash_key >> 32) as u32 ^ hash_key as u32)) as usize % self.entries.capacity();

        println!("Searching for conntrack with key {}", hash_key);

        let mut ct_list = self.entries[ct_index].lock().unwrap();

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
}

