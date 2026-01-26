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
    children: Vec<ConntrackRef>
}

type ConntrackList<K> = Vec<ConntrackEntry<K>>;

struct ConntrackEntry<K: ConntrackKey> {
    key: K,
    parent: Option<ConntrackWeakRef>,
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


    pub fn get(&self, key: K, parent: Option<ConntrackWeakRef>) -> ConntrackRef {



        // Let's see if we can find it from the parent first

        // Calculate the key and try to find it in the array
        let hash_key = key.key();
        let ct_index : usize = (((hash_key >> 32) as u32 ^ hash_key as u32)) as usize % self.entries.capacity();

        println!("Searching for conntrack with key {}", hash_key);

        let mut ct_list = self.entries[ct_index].lock().unwrap();

        for ct_entry in ct_list.iter() { // Try to find the exact conntrack in the ConntrackList

            if let Some(ref parent_weak) = parent { // If we were provided a parent
                if let Some(ct_parent_weak) = &ct_entry.parent { // Check the parent of the conntrack entry
                    println!("Comparing ct_entry {:p} with parent {:p}", Weak::as_ptr(&ct_parent_weak), Weak::as_ptr(&parent_weak));
                    // Make sure the parent is the same
                    if !Weak::ptr_eq(&ct_parent_weak, &parent_weak) {
                        println!("Parent did not match");
                        continue;
                    }
                }
            };

            if ct_entry.key.fwd_eq(&key) {
                // Conntrack found, forward direction
                println!("Conntrack found in forward direction");
                return ct_entry.ce.clone();
            } else if ct_entry.key.rev_eq(&key) {
                // Conntrack found, reverse direction
                println!("Conntrack found in reverse direction");
                return ct_entry.ce.clone();
            };


        }

        // Not found, create and add to the ConntrackList
 
        let ce = Conntrack::new();
        let ct_entry = ConntrackEntry {
            key: key,
            parent: parent.clone(),
            ce: ce.clone()
        };
        println!("Created new conntrack {:p}", Arc::as_ptr(&ct_entry.ce));
        ct_list.push(ct_entry);

        if let Some(ref parent_weak) = parent {
            if let Some(ref parent_strong) = parent_weak.upgrade() {
                parent_strong.lock().unwrap().children.push(ce.clone());
            }
        }


        println!("New conntrack in an existing list");

        ce
    }
}

