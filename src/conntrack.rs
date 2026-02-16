use std::sync::{Arc, Weak, Mutex};
use std::any::Any;
use tracing::debug;
use std::time::Duration;
use std::sync::atomic::{AtomicU64, Ordering};


use crate::timer::{TimerManager, TimerId, TimerCb};
use crate::packet::PktTime;

pub type ConntrackRef = Arc<Mutex<Conntrack>>;
pub type ConntrackWeakRef = Weak<Mutex<Conntrack>>;

pub trait ConntrackKey {
    fn key(&self) -> u64;
    fn fwd_eq(&self, other: &Self) -> bool;
    fn rev_eq(&self, other: &Self) -> bool;
}

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct ConntrackKeyBidir<T> {
    pub a: T,
    pub b: T,
}

impl<T> ConntrackKey for ConntrackKeyBidir<T>
    where T: Copy + PartialEq + Into<u64>
{
    fn key(&self) -> u64 {
        // FIXME: This hash algo is wayy too simple
        self.a.into().overflowing_mul(self.b.into()).0
    }

    fn fwd_eq(&self, other: &Self) -> bool {
        self == other
    }

    fn rev_eq(&self, other: &Self) -> bool {
        self.a == other.b && self.b == other.a
    }
}

pub type ConntrackData = Box<dyn Any + Send + Sync>;

type ConntrackId = u64;

pub struct Conntrack {
    data: Option<ConntrackData>,
    children: Vec<ConntrackRef>,
    timer: Option<TimerId>,
    remove_cb: TimerCb,
}

type ConntrackList<K> = Vec<ConntrackEntry<K>>;

struct ConntrackEntry<K: ConntrackKey> {
    key: K,
    parent: Option<ConntrackWeakRef>,
    ce: ConntrackRef,
    id: ConntrackId,
}

pub struct ConntrackTable<K: ConntrackKey> {
    entries: Vec<Mutex<ConntrackList<K>>>,
    next_id: AtomicU64,
}


impl Conntrack {

    pub fn new<F>(remove_cb: F) -> ConntrackRef
    where
        F: Fn() + Send + Sync + 'static
    {
        Arc::new(Mutex::new(
        Conntrack {
            data: None,
            children: Vec::new(),
            timer: None,
            remove_cb: Arc::new(remove_cb)
        }))

    }

    pub fn get_or_insert(&mut self, value: ConntrackData) -> &mut ConntrackData {
        self.data.get_or_insert(value)
    }

    pub fn set_timeout(&mut self, duration: Duration, now: PktTime) {

        self.timer = match self.timer {
            None => Some(TimerManager::queue_new(duration, now, self.remove_cb.clone())),
            Some(tid) => Some(TimerManager::requeue(tid, duration, now))
        }

    }

}

impl Drop for Conntrack {

    fn drop(&mut self) {
        if let Some(timer) = self.timer {
            TimerManager::destroy(timer);
        }
    }

}


impl<K: ConntrackKey + Send> ConntrackTable<K> {

    pub fn new(size: usize) -> Self {

        let mut entries = Vec::with_capacity(size);

        for _ in 0..size {
            entries.push(Mutex::new(ConntrackList::new()));
        }

        Self { entries, next_id: AtomicU64::new(1) }
    }

    //#[tracing::instrument(skip(self))]
    pub fn get(&'static self, key: K, parent: Option<ConntrackWeakRef>) -> ConntrackRef {


        // Let's see if we can find it from the parent first

        // Calculate the key and try to find it in the array
        let hash_key = key.key();
        let ct_index : usize = (((hash_key >> 32) as u32 ^ hash_key as u32)) as usize % self.entries.capacity();

        debug!("Searching for conntrack with key {} and parent {:?}", hash_key, parent);

        let mut ct_list = self.entries[ct_index].lock().unwrap();

        for ct_entry in ct_list.iter() { // Try to find the exact conntrack in the ConntrackList

            if let Some(ref parent_weak) = parent { // If we were provided a parent
                if let Some(ct_parent_weak) = &ct_entry.parent { // Check the parent of the conntrack entry
                    debug!("Comparing ct_entry {:p} with parent {:p}", Weak::as_ptr(&ct_parent_weak), Weak::as_ptr(&parent_weak));
                    // Make sure the parent is the same
                    if !Weak::ptr_eq(&ct_parent_weak, &parent_weak) {
                        debug!("Parent did not match");
                        continue;
                    }
                } else {
                    // We need a conntrack with a parent
                    continue;
                }
            } else {
                if ct_entry.parent.is_some() {
                    // We need a conntrack without parent
                    continue;
                }

            };

            if ct_entry.key.fwd_eq(&key) {
                // Conntrack found, forward direction
                debug!("Conntrack found in forward direction");
                return ct_entry.ce.clone();
            } else if ct_entry.key.rev_eq(&key) {
                // Conntrack found, reverse direction
                debug!("Conntrack found in reverse direction");
                return ct_entry.ce.clone();
            };


        }

        // Not found, create and add to the ConntrackList

        let next_id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let ce = Conntrack::new(move || self.remove(ct_index, next_id));
        let ct_entry = ConntrackEntry {
            key: key,
            parent: parent.clone(),
            ce: ce.clone(),
            id: next_id
        };
        debug!("Created new conntrack {:p}", Arc::as_ptr(&ct_entry.ce));
        ct_list.push(ct_entry);

        if let Some(ref parent_weak) = parent {
            if let Some(ref parent_strong) = parent_weak.upgrade() {
                parent_strong.lock().unwrap().children.push(ce.clone());
            }
        }

        ce
    }

    fn remove(&self, ct_index: usize, id: ConntrackId) {

        let ct_entry;
        {
            let mut ct_list = self.entries[ct_index].lock().unwrap();

            let pos = match ct_list.iter().position(|ct| ct.id == id) {
                Some(p) => p,
                None => return
            };

            ct_entry = ct_list.remove(pos);
        }

        for child in &ct_entry.ce.lock().unwrap().children {
            // Don't call the cb while locked
            let remove_cb = child.lock().unwrap().remove_cb.clone();
            remove_cb();
        }


    }
}


#[cfg(test)]
mod tests {

    use super::*;
    use std::sync::OnceLock;
    use tracing_test::traced_test;


    type ConntrackKeyTest = ConntrackKeyBidir<u32>;

    fn ct_len<K :ConntrackKey>(ct :&ConntrackTable<K>) -> usize {
        let mut count = 0;

        for entry in &ct.entries {
            count = count + entry.lock().unwrap().len();
        }
        count
    }

    static CT_TEST_SIZE :usize = 16;

    #[test]
    #[traced_test]
    fn add_remove() {
        static CT_TEST: OnceLock<ConntrackTable<ConntrackKeyTest>> = OnceLock::new();

        let ct_key = ConntrackKeyTest{ a: 1, b: 2};
        let ct = CT_TEST.get_or_init(|| ConntrackTable::new(CT_TEST_SIZE));
        let ce = ct.get(ct_key, None);
        assert_eq!(ct_len(&ct), 1);

        // Cannot call remove_cb while locked
        let remove_cb = ce.lock().unwrap().remove_cb.clone();

        remove_cb();

        assert_eq!(ct_len(&ct), 0);
    }


    #[test]
    #[traced_test]
    fn add_child_remove_parent() {
        static CT_TEST: OnceLock<ConntrackTable<ConntrackKeyTest>> = OnceLock::new();

        // Use the same ct_key for parent and child to make sure it creates different conntracks
        let ct_key = ConntrackKeyTest{ a: 1, b: 2};

        let ct = CT_TEST.get_or_init(|| ConntrackTable::new(CT_TEST_SIZE));

        let parent = ct.get(ct_key, None);
        ct.get(ct_key, Some(Arc::downgrade(&parent)));
        assert_eq!(ct_len(&ct), 2);

        // Cannot call remove_cb while locked
        let remove_cb = parent.lock().unwrap().remove_cb.clone();

        remove_cb();
        assert_eq!(ct_len(&ct), 0);

    }

    #[test]
    #[traced_test]
    fn match_fwd_rev() {
        static CT_TEST: OnceLock<ConntrackTable<ConntrackKeyTest>> = OnceLock::new();

        let ct_key_fwd = ConntrackKeyTest{ a: 1, b: 2};
        let ct_key_rev = ConntrackKeyTest{ a: 2, b: 1};

        let ct = CT_TEST.get_or_init(|| ConntrackTable::new(CT_TEST_SIZE));

        let ce_fwd = ct.get(ct_key_fwd, None);
        assert_eq!(ct_len(&ct), 1);
        let ce_rev = ct.get(ct_key_rev, None);
        assert_eq!(ct_len(&ct), 1);

        assert_eq!(Arc::as_ptr(&ce_fwd), Arc::as_ptr(&ce_rev));

    }


}

