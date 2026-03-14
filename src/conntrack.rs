use std::sync::{Arc, Weak, Mutex};
use std::any::Any;
use tracing::{debug, trace};
use std::time::Duration;
use std::sync::atomic::{AtomicU64, Ordering};


use crate::timer::{TimerManager, TimerId, TimerCb};
use crate::packet::PktTime;

pub type ConntrackRef = Arc<Mutex<Conntrack>>;
pub type ConntrackWeakRef = Weak<Mutex<Conntrack>>;
pub type ConntrackTimerCb = Arc<dyn Fn(ConntrackRef) + Send + Sync>;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ConntrackDirection {
    Forward,
    Reverse
}

impl ConntrackDirection {

    pub fn opposite(&self) -> Self {
        match self {
            ConntrackDirection::Forward => ConntrackDirection::Reverse,
            ConntrackDirection::Reverse => ConntrackDirection::Forward
        }
    }
}

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
    cleanup_cb: TimerCb,
    timer: Option<TimerId>,
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

pub struct ConntrackTimer {
    timer: TimerId,
}

impl Conntrack {

    pub fn new(cleanup_cb: TimerCb) -> ConntrackRef
    {
        Arc::new(Mutex::new(
        Conntrack {
            data: None,
            children: Vec::new(),
            cleanup_cb: cleanup_cb,
            timer: None,
        }))

    }

    pub fn get_or_insert_with<F>(&mut self, f: F) -> &mut ConntrackData
    where
        F: FnOnce() -> ConntrackData,
    {
        self.data.get_or_insert_with(f)
    }

    pub fn has_children(&self) -> bool {
        self.children.len() > 0
    }

    pub fn set_timeout(&mut self, duration: Duration, now: PktTime) {

        if duration.is_zero() {
            if self.timer.is_some() {
                TimerManager::destroy(self.timer.take().unwrap());
            }
        } else {
            match self.timer {
                Some(timer) => { TimerManager::requeue(timer, duration, now); },
                None => self.timer = Some(TimerManager::queue_new(duration, now, self.cleanup_cb.clone()))
            }

        }
    }

}

impl Drop for Conntrack {

    fn drop(&mut self) {
        trace!("Conntrack {:p} dropped", self);
        if self.timer.is_some() {
            TimerManager::destroy(self.timer.unwrap());
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
    pub fn get(&'static self, key: K, parent: Option<ConntrackWeakRef>) -> (ConntrackRef, ConntrackDirection) {

        // Calculate the key and try to find it in the array
        let hash_key = key.key();
        let ct_index : usize = (((hash_key >> 32) as u32 ^ hash_key as u32)) as usize % self.entries.capacity();

        debug!("Searching for conntrack with key {} and parent {:?}", hash_key, parent);

        let mut ct_list = self.entries[ct_index].lock().unwrap();

        let mut found: Option<&mut ConntrackEntry<K>> = None;

        let mut direction = ConntrackDirection::Forward;

        for ct_entry in ct_list.iter_mut() { // Try to find the exact conntrack in the ConntrackList

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
                found = Some(ct_entry);
                break;
            } else if ct_entry.key.rev_eq(&key) {
                // Conntrack found, reverse direction
                debug!("Conntrack found in reverse direction");
                found = Some(ct_entry);
                direction = ConntrackDirection::Reverse;
                break;
            };


        }

        if let Some(entry) = found {
            return (entry.ce.clone(), direction);
        }

        // Not found, create and add to the ConntrackList

        let next_id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let cleanup_cb = Arc::new(move || self.remove(ct_index, next_id));
        let ce = Conntrack::new(cleanup_cb);
        let ct_entry = ConntrackEntry {
            key: key,
            parent: parent.clone(),
            ce: ce.clone(),
            id: next_id,
        };
        debug!("Created new conntrack {:p}", Arc::as_ptr(&ct_entry.ce));
        ct_list.push(ct_entry);

        if let Some(ref parent_weak) = parent {
            if let Some(ref parent_strong) = parent_weak.upgrade() {
                parent_strong.lock().unwrap().children.push(ce.clone());
            }
        }

        (ce, ConntrackDirection::Forward)
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
            let cleanup_cb = child.lock().unwrap().cleanup_cb.clone();
            cleanup_cb();
        }


    }

    pub fn purge(&self) {

        for ct_list in &self.entries {
            ct_list.lock().unwrap().clear();
        }

    }
}


impl ConntrackTimer {

    pub fn new(ce: &ConntrackRef, duration: Duration, now: PktTime, action: ConntrackTimerCb) -> Self {


        let ce_weak = Arc::downgrade(ce);
        ConntrackTimer {
            timer: TimerManager::queue_new(duration, now, Arc::new(move || ConntrackTimer::process(ce_weak.clone(), action.clone())))
        }

    }

    pub fn requeue(&self, duration: Duration, now: PktTime) {
        TimerManager::requeue(self.timer, duration, now);
    }

    fn process(ce_weak: ConntrackWeakRef, action: ConntrackTimerCb) {

        let ce = Weak::upgrade(&ce_weak);
        if ce.is_none() {
            return
        }
        action(ce.unwrap());
    }
}

impl Drop for ConntrackTimer {

    fn drop(&mut self) {
        TimerManager::destroy(self.timer);
    }

}


#[cfg(test)]
mod tests {

    use super::*;
    use std::sync::OnceLock;
    use tracing_test::traced_test;


    type ConntrackKeyTest = ConntrackKeyBidir<u32>;

    fn ct_len<K: ConntrackKey>(ct: &ConntrackTable<K>) -> usize {
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
        let (ce, _) = ct.get(ct_key, None);
        assert_eq!(ct_len(&ct), 1);

        // Cannot call cleanup_cb while locked
        let cleanup_cb = ce.lock().unwrap().cleanup_cb.clone();

        cleanup_cb();

        assert_eq!(ct_len(&ct), 0);
    }


    #[test]
    #[traced_test]
    fn add_child_remove_parent() {
        static CT_TEST: OnceLock<ConntrackTable<ConntrackKeyTest>> = OnceLock::new();

        // Use the same ct_key for parent and child to make sure it creates different conntracks
        let ct_key = ConntrackKeyTest{ a: 1, b: 2};

        let ct = CT_TEST.get_or_init(|| ConntrackTable::new(CT_TEST_SIZE));

        let (parent, _) = ct.get(ct_key, None);
        ct.get(ct_key, Some(Arc::downgrade(&parent)));
        assert_eq!(ct_len(&ct), 2);

        // Cannot call cleanup_cb while locked
        let cleanup_cb = parent.lock().unwrap().cleanup_cb.clone();

        cleanup_cb();
        assert_eq!(ct_len(&ct), 0);

    }

    #[test]
    #[traced_test]
    fn match_fwd_rev() {
        static CT_TEST: OnceLock<ConntrackTable<ConntrackKeyTest>> = OnceLock::new();

        let ct_key_fwd = ConntrackKeyTest{ a: 1, b: 2};
        let ct_key_rev = ConntrackKeyTest{ a: 2, b: 1};

        let ct = CT_TEST.get_or_init(|| ConntrackTable::new(CT_TEST_SIZE));

        let (ce_fwd, _) = ct.get(ct_key_fwd, None);
        assert_eq!(ct_len(&ct), 1);
        let (ce_rev, _) = ct.get(ct_key_rev, None);
        assert_eq!(ct_len(&ct), 1);

        assert_eq!(Arc::as_ptr(&ce_fwd), Arc::as_ptr(&ce_rev));

    }

    #[test]
    #[traced_test]
    fn purge() {

        static CT_TEST: OnceLock<ConntrackTable<ConntrackKeyTest>> = OnceLock::new();
        let ct = CT_TEST.get_or_init(|| ConntrackTable::new(CT_TEST_SIZE));
        let ct_key1 = ConntrackKeyTest{ a: 1, b: 2};
        let ct_key2 = ConntrackKeyTest{ a: 2, b: 3};
        let ct_key3 = ConntrackKeyTest{ a: 3, b: 4};

        ct.get(ct_key1, None);
        ct.get(ct_key2, None);
        ct.get(ct_key3, None);
        assert_eq!(ct_len(&ct), 3);
        ct.purge();
        assert_eq!(ct_len(&ct), 0);
    }


}

