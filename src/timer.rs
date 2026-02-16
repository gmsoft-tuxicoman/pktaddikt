
use crate::packet::PktTime;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, LazyLock, TryLockError};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::trace;
use std::time::Duration;
use slab::Slab;


static TIMER_MANAGER: LazyLock<Mutex<TimerManager>> = LazyLock::new(|| { println!("Initialized"); Mutex::new(TimerManager::new())});
static TIMER_NOW: AtomicU64 = AtomicU64::new(0);


pub type TimerId = usize;
pub type TimerCb = Arc<dyn Fn() + Send + Sync + 'static>;

pub struct TimerManager {
    timers: Slab<Timer>,
    queues: BTreeMap<PktTime, TimerQueue>
}


struct Timer {
    duration: PktTime, // Initial duration of the timer
    expiry: PktTime, // When the timer expires
    action: Option<TimerCb>,
    next: Option<TimerId>,
    prev: Option<TimerId>
}

#[derive(Debug)]
struct TimerQueue {
    head: Option<TimerId>,
    tail: Option<TimerId>
}

impl TimerManager {

    fn new() -> Self {
        TimerManager {
            timers: Slab::new(),
            queues: BTreeMap::new()
        }
    }

    // Queue a new timer
    pub fn queue_new(duration: Duration, now: PktTime, action: TimerCb) -> TimerId {
        // Aquire lock
        let mut manager = TIMER_MANAGER.lock().unwrap();
        manager.queue_new_locked(duration.as_micros() as u64, now, action)
    }

    fn queue_new_locked(&mut self, duration: PktTime, now: PktTime, action: TimerCb) -> TimerId {

        let timer = Timer {
                action: Some(action),
                duration: 0,
                expiry: 0,
                next: None,
                prev: None,
        };

        let tid = self.timers.insert(timer);

        self.queue_locked(tid, duration, now);

        trace!("Timer {} created and queued with duration {}", tid, duration);

        tid
    }


    pub fn requeue(tid: TimerId, duration: Duration, now: PktTime) -> TimerId {
        // Aquire lock
        let mut manager = TIMER_MANAGER.lock().unwrap();
        manager.requeue_locked(tid, duration.as_micros() as u64, now)
    }


    fn requeue_locked(&mut self, tid: TimerId, duration: PktTime, now: PktTime) -> TimerId {

        self.dequeue_locked(tid);
        self.queue_locked(tid, duration, now);
        trace!("Timer {} requeued with duration {}", tid, duration);
        tid
    }

    pub fn destroy(tid: TimerId) {
        // Aquire lock
        let mut manager = TIMER_MANAGER.lock().unwrap();
        manager.destroy_locked(tid)

    }

    pub fn destroy_locked(&mut self, tid: TimerId) {
        self.dequeue_locked(tid);
        self.timers.remove(tid);
    }


    fn dequeue_locked(&mut self, tid: TimerId) {
        // Timer are always queued. Remove it

        let timer = &mut self.timers[tid];


        // Remove the timer from the existing queue
        let next_tid = timer.next;
        let prev_tid = timer.prev;
        let timer_duration = timer.duration;

        timer.prev = None;
        timer.next = None;


        let queue = self.queues.get_mut(&timer_duration).unwrap(); // Queue must exist.

        if let Some(next) = next_tid {
            // Timer is not the tail
            self.timers[next].prev = prev_tid;
        } else {
            // Timer is the tail
            queue.tail = prev_tid;
        }

        if let Some(prev) = prev_tid {
            // Timer is not the head
            self.timers[prev].next = next_tid;
        } else {
            // Timer is head
            queue.head = next_tid;
        }

    }


    fn queue_locked(&mut self, tid: TimerId, duration: PktTime, now: PktTime) {

        let timer = &mut self.timers[tid];
        timer.duration = duration;
        timer.expiry = duration + now;

        // Timer must be dequeued and not pointing anywhere
        assert_eq!(timer.next, None);
        assert_eq!(timer.prev, None);

        let queue = self.queues.entry(duration).or_insert(TimerQueue{ head: None, tail: None});

        if let Some(t) = queue.tail {
            // Some timer at the end of the queue
            self.timers[t].next = Some(tid);
            self.timers[tid].prev = Some(t);
        } else {
            // Queue empty
            queue.head = Some(tid);
        }
        queue.tail = Some(tid);

    }

    pub fn update_time(new_time: PktTime) {
        TIMER_NOW.fetch_max(new_time, Ordering::Relaxed);
    }


    pub fn process() {

        let actions;

        {
            // Locked scope
            let mut manager = match TIMER_MANAGER.try_lock() {
                Ok(g) => { g },
                Err(TryLockError::WouldBlock) => return,
                _ => panic!("Unexpected lock error")
            };
            let now = TIMER_NOW.load(Ordering::Relaxed);
            actions = manager.collect_timers_locked(now);
        }

        if actions.is_none() {
            return // Nothing to do
        }

        // Execute all the actions
        for action in actions.unwrap() {
            action();
        }

    }


    fn collect_timers_locked(&mut self, now: PktTime) -> Option<Vec<TimerCb>> {

        // Create a list with all the timers that need to be processed
        let mut ret: Option<Vec<TimerCb>> = None;

        // Check all the queues
        for queue in self.queues.values_mut() {

            // Check all items in the queue, stop on first non-expired
            while let Some(tid) = queue.head {
                if self.timers[tid].expiry > now {
                    break;
                }

                let mut timer = self.timers.remove(tid);
                let next_tid = timer.next;
                let prev_tid = timer.prev;

                let actions = ret.get_or_insert_with(Vec::new);
                actions.push(timer.action.take().unwrap());


                // Dequeue the timer
                if let Some(next) = next_tid {
                    // Timer is not the tail
                    self.timers[next].prev = prev_tid;
                } else {
                    // Timer is the tail
                    queue.tail = prev_tid;
                }

                if let Some(prev) = prev_tid {
                    // Timer is not the head
                    self.timers[prev].next = next_tid;
                } else {
                    // Timer is head
                    queue.head = next_tid;
                }

            }
        }
        ret
    }

}


impl Drop for Timer {

       fn drop(&mut self) {
            trace!("Timer {:p} dropped", self);
       }
}



#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn timer_insert_remove_one() {

        let mut manager = TimerManager::new();

        let timer1 = manager.queue_new_locked(1, 1, || { println!("Timer1")});
        assert_eq!(manager.timers.len(), 1);
        manager.destroy_locked(timer1);
        assert_eq!(manager.timers.len(), 0);
    }

    #[test]
    fn timer_insert2_remove_front() {
        let mut manager = TimerManager::new();

        let timer1 = manager.queue_new_locked(1,1, || { println!("Timer1")});
        let timer2 = manager.queue_new_locked(1,1, || { println!("Timer2")});
        assert_eq!(manager.timers.len(), 2);
        manager.destroy_locked(timer1);
        assert_eq!(manager.timers.len(), 1);
        assert_eq!(manager.timers[timer2].next, None);
        assert_eq!(manager.timers[timer2].prev, None);
        assert_eq!(manager.queues.get(&1).unwrap().head, Some(timer2));
        assert_eq!(manager.queues.get(&1).unwrap().tail, Some(timer2));
        manager.destroy_locked(timer2);
        assert_eq!(manager.queues.get(&1).unwrap().head, None);
        assert_eq!(manager.queues.get(&1).unwrap().tail, None);

    }

    #[test]
    fn timer_insert2_remove_back() {
        let mut manager = TimerManager::new();

        let timer1 = manager.queue_new_locked(1,1, || { println!("Timer1")});
        let timer2 = manager.queue_new_locked(1,1, || { println!("Timer2")});
        assert_eq!(manager.timers.len(), 2);
        manager.destroy_locked(timer2);
        assert_eq!(manager.timers.len(), 1);
        assert_eq!(manager.timers[timer1].next, None);
        assert_eq!(manager.timers[timer1].prev, None);
        assert_eq!(manager.queues.get(&1).unwrap().head, Some(timer1));
        assert_eq!(manager.queues.get(&1).unwrap().tail, Some(timer1));
        manager.destroy_locked(timer1);
        assert_eq!(manager.queues.get(&1).unwrap().head, None);
        assert_eq!(manager.queues.get(&1).unwrap().tail, None);

    }

    #[test]
    fn timer_insert3_remove_middle() {
        let mut manager = TimerManager::new();

        let timer1 = manager.queue_new_locked(1,1, || { println!("Timer1")});
        let timer2 = manager.queue_new_locked(1,1, || { println!("Timer2")});
        let timer3 = manager.queue_new_locked(1,1, || { println!("Timer3")});
        assert_eq!(manager.timers.len(), 3);
        manager.destroy_locked(timer2);
        assert_eq!(manager.timers.len(), 2);
        assert_eq!(manager.timers[timer1].prev, None);
        assert_eq!(manager.timers[timer1].next, Some(timer3));
        assert_eq!(manager.timers[timer3].prev, Some(timer1));
        assert_eq!(manager.timers[timer3].next, None);
        assert_eq!(manager.queues.get(&1).unwrap().head, Some(timer1));
        assert_eq!(manager.queues.get(&1).unwrap().tail, Some(timer3));

    }

    #[test]
    #[should_panic]
    fn timer_remove_invalid() {
        let mut manager = TimerManager::new();
        manager.dequeue_locked(42);

    }

    #[test]
    fn timer_insert3_collect2_same_queue() {

        let mut manager = TimerManager::new();
        manager.queue_new_locked(1, 1, || { println!("Timer1")});
        manager.queue_new_locked(1, 2, || { println!("Timer2")});
        manager.queue_new_locked(1, 3, || { println!("Timer3")});

        let actions = manager.collect_timers_locked(3).unwrap();

        assert_eq!(actions.len(), 2);
        assert_eq!(manager.timers.len(), 1);

    }

    #[test]
    fn timer_insert3_collect2_different_queue() {

        let mut manager = TimerManager::new();
        manager.queue_new_locked(1, 1, || { println!("Timer1")});
        manager.queue_new_locked(2, 1, || { println!("Timer2")});
        manager.queue_new_locked(3, 1, || { println!("Timer3")});

        let actions = manager.collect_timers_locked(3).unwrap();

        assert_eq!(actions.len(), 2);
        assert_eq!(manager.timers.len(), 1);

    }
}
