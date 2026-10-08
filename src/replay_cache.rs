use std::collections::{HashSet, VecDeque};
use std::hash::Hash;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReplayError {
    Replayed,
    Full,
}

struct Entries<K> {
    keys: HashSet<K>,
    expiry: VecDeque<(Instant, K)>,
}

// Never evict an unexpired key to make room: that would permit replay under load.
// Insertion order and monotonic time allow amortized O(1) expiry, without scanning
// every authenticated handshake on every new handshake.
pub(crate) struct ReplayCache<K> {
    entries: Mutex<Entries<K>>,
    ttl: Duration,
    capacity: usize,
}

impl<K: Eq + Hash + Clone> ReplayCache<K> {
    pub(crate) fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            entries: Mutex::new(Entries {
                keys: HashSet::new(),
                expiry: VecDeque::new(),
            }),
            ttl,
            capacity,
        }
    }

    pub(crate) fn check_and_store(&self, key: K) -> Result<(), ReplayError> {
        let mut entries = self.entries.lock().expect("replay cache lock poisoned");
        // Read time inside the lock so concurrent insertion order stays monotonic.
        self.insert(&mut entries, key, Instant::now())
    }

    fn insert(&self, entries: &mut Entries<K>, key: K, now: Instant) -> Result<(), ReplayError> {
        while entries
            .expiry
            .front()
            .is_some_and(|(seen, _)| now.duration_since(*seen) > self.ttl)
        {
            let (_, expired) = entries.expiry.pop_front().unwrap();
            entries.keys.remove(&expired);
        }
        if entries.keys.contains(&key) {
            return Err(ReplayError::Replayed);
        }
        if entries.keys.len() >= self.capacity {
            return Err(ReplayError::Full);
        }
        entries.keys.insert(key.clone());
        entries.expiry.push_back((now, key));
        Ok(())
    }
}

#[cfg(test)]
mod tests;
