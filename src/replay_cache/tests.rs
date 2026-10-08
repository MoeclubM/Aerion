use super::*;
use std::sync::Arc;

#[test]
fn rejects_replays_and_full_cache_without_eviction_or_extending_expiry() {
    let ttl = Duration::from_secs(10);
    let cache = ReplayCache::new(ttl, 2);
    let now = Instant::now();
    let mut entries = cache.entries.lock().unwrap();
    assert_eq!(cache.insert(&mut entries, 1, now), Ok(()));
    assert_eq!(cache.insert(&mut entries, 2, now + ttl / 2), Ok(()));
    assert_eq!(
        cache.insert(&mut entries, 1, now + ttl),
        Err(ReplayError::Replayed)
    );
    assert_eq!(
        cache.insert(&mut entries, 3, now + ttl),
        Err(ReplayError::Full)
    );
    assert_eq!(entries.keys.len(), 2);
    assert_eq!(entries.expiry.len(), 2);
    // The failed replay did not refresh key 1, and key 2 remains protected.
    assert_eq!(cache.insert(&mut entries, 3, now + ttl + ttl / 10), Ok(()));
    assert_eq!(
        cache.insert(&mut entries, 2, now + ttl + ttl / 10),
        Err(ReplayError::Replayed)
    );
    assert!(!entries.keys.contains(&1));
    assert_eq!(entries.keys.len(), 2);
    assert_eq!(cache.insert(&mut entries, 1, now + ttl * 3), Ok(()));
    assert_eq!(entries.keys.len(), 1);
    assert_eq!(entries.expiry.len(), 1);
}

#[test]
fn concurrent_handshakes_accept_a_nonce_exactly_once() {
    let cache = Arc::new(ReplayCache::new(Duration::from_secs(60), 32));
    let tasks = (0..16)
        .map(|_| {
            let cache = cache.clone();
            std::thread::spawn(move || cache.check_and_store([7u8; 16]))
        })
        .collect::<Vec<_>>();
    let results = tasks
        .into_iter()
        .map(|t| t.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| **r == Err(ReplayError::Replayed))
            .count(),
        15
    );
}

#[test]
fn credential_is_part_of_the_replay_key() {
    let cache = ReplayCache::new(Duration::from_secs(60), 2);
    assert_eq!(cache.check_and_store(("alice", [1u8; 16])), Ok(()));
    assert_eq!(cache.check_and_store(("bob", [1u8; 16])), Ok(()));
    assert_eq!(
        cache.check_and_store(("alice", [1u8; 16])),
        Err(ReplayError::Replayed)
    );
}
