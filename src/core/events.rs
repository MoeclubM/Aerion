use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::mpsc;

use super::CoreEvent;

#[derive(Default)]
pub(super) struct CoreEventBus {
    subscribers: Mutex<Vec<mpsc::UnboundedSender<CoreEvent>>>,
    /// Cached subscriber count so hot-path callers can skip event construction
    /// (and the subscribers lock) entirely when nobody is listening.
    subscriber_count: AtomicUsize,
}

impl CoreEventBus {
    pub(super) fn subscribe(&self) -> mpsc::UnboundedReceiver<CoreEvent> {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut subscribers = self
            .subscribers
            .lock()
            .expect("core event subscribers lock poisoned");
        subscribers.push(tx);
        self.subscriber_count
            .store(subscribers.len(), Ordering::Relaxed);
        rx
    }

    pub(super) fn send(&self, event: CoreEvent) {
        let mut subscribers = self
            .subscribers
            .lock()
            .expect("core event subscribers lock poisoned");
        subscribers.retain(|subscriber| subscriber.send(event.clone()).is_ok());
        self.subscriber_count
            .store(subscribers.len(), Ordering::Relaxed);
    }

    /// Deliver an event only when at least one subscriber is attached, building
    /// it lazily. On the per-chunk traffic hot path this avoids cloning the
    /// user id and locking the subscribers mutex when no one is listening.
    pub(super) fn dispatch(&self, make: impl FnOnce() -> CoreEvent) {
        if self.subscriber_count.load(Ordering::Relaxed) == 0 {
            return;
        }
        self.send(make());
    }
}

impl std::fmt::Debug for CoreEventBus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let subscribers = self
            .subscribers
            .lock()
            .expect("core event subscribers lock poisoned")
            .len();
        formatter
            .debug_struct("CoreEventBus")
            .field("subscribers", &subscribers)
            .finish()
    }
}
