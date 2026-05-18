use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::Notify;

#[derive(Clone, Debug, Default)]
pub struct ListenerStopToken {
    inner: Arc<ListenerStopInner>,
}

#[derive(Debug, Default)]
struct ListenerStopInner {
    stopped: AtomicBool,
    notify: Notify,
}

impl ListenerStopToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn stop(&self) {
        if !self.inner.stopped.swap(true, Ordering::SeqCst) {
            self.inner.notify.notify_waiters();
        }
    }

    pub fn is_stopped(&self) -> bool {
        self.inner.stopped.load(Ordering::SeqCst)
    }

    pub async fn stopped(&self) {
        if self.is_stopped() {
            return;
        }
        self.inner.notify.notified().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stop_token_notifies_waiters() {
        let token = ListenerStopToken::new();
        let waiter = token.clone();
        let task = tokio::spawn(async move {
            waiter.stopped().await;
            waiter.is_stopped()
        });
        token.stop();
        assert!(task.await.expect("join stop waiter"));
    }
}
