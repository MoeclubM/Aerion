use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::Notify;

pub struct TaskAbort {
    done: AtomicBool,
    notify: Notify,
}

impl TaskAbort {
    pub fn new() -> Self {
        Self {
            done: AtomicBool::new(false),
            notify: Notify::new(),
        }
    }

    pub fn trigger(&self) {
        if !self.done.swap(true, Ordering::Release) {
            self.notify.notify_waiters();
        }
    }

    pub fn is_triggered(&self) -> bool {
        self.done.load(Ordering::Acquire)
    }

    pub async fn cancelled(&self) {
        let notified = self.notify.notified();
        if self.done.load(Ordering::Acquire) {
            return;
        }
        notified.await;
    }
}

impl Default for TaskAbort {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for TaskAbort {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TaskAbort")
            .field("triggered", &self.is_triggered())
            .finish()
    }
}

#[cfg(test)]
mod tests;
