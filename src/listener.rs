use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::net::{TcpListener, TcpStream};
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

#[derive(Debug)]
pub enum AcceptError {
    Cancelled,
    Io(std::io::Error),
}

impl From<std::io::Error> for AcceptError {
    fn from(error: std::io::Error) -> Self {
        if is_accept_cancelled(&error) {
            Self::Cancelled
        } else {
            Self::Io(error)
        }
    }
}

/// Returns `AcceptError::Cancelled` when the listener task is aborted during shutdown.
pub fn is_accept_cancelled(error: &std::io::Error) -> bool {
    if error.kind() == std::io::ErrorKind::Interrupted {
        return true;
    }
    #[cfg(windows)]
    if matches!(error.raw_os_error(), Some(995) | Some(10004)) {
        return true;
    }
    let message = error.to_string().to_ascii_lowercase();
    message.contains("cancel")
        || message.contains("aborted")
        || message.contains("operation was aborted")
}

pub async fn accept_client(listener: &TcpListener) -> Result<(TcpStream, SocketAddr), AcceptError> {
    listener.accept().await.map_err(AcceptError::from)
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

    #[test]
    fn accept_cancelled_detects_interrupted() {
        assert!(is_accept_cancelled(&std::io::Error::from(
            std::io::ErrorKind::Interrupted
        )));
    }
}
