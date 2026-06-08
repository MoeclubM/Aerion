use anyhow::{Result, bail};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::time::{Duration, Instant};

use super::SessionControl;

#[derive(Debug)]
pub(super) struct ByteRateLimiter {
    bytes_per_second: AtomicU64,
    next: Mutex<Instant>,
}

impl ByteRateLimiter {
    pub(super) fn new(bytes_per_second: Option<u64>) -> Self {
        Self {
            bytes_per_second: AtomicU64::new(rate_value(bytes_per_second)),
            next: Mutex::new(Instant::now()),
        }
    }

    pub(super) fn set_rate(&self, bytes_per_second: Option<u64>) {
        let bytes_per_second = rate_value(bytes_per_second);
        let previous = self
            .bytes_per_second
            .swap(bytes_per_second, Ordering::Relaxed);
        if previous != bytes_per_second {
            *self.next.lock().expect("core limiter lock poisoned") = Instant::now();
        }
    }

    pub(super) async fn wait(&self, bytes: u64, control: &SessionControl) -> Result<()> {
        let rate = self.bytes_per_second.load(Ordering::Relaxed);
        if bytes == 0 || rate == 0 {
            return Ok(());
        }
        let wait_until = {
            let mut next = self.next.lock().expect("core limiter lock poisoned");
            let now = Instant::now();
            if *next < now {
                *next = now;
            }
            *next += Duration::from_secs_f64(bytes as f64 / rate as f64);
            *next
        };
        tokio::select! {
            _ = control.cancelled() => bail!("core session cancelled"),
            _ = tokio::time::sleep_until(wait_until) => Ok(()),
        }
    }
}

fn rate_value(bytes_per_second: Option<u64>) -> u64 {
    bytes_per_second.filter(|rate| *rate > 0).unwrap_or(0)
}
