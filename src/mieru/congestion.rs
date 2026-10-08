use std::time::Duration;
use tokio::time::Instant;

const MIN_WINDOW: f64 = 16.0;
const BETA: f64 = 0.7;
const C: f64 = 0.4;

// Packet-based CUBIC growth (RFC 9438), independent of the encrypted wire format.
// ACK credit counts newly delivered packets, never duplicate ACK messages.
pub(super) struct Cubic {
    window: f64,
    limit: f64,
    threshold: f64,
    last_max: f64,
    epoch: Option<(Instant, f64, f64)>,
    reno_window: f64,
    last_sent: Option<Instant>,
}

impl Cubic {
    pub(super) fn new(limit: usize) -> Self {
        Self {
            window: 32.0,
            limit: limit as f64,
            threshold: limit as f64,
            last_max: 0.0,
            epoch: None,
            reno_window: 32.0,
            last_sent: None,
        }
    }

    pub(super) fn window(&self) -> usize {
        self.window.floor() as usize
    }

    pub(super) fn sent(&mut self, now: Instant, in_flight: usize, rtt: Duration) {
        if in_flight == 0 {
            if let (Some(last), Some((start, _, _))) = (self.last_sent, &mut self.epoch) {
                let idle = now.duration_since(last).saturating_sub(rtt);
                *start += idle;
            }
        }
        self.last_sent = Some(now);
    }

    pub(super) fn ack(&mut self, count: usize, rtt: Duration, now: Instant, window_limited: bool) {
        if count == 0 || !window_limited {
            return;
        }
        if self.window < self.threshold {
            self.window = (self.window + count as f64)
                .min(self.threshold)
                .min(self.limit);
            return;
        }
        let (start, origin, k) = *self.epoch.get_or_insert_with(|| {
            self.reno_window = self.window;
            if self.last_max > self.window {
                (
                    now,
                    self.last_max,
                    ((self.last_max - self.window) / C).cbrt(),
                )
            } else {
                (now, self.window, 0.0)
            }
        });
        let time = now.duration_since(start).as_secs_f64() + rtt.as_secs_f64();
        let target = (origin + C * (time - k).powi(3))
            .max(self.window)
            .min(self.window * 1.5)
            .min(self.limit);
        let increase = (target - self.window) * count as f64 / self.window;
        let alpha = 3.0 * (1.0 - BETA) / (1.0 + BETA);
        self.reno_window += alpha * count as f64 / self.reno_window;
        self.window = (self.window + increase)
            .max(self.reno_window)
            .clamp(MIN_WINDOW, self.limit);
    }

    pub(super) fn loss(&mut self, timeout: bool) {
        let previous = self.window;
        self.last_max = if previous < self.last_max {
            previous * (1.0 + BETA) / 2.0
        } else {
            previous
        };
        self.threshold = (previous * BETA).max(MIN_WINDOW);
        self.window = if timeout { MIN_WINDOW } else { self.threshold };
        self.reno_window = self.window;
        self.epoch = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn congestion_growth_is_bounded_and_duplicate_or_idle_acks_give_no_credit() {
        let now = Instant::now();
        let rtt = Duration::from_millis(100);
        let mut cubic = Cubic::new(1024);
        cubic.ack(200, rtt, now, false);
        assert_eq!(cubic.window(), 32);
        cubic.ack(0, rtt, now, true);
        assert_eq!(cubic.window(), 32);
        cubic.ack(5000, rtt, now, true);
        assert_eq!(cubic.window(), 1024);
        cubic.loss(false);
        assert!((716..=717).contains(&cubic.window()));
        for second in 0..120 {
            cubic.ack(1024, rtt, now + Duration::from_secs(second), true);
            assert!((16..=1024).contains(&cubic.window()));
        }
        cubic.loss(true);
        assert_eq!(cubic.window(), 16);
    }

    #[test]
    fn idle_time_cannot_jump_the_cubic_window_after_a_loss() {
        let now = Instant::now();
        let rtt = Duration::from_millis(100);
        let mut active = Cubic::new(1024);
        let mut idle = Cubic::new(1024);
        for cubic in [&mut active, &mut idle] {
            cubic.ack(200, rtt, now, true);
            cubic.loss(false);
            cubic.ack(1, rtt, now, true);
            cubic.sent(now, 0, rtt);
        }
        active.sent(now + rtt, 0, rtt);
        active.ack(1, rtt, now + rtt, true);
        idle.sent(now + rtt + Duration::from_secs(60), 0, rtt);
        idle.ack(1, rtt, now + rtt + Duration::from_secs(60), true);
        assert_eq!(active.window(), idle.window());
    }
}
