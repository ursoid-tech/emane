//! The virtual transport's shared, one-second bit-rate budget.
use std::sync::{Condvar, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Default)]
pub struct BitPoolState {
    maximum: u64,
    available: u64,
    last_request_us: i64,
    remainder: f32,
}

impl BitPoolState {
    pub fn set_max_size(&mut self, maximum: u64) {
        self.available = self.available.min(maximum);
        self.maximum = maximum;
    }

    /// Drain at a supplied clock time. Returns acquired bits and the wait in us.
    /// The original uses single precision for fractional refill and wait ratios.
    pub fn drain_at(&mut self, request: u64, now_us: i64) -> (u64, u64) {
        if self.maximum == 0 || request == 0 {
            return (request, 0);
        }
        if self.last_request_us != 0 {
            let elapsed = now_us.saturating_sub(self.last_request_us);
            if elapsed >= 1_000_000 {
                self.available = self.maximum;
                self.remainder = 0.0;
            } else {
                self.remainder += (elapsed as f32 / 1_000_000.0) * self.maximum as f32;
                if self.remainder >= 1.0 {
                    let fill = self.remainder as u64;
                    self.available = self.available.saturating_add(fill).min(self.maximum);
                    self.remainder -= fill as f32;
                }
            }
        }
        let acquired = request.min(self.available);
        let wait_us = if request > self.available {
            let seconds = (request - self.available) as f32 / self.maximum as f32;
            ((f64::from(seconds) * 1_000_000.0) as u64).min(1_000_000)
        } else {
            0
        };
        self.available -= acquired;
        self.last_request_us = now_us;
        (acquired, wait_us)
    }

    pub fn snapshot(&self) -> (u64, u32) {
        (self.available, self.remainder.to_bits())
    }
}

#[derive(Default)]
pub struct BitPool {
    state: Mutex<BitPoolState>,
    canceled: Mutex<bool>,
    wake: Condvar,
}

fn now_us() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros()
        .min(i64::MAX as u128) as i64
}

impl BitPool {
    pub fn start(&self, maximum: u64) {
        self.state.lock().unwrap().set_max_size(maximum);
        *self.canceled.lock().unwrap() = false;
    }

    pub fn cancel(&self) {
        *self.canceled.lock().unwrap() = true;
        self.wake.notify_all();
    }

    pub fn get(&self, mut bits: u64) {
        // Like the original, serialize whole requests across both directions,
        // including refill waits. A separate cancellation lock wakes stop().
        let mut state = self.state.lock().unwrap();
        while bits != 0 {
            let mut canceled = self.canceled.lock().unwrap();
            if *canceled {
                return;
            }
            let requested_at = now_us();
            let (acquired, wait_us) = state.drain_at(bits, requested_at);
            bits -= acquired;
            if bits == 0 {
                return;
            }
            let deadline = requested_at.saturating_add(wait_us as i64);
            while !*canceled {
                let remaining = deadline.saturating_sub(now_us());
                if remaining <= 0 {
                    break;
                }
                canceled = self
                    .wake
                    .wait_timeout(canceled, Duration::from_micros(remaining as u64))
                    .unwrap()
                    .0;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_idle_capacity_and_fractional_refill() {
        let mut pool = BitPoolState::default();
        pool.set_max_size(8);
        assert_eq!(pool.drain_at(1, 100), (0, 125_000));
        assert_eq!(pool.drain_at(1, 62_600), (0, 125_000));
        assert_eq!(pool.drain_at(1, 125_100), (1, 0));
        assert_eq!(pool.drain_at(3, 1_125_100), (3, 0));
        assert_eq!(pool.snapshot().0, 5);
        pool.set_max_size(2);
        assert_eq!(pool.drain_at(3, 1_125_100), (2, 500_000));
    }

    #[test]
    fn cancel_wakes_a_long_refill_wait() {
        let pool = std::sync::Arc::new(BitPool::default());
        pool.start(1);
        let (sent, received) = std::sync::mpsc::channel();
        let reader = pool.clone();
        let thread = std::thread::spawn(move || {
            reader.get(1_000_000);
            sent.send(()).unwrap();
        });
        assert!(received.recv_timeout(Duration::from_millis(20)).is_err());
        pool.cancel();
        received.recv_timeout(Duration::from_secs(1)).unwrap();
        thread.join().unwrap();
    }
}
