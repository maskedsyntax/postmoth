//! Time source abstraction.
//!
//! Expiry checks use **both** a monotonic and a wall-clock reading. On Linux
//! `Instant` is `CLOCK_MONOTONIC`, which does not advance while suspended, so
//! a code captured before a suspend would look fresh on resume if we used it
//! alone. The wall clock can jump either way. A candidate is expired if
//! **either** clock says so, or if the wall clock moved backwards.

use std::time::{Duration, Instant, SystemTime};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timestamp {
    pub mono: Instant,
    pub wall: SystemTime,
}

impl Timestamp {
    /// Has more than `ttl` elapsed between `self` and `now`, by either clock?
    #[must_use]
    pub fn elapsed_exceeds(&self, now: &Timestamp, ttl: Duration) -> bool {
        let mono = now.mono.saturating_duration_since(self.mono);
        let wall = match now.wall.duration_since(self.wall) {
            Ok(d) => d,
            // Wall clock went backwards: fail closed.
            Err(_) => return true,
        };
        mono > ttl || wall > ttl
    }

    #[must_use]
    pub fn plus(&self, d: Duration) -> Self {
        Self {
            mono: self.mono + d,
            wall: self.wall + d,
        }
    }
}

pub trait Clock: Send + Sync {
    fn now(&self) -> Timestamp;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        Timestamp {
            mono: Instant::now(),
            wall: SystemTime::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suspend_is_caught_by_wall_clock() {
        let t0 = SystemClock.now();
        // Simulate suspend: monotonic barely moves, wall clock moves 1h.
        let t1 = Timestamp {
            mono: t0.mono + Duration::from_secs(1),
            wall: t0.wall + Duration::from_secs(3600),
        };
        assert!(t0.elapsed_exceeds(&t1, Duration::from_secs(300)));
    }

    #[test]
    fn wall_clock_rewind_fails_closed() {
        let t0 = SystemClock.now();
        let t1 = Timestamp {
            mono: t0.mono + Duration::from_secs(1),
            wall: t0.wall - Duration::from_secs(60),
        };
        assert!(t0.elapsed_exceeds(&t1, Duration::from_secs(300)));
    }

    #[test]
    fn fresh_is_not_expired() {
        let t0 = SystemClock.now();
        let t1 = t0.plus(Duration::from_secs(10));
        assert!(!t0.elapsed_exceeds(&t1, Duration::from_secs(300)));
    }
}
