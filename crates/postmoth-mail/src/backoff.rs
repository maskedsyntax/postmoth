//! Exponential backoff with jitter for reconnects (spec §7.2: avoid
//! aggressive reconnection loops).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct Backoff {
    base: Duration,
    max: Duration,
    attempt: u32,
}

impl Backoff {
    #[must_use]
    pub fn new(base: Duration, max: Duration) -> Self {
        Self {
            base,
            max,
            attempt: 0,
        }
    }

    /// Defaults suitable for IMAP reconnects: 5 s doubling up to 15 min.
    #[must_use]
    pub fn for_reconnect() -> Self {
        Self::new(Duration::from_secs(5), Duration::from_secs(15 * 60))
    }

    /// Delay before the next attempt: `base * 2^attempt`, capped, with
    /// "equal jitter" (between half and full of the capped value).
    pub fn next_delay(&mut self) -> Duration {
        let exp = self.attempt.min(20);
        self.attempt = self.attempt.saturating_add(1);
        let raw = self.base.saturating_mul(1u32 << exp).min(self.max);
        let half = raw / 2;
        let jitter_ns = u64::try_from(half.as_nanos()).unwrap_or(u64::MAX);
        let r = if jitter_ns == 0 {
            0
        } else {
            cheap_random() % jitter_ns
        };
        half + Duration::from_nanos(r)
    }

    pub fn reset(&mut self) {
        self.attempt = 0;
    }

    #[must_use]
    pub fn attempts(&self) -> u32 {
        self.attempt
    }
}

/// Jitter source; does not need to be cryptographic.
fn cheap_random() -> u64 {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    // splitmix64 finalizer
    let mut z = u64::from(n).wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grows_and_caps() {
        let mut b = Backoff::new(Duration::from_secs(1), Duration::from_secs(60));
        let d0 = b.next_delay();
        assert!(d0 >= Duration::from_millis(500) && d0 <= Duration::from_secs(1));
        for _ in 0..30 {
            let d = b.next_delay();
            assert!(d <= Duration::from_secs(60));
        }
        let d = b.next_delay();
        assert!(d >= Duration::from_secs(30), "stays near cap: {d:?}");
        b.reset();
        assert!(b.next_delay() <= Duration::from_secs(1));
    }
}
