//! Anti-replay state for the server side (spec §8).
//!
//! The reference impl uses a fixed-size hash set of recently-seen
//! `(client_nonce, timestamp)` pairs. Production deployments are expected
//! to use a true sliding Bloom (spec §8.1); this implementation has the
//! same API surface so the swap is a constant change.

use std::collections::BTreeSet;
use std::time::Duration;

use proteus_spec::TIMESTAMP_WINDOW_SECS;

/// Maximum number of `(client_nonce, timestamp)` records kept in the
/// reference impl set. ~256 KiB at this size.
pub const REFERENCE_SET_CAPACITY: usize = 1 << 16;

/// Anti-replay verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// First time we have seen this `(nonce, ts)` pair, and `ts` is fresh.
    Accept,
    /// Already-seen pair. Per spec §7.5 / §11.16, caller MUST forward to cover.
    Replay,
    /// Timestamp skew exceeds [`TIMESTAMP_WINDOW_SECS`]. Per spec §8.2, forward.
    Stale,
}

/// Reference replay detector.
pub struct ReplayWindow {
    seen: BTreeSet<([u8; 16], u64)>,
    capacity: usize,
}

impl ReplayWindow {
    /// Create a detector with [`REFERENCE_SET_CAPACITY`] slots.
    #[must_use]
    pub fn new() -> Self {
        Self {
            seen: BTreeSet::new(),
            capacity: REFERENCE_SET_CAPACITY,
        }
    }

    /// Check + insert. Returns [`Verdict::Accept`] iff the pair is new
    /// AND the timestamp is within `TIMESTAMP_WINDOW_SECS` of `now`.
    pub fn check(
        &mut self,
        now_unix_seconds: u64,
        client_nonce: &[u8; 16],
        timestamp_unix_seconds: u64,
    ) -> Verdict {
        let skew = now_unix_seconds.abs_diff(timestamp_unix_seconds);
        if skew > TIMESTAMP_WINDOW_SECS {
            return Verdict::Stale;
        }
        let key = (*client_nonce, timestamp_unix_seconds);
        if self.seen.contains(&key) {
            return Verdict::Replay;
        }
        if self.seen.len() >= self.capacity {
            // Reference policy: drop the smallest element (BTreeSet's first()).
            if let Some(first) = self.seen.iter().next().copied() {
                self.seen.remove(&first);
            }
        }
        self.seen.insert(key);
        Verdict::Accept
    }

    /// Number of currently-tracked pairs (for telemetry).
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Whether the detector is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert a [`Duration`] to whole unix seconds.
#[must_use]
pub fn duration_to_unix_seconds(d: Duration) -> u64 {
    d.as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_use_accepted() {
        let mut win = ReplayWindow::new();
        let now = 1_700_000_000u64;
        assert_eq!(win.check(now, &[0u8; 16], now), Verdict::Accept);
    }

    #[test]
    fn second_use_replay() {
        let mut win = ReplayWindow::new();
        let now = 1_700_000_000u64;
        let nonce = [0xabu8; 16];
        assert_eq!(win.check(now, &nonce, now), Verdict::Accept);
        assert_eq!(win.check(now, &nonce, now), Verdict::Replay);
    }

    #[test]
    fn skewed_timestamp_rejected() {
        let mut win = ReplayWindow::new();
        let now = 1_700_000_000u64;
        let stale = now - TIMESTAMP_WINDOW_SECS - 1;
        assert_eq!(win.check(now, &[0u8; 16], stale), Verdict::Stale);

        let future = now + TIMESTAMP_WINDOW_SECS + 1;
        assert_eq!(win.check(now, &[1u8; 16], future), Verdict::Stale);
    }

    #[test]
    fn within_window_accepted() {
        let mut win = ReplayWindow::new();
        let now = 1_700_000_000u64;
        // Just inside the boundary.
        let edge = now - TIMESTAMP_WINDOW_SECS;
        assert_eq!(win.check(now, &[0u8; 16], edge), Verdict::Accept);
    }

    #[test]
    fn different_nonces_independent() {
        let mut win = ReplayWindow::new();
        let now = 1_700_000_000u64;
        assert_eq!(win.check(now, &[0u8; 16], now), Verdict::Accept);
        assert_eq!(win.check(now, &[1u8; 16], now), Verdict::Accept);
    }
}
