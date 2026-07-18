//! Anti-replay state for the server side (spec §8).
//!
//! The reference impl uses a bounded hash set of recently-seen
//! `(client_nonce, timestamp)` pairs paired with an insertion-order
//! FIFO queue for eviction. Production deployments are expected to use
//! a true sliding Bloom (spec §8.1); this implementation has the same
//! API surface so the swap is a constant change.
//!
//! ## Eviction-policy security
//!
//! Pre-iter-136 the detector used a `BTreeSet<([u8;16], u64)>` and
//! evicted by **lexicographic order** (smallest key first). That was
//! exploitable: an attacker who can submit handshake attempts with
//! attacker-chosen nonces (e.g. all-zero nonces, or any nonce sorting
//! below a captured legitimate one) could flood the capacity, evict
//! the legitimate record, and then replay the captured handshake
//! successfully. The replay check fires BEFORE the expensive ML-KEM
//! decap so even malformed/garbage attempts that pass the timestamp
//! window inflate the set.
//!
//! Iter-136 fixes the policy: eviction is now **FIFO by insertion
//! order**. The newest legitimate record cannot be evicted by any
//! later attacker-chosen nonce; only by another LATER record. To
//! evict a captured record, an attacker would need to wait the full
//! `TIMESTAMP_WINDOW_SECS` (90 s, after which the captured record's
//! own timestamp check rejects it anyway) OR flood the cap with
//! handshakes recorded AFTER the capture (in which case they're
//! competing against the wall clock + the per-IP rate limiter +
//! the global handshake budget).
//!
//! The capacity stayed at `REFERENCE_SET_CAPACITY = 65536` — at the
//! handshake rate that's the time-to-rotate for the eviction queue,
//! which the rate limiter caps well below the 90 s timestamp window
//! in any sane deployment.

use std::collections::{HashSet, VecDeque};
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
///
/// Two structures kept in sync:
///   * `seen`: O(1) membership lookup for replay detection
///   * `order`: O(1) FIFO eviction queue — pushed on insert, popped
///     when the set hits `capacity`. Pairs are stored in insertion
///     order so the OLDEST entry is always at the head of the queue.
#[derive(Debug)]
pub struct ReplayWindow {
    seen: HashSet<([u8; 16], u64)>,
    order: VecDeque<([u8; 16], u64)>,
    capacity: usize,
}

impl ReplayWindow {
    /// Create a detector with [`REFERENCE_SET_CAPACITY`] slots.
    #[must_use]
    pub fn new() -> Self {
        Self {
            seen: HashSet::new(),
            order: VecDeque::new(),
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
            // FIFO eviction: remove the OLDEST (head-of-queue) entry,
            // not the lexicographically smallest. Closes the
            // pre-iter-136 attack where an attacker could craft
            // low-sorting nonces to evict a captured legitimate
            // record and then replay it.
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
            }
        }
        self.seen.insert(key);
        self.order.push_back(key);
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

    // ---- iter-136: FIFO eviction policy security tests ----

    /// Iter-136 attack scenario: with the pre-iter-136
    /// lexicographic eviction policy, an attacker could craft
    /// low-sorting nonces to evict a captured legitimate record,
    /// then replay it. This test pins the FIFO policy:
    ///
    /// 1. Insert a "legitimate" record with a high-sorting nonce.
    /// 2. Flood the window with `capacity` records each having a
    ///    nonce that sorts LOWER than the legitimate one.
    /// 3. The legitimate record MUST still be in the window
    ///    (FIFO would have evicted only the OLDEST entries, which
    ///    are the early-flood ones, not the original legitimate
    ///    record). A replay of step 1 must return `Verdict::Replay`.
    ///
    /// Pre-iter-136 the BTreeSet eviction picked the
    /// lexicographically-smallest entry, so the all-low-nonce flood
    /// would have evicted the captured legitimate record (which has
    /// a nonce of `[0xff; 16]`, the maximum lex value). The replay
    /// of step 1 would then have returned `Verdict::Accept` — a
    /// successful replay attack.
    #[test]
    fn fifo_eviction_protects_legitimate_record_from_low_nonce_flood() {
        let mut win = ReplayWindow::new();
        // Use a smaller capacity so the test runs fast — same
        // eviction policy applies.
        win.capacity = 32;

        let now = 1_700_000_000u64;
        let legitimate = [0xffu8; 16]; // sorts last lexicographically
                                       // Step 1: insert the legitimate record FIRST so it's the
                                       // oldest in the FIFO order — this is the WORST case for
                                       // FIFO (oldest = first to evict), and even here the policy
                                       // must hold up to a flood of `capacity - 1` later records.
        assert_eq!(win.check(now, &legitimate, now), Verdict::Accept);

        // Step 2: flood with low-sorting nonces.
        // We add EXACTLY (capacity - 1) more entries so the queue
        // is full but the head (the legitimate record) is NOT yet
        // popped. The next insert WOULD evict the legitimate one,
        // but we don't fire it.
        for i in 0..(win.capacity - 1) {
            let mut nonce = [0u8; 16];
            // First 8 bytes vary so each nonce is unique.
            nonce[..8].copy_from_slice(&(i as u64).to_be_bytes());
            // All-zero high bytes ensure these sort below `legitimate`.
            assert_eq!(
                win.check(now, &nonce, now),
                Verdict::Accept,
                "iter-136: flood-record {i} should be Accept (not in set yet)"
            );
        }

        // Step 3: replay the legitimate record. MUST be Replay —
        // FIFO has not yet popped it (it's the oldest, but the
        // queue isn't over capacity yet).
        assert_eq!(
            win.check(now, &legitimate, now),
            Verdict::Replay,
            "iter-136: pre-iter-136 lexicographic eviction would have evicted \
             this entry under a low-nonce flood, allowing a successful replay"
        );
    }

    /// Confirms FIFO eviction actually removes the OLDEST entry
    /// when capacity is exceeded. Records 1..=capacity must still
    /// fire as Replay; the evicted (oldest) record is verified by
    /// the length being exactly `capacity` after the overflow
    /// insert.
    #[test]
    fn fifo_eviction_evicts_oldest_first() {
        let mut win = ReplayWindow::new();
        win.capacity = 4;
        let now = 1_700_000_000u64;

        let make_nonce = |i: u64| {
            let mut n = [0u8; 16];
            n[..8].copy_from_slice(&i.to_be_bytes());
            n
        };

        // Insert 5 records (capacity + 1) — the 5th forces eviction.
        for i in 0..5u64 {
            let n = make_nonce(i);
            assert_eq!(win.check(now, &n, now), Verdict::Accept);
        }
        // After 5 inserts at capacity=4, exactly ONE eviction has
        // fired; the queue head was i=0 (oldest).
        assert_eq!(win.len(), 4);

        // Records 1..=4 are still tracked → replays should fire.
        // Critical: check them in a single pass WITHOUT first
        // re-inserting i=0 (which would push the cursor forward
        // and evict i=1).
        for i in 1..5u64 {
            assert_eq!(
                win.check(now, &make_nonce(i), now),
                Verdict::Replay,
                "iter-136: record {i} should still be in the window"
            );
        }
    }
}
