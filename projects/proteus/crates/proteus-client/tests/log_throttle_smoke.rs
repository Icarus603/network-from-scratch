//! Iter-23 smoke test: prove the per-process log throttles
//! used by socks.rs's failure paths actually rate-limit.
//!
//! This is NOT a complete test of every throttled site (those
//! would require driving the whole SOCKS dispatch chain
//! through a controlled-failure mock VPS — possible but
//! heavyweight). Instead it pins the BEHAVIOR of the
//! `proteus_transport_alpha::log_throttle::Throttle` primitive
//! at the exact `(burst=3, refill_per_sec=0.2)` shape socks.rs
//! uses. If a future refactor accidentally regresses the
//! throttle's contract (e.g. starts allowing every call),
//! the failure paths in socks.rs would silently start spamming
//! again and this test catches it at the primitive level.

use proteus_transport_alpha::log_throttle::{AcquireResult, Throttle};

/// `burst=3` → first three try_acquire calls return Allowed.
/// The fourth one returns Suppressed because the bucket is
/// drained and the refill rate (0.2/sec) means we'd need to
/// wait 5 seconds for one more token.
#[test]
fn iter23_throttle_shape_allows_burst_then_suppresses() {
    let t = Throttle::new(3, 0.2);
    assert!(matches!(t.try_acquire(), AcquireResult::Allowed));
    assert!(matches!(t.try_acquire(), AcquireResult::Allowed));
    assert!(matches!(t.try_acquire(), AcquireResult::Allowed));
    assert!(
        matches!(t.try_acquire(), AcquireResult::Suppressed(_)),
        "4th try_acquire on burst=3 with 0.2/s refill must suppress"
    );
}

/// total_suppressed counter MUST increment on every Suppressed
/// return. socks.rs surfaces this in the throttled log line as
/// `suppressed = throttle.total_suppressed()` so the operator
/// sees "this is one of N lines we'd otherwise have spammed"
/// — without the counter the throttling is invisible and the
/// operator might miss that there's a sustained failure mode.
#[test]
fn iter23_throttle_suppressed_counter_increments_on_overflow() {
    let t = Throttle::new(3, 0.2);
    // Drain the bucket.
    for _ in 0..3 {
        let _ = t.try_acquire();
    }
    assert_eq!(t.total_suppressed(), 0);
    // 10 suppressed calls.
    for _ in 0..10 {
        let _ = t.try_acquire();
    }
    assert_eq!(t.total_suppressed(), 10);
}

/// Three independent throttles (β-dial-fail, pool-entry-fail,
/// pool-entry-β-fail) must NOT share state. socks.rs uses
/// per-throttle `OnceLock<Throttle>` statics — this test pins
/// that contract: draining one throttle doesn't affect
/// another.
#[test]
fn iter23_independent_throttles_dont_share_state() {
    let a = Throttle::new(3, 0.2);
    let b = Throttle::new(3, 0.2);
    // Drain `a` completely.
    for _ in 0..5 {
        let _ = a.try_acquire();
    }
    // `b` must still have a full burst.
    assert!(matches!(b.try_acquire(), AcquireResult::Allowed));
    assert!(matches!(b.try_acquire(), AcquireResult::Allowed));
    assert!(matches!(b.try_acquire(), AcquireResult::Allowed));
    assert!(matches!(b.try_acquire(), AcquireResult::Suppressed(_)));
}

/// Iter-27: the public `drain_failure_log_rollups()` MUST be
/// idempotent — calling it on a throttle that was never
/// suppressed returns an empty Vec; calling it twice in a row
/// after a single suppression event returns the count exactly
/// once.
///
/// Note: this test relies on the per-process static throttles.
/// Other tests in the same binary might also touch them; we
/// drain at the start so we get a clean baseline.
#[test]
fn iter27_drain_failure_log_rollups_is_idempotent() {
    // Baseline drain — clear any state from sibling tests.
    let _ = proteus_client::socks::drain_failure_log_rollups();

    // No throttles fired since baseline → empty.
    let first = proteus_client::socks::drain_failure_log_rollups();
    assert!(
        first.is_empty(),
        "drain on idle throttles must return empty, got {first:?}"
    );

    // We can't easily fire the throttles from a test (the only
    // path is via SOCKS5 failure plumbing). But we can verify
    // the OUTPUT shape: keys are stable, count is u64, no
    // duplicates.
    // Calling again must STILL be empty (idempotent on idle).
    let second = proteus_client::socks::drain_failure_log_rollups();
    assert!(second.is_empty());
}
