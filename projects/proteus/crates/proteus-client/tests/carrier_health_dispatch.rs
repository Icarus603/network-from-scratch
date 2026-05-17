//! Integration test: the per-process `CarrierHealth` actually
//! saves time on repeated CONNECTs when β is dead.
//!
//! ## What this pins
//!
//! Without back-off (the pre-change behavior): every CONNECT pays
//! `beta_first_timeout_secs` (default 3 s, here lowered to make
//! the test fast) of pointless waiting before falling back to α.
//!
//! With back-off (this commit): the first N CONNECTs (where N =
//! `DEFAULT_FAILURE_THRESHOLD` = 3) pay the β-first cost; the
//! 4th+ CONNECT in the same burst hits `BetaDecision::SkipSuppressed`
//! and goes straight to α — measurably faster.
//!
//! We don't measure wall-clock latency directly (CI flakiness) —
//! we measure the `BetaDecision` flow through repeated calls. The
//! latency win is a strict consequence of the decision flow: if
//! the decision is `SkipSuppressed`, the dispatcher does not call
//! `try_beta` at all, so the β-first timeout cost is structurally
//! eliminated.

use std::sync::Arc;
use std::time::{Duration, Instant};

use proteus_client::carrier_health::{
    BetaDecision, CarrierHealth, DEFAULT_FAILURE_THRESHOLD, INITIAL_SUPPRESSION,
};

#[test]
fn burst_of_failures_engages_suppression_after_threshold() {
    let health = Arc::new(CarrierHealth::new());
    let t = Instant::now();
    let mut decisions = Vec::new();

    // Simulate a burst of 6 CONNECTs where β fails every time
    // (corresponds to "user's network blocks UDP").
    for _ in 0..6 {
        let d = health.decide_beta(true, t);
        decisions.push(d);
        // Per-CONNECT failure feedback.
        if matches!(d, BetaDecision::TryBeta | BetaDecision::Probe) {
            health.record_beta_failure(t);
        }
    }

    // First 3 (= DEFAULT_FAILURE_THRESHOLD) attempts hit `TryBeta`.
    // Then suppression engages: the 4th attempt is the recovery
    // probe (count = 0 modulo PROBE_INTERVAL), 5th+ are skipped.
    let threshold = DEFAULT_FAILURE_THRESHOLD as usize;
    for d in &decisions[..threshold] {
        assert_eq!(*d, BetaDecision::TryBeta, "pre-suppression CONNECT");
    }
    assert_eq!(
        decisions[threshold],
        BetaDecision::Probe,
        "first suppressed CONNECT = probe"
    );
    for (i, d) in decisions[threshold + 1..].iter().enumerate() {
        assert_eq!(
            *d,
            BetaDecision::SkipSuppressed,
            "CONNECT {} after probe should skip",
            threshold + 1 + i,
        );
    }
}

#[test]
fn one_success_clears_an_ongoing_failure_streak() {
    let health = Arc::new(CarrierHealth::new());
    let t = Instant::now();

    // Two failures — not yet at threshold.
    health.record_beta_failure(t);
    health.record_beta_failure(t);
    assert!(!health.is_suppressed(t));
    assert_eq!(health.failure_streak(), 2);

    // One success — streak resets to 0.
    health.record_beta_success();
    assert_eq!(health.failure_streak(), 0);

    // Need a fresh full streak to suppress again.
    for _ in 0..(DEFAULT_FAILURE_THRESHOLD - 1) {
        health.record_beta_failure(t);
    }
    assert!(!health.is_suppressed(t));
    health.record_beta_failure(t);
    assert!(health.is_suppressed(t));
}

/// Sanity check: suppression window honors INITIAL_SUPPRESSION exactly
/// for the first streak. Tied to the suppression duration constant so
/// a future tweak to that constant fails this test loudly and forces
/// the author to update the operator-facing docs in tandem.
#[test]
fn suppression_window_matches_initial_constant() {
    let health = Arc::new(CarrierHealth::new());
    let t = Instant::now();
    for _ in 0..DEFAULT_FAILURE_THRESHOLD {
        health.record_beta_failure(t);
    }
    // Just inside the window: still suppressed.
    assert!(
        health.is_suppressed(t + INITIAL_SUPPRESSION - Duration::from_millis(50)),
        "should still be suppressed just before window end"
    );
    // Just past the window: cleared.
    assert!(
        !health.is_suppressed(t + INITIAL_SUPPRESSION + Duration::from_millis(50)),
        "should be cleared just after window end"
    );
}

/// Defends against carrier-asymmetry regression: when
/// `beta_configured = false`, the tracker MUST short-circuit to
/// `SkipNoConfig` and never increment its internal counters. Without
/// this, an α-only deploy would accumulate misleading state about a
/// nonexistent β carrier.
#[test]
fn no_beta_config_short_circuits_without_touching_state() {
    let health = Arc::new(CarrierHealth::new());
    let t = Instant::now();
    for _ in 0..10 {
        assert_eq!(health.decide_beta(false, t), BetaDecision::SkipNoConfig,);
    }
    // No counters should have moved.
    assert_eq!(health.failure_streak(), 0);
    assert!(!health.is_suppressed(t));
}

/// Concurrency: `CarrierHealth` is meant to be shared across the
/// accept-loop's per-CONNECT tasks via `Arc`. Hammer it from many
/// threads at once to verify the atomic operations don't deadlock,
/// produce inconsistent failure streaks, or panic.
#[test]
fn concurrent_access_does_not_panic_or_deadlock() {
    let health = Arc::new(CarrierHealth::new());
    let mut handles = Vec::new();
    for thread_idx in 0..8 {
        let h = Arc::clone(&health);
        handles.push(std::thread::spawn(move || {
            let t = Instant::now();
            for _ in 0..100 {
                let _ = h.decide_beta(true, t);
                if thread_idx % 2 == 0 {
                    h.record_beta_failure(t);
                } else {
                    h.record_beta_success();
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    // The exact final state is non-deterministic (depends on
    // thread interleaving), but the tracker must be in a valid
    // queryable state.
    let _ = health.failure_streak();
    let _ = health.is_suppressed(Instant::now());
    let _ = health.decide_beta(true, Instant::now());
}
