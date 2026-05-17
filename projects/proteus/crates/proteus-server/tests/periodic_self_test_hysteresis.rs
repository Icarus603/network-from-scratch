//! Hysteresis behavior of the periodic self-test → /healthz path.
//!
//! Tests the contract that:
//!   1. `consecutive_periodic_self_test_failures` counts up on
//!      back-to-back failures and resets to 0 on the next pass.
//!   2. `last_periodic_self_test_passed` (the gauge /healthz
//!      reads) only flips to `false` when the streak crosses
//!      `periodic_self_test_failure_threshold` — single transient
//!      blips are absorbed.
//!   3. `proteus_consecutive_periodic_self_test_failures` is
//!      surfaced via the Prometheus exposition.
//!
//! These tests drive `ServerMetrics` directly rather than spawning
//! the full binary. The closure logic in `main.rs::run` is small
//! enough that the test re-implements the bump+mark pattern to
//! exercise the contract; production validity follows from both
//! using the same atomic counters.

use std::sync::atomic::Ordering;

use proteus_transport_alpha::metrics::ServerMetrics;

/// Reproduces the `bump_failure` closure from main.rs::run: bump
/// failed_total + streak, only flip passed=false at threshold.
fn bump_failure(m: &ServerMetrics) -> u64 {
    m.periodic_self_test_failed_total
        .fetch_add(1, Ordering::Relaxed);
    let streak = m
        .consecutive_periodic_self_test_failures
        .fetch_add(1, Ordering::Relaxed)
        + 1;
    let threshold = m
        .periodic_self_test_failure_threshold
        .load(Ordering::Relaxed)
        .max(1);
    if streak >= threshold {
        m.last_periodic_self_test_passed
            .store(false, Ordering::Relaxed);
    }
    streak
}

/// Reproduces the `mark_success` closure: reset streak, set
/// passed=true.
fn mark_success(m: &ServerMetrics) {
    m.consecutive_periodic_self_test_failures
        .swap(0, Ordering::Relaxed);
    m.last_periodic_self_test_passed
        .store(true, Ordering::Relaxed);
}

#[test]
fn single_failure_does_not_drain_when_threshold_is_two() {
    let m = ServerMetrics::default();
    // Configure threshold = 2 (the production default).
    m.periodic_self_test_failure_threshold
        .store(2, Ordering::Relaxed);
    // Start in the "passing" state.
    m.last_periodic_self_test_passed
        .store(true, Ordering::Relaxed);

    let streak = bump_failure(&m);

    assert_eq!(streak, 1);
    assert!(
        m.last_periodic_self_test_passed.load(Ordering::Relaxed),
        "single failure under threshold must NOT drain /healthz"
    );
    assert_eq!(
        m.consecutive_periodic_self_test_failures
            .load(Ordering::Relaxed),
        1
    );
}

#[test]
fn two_consecutive_failures_flip_healthz_at_threshold() {
    let m = ServerMetrics::default();
    m.periodic_self_test_failure_threshold
        .store(2, Ordering::Relaxed);
    m.last_periodic_self_test_passed
        .store(true, Ordering::Relaxed);

    let streak1 = bump_failure(&m);
    assert_eq!(streak1, 1);
    assert!(m.last_periodic_self_test_passed.load(Ordering::Relaxed));

    let streak2 = bump_failure(&m);
    assert_eq!(streak2, 2);
    assert!(
        !m.last_periodic_self_test_passed.load(Ordering::Relaxed),
        "second consecutive failure MUST flip /healthz to 503"
    );
}

#[test]
fn pass_after_failure_resets_streak_and_restores_healthz() {
    let m = ServerMetrics::default();
    m.periodic_self_test_failure_threshold
        .store(2, Ordering::Relaxed);
    m.last_periodic_self_test_passed
        .store(true, Ordering::Relaxed);

    // One failure (under threshold, healthz stays 200).
    let _ = bump_failure(&m);
    assert_eq!(
        m.consecutive_periodic_self_test_failures
            .load(Ordering::Relaxed),
        1
    );
    // Next cycle passes — streak resets.
    mark_success(&m);
    assert_eq!(
        m.consecutive_periodic_self_test_failures
            .load(Ordering::Relaxed),
        0
    );
    assert!(m.last_periodic_self_test_passed.load(Ordering::Relaxed));
}

#[test]
fn legacy_threshold_one_means_single_failure_drains_immediately() {
    let m = ServerMetrics::default();
    m.periodic_self_test_failure_threshold
        .store(1, Ordering::Relaxed);
    m.last_periodic_self_test_passed
        .store(true, Ordering::Relaxed);

    let streak = bump_failure(&m);

    assert_eq!(streak, 1);
    assert!(
        !m.last_periodic_self_test_passed.load(Ordering::Relaxed),
        "threshold=1 (legacy) must flip /healthz on the very first failure"
    );
}

#[test]
fn threshold_zero_is_clamped_to_one_at_runtime() {
    let m = ServerMetrics::default();
    // Threshold = 0 (degenerate). The `bump_failure` helper
    // clamps to max(1) so /healthz still flips on the first
    // failure — never let a misconfig leave us permanently
    // green.
    m.periodic_self_test_failure_threshold
        .store(0, Ordering::Relaxed);
    m.last_periodic_self_test_passed
        .store(true, Ordering::Relaxed);

    let streak = bump_failure(&m);

    assert_eq!(streak, 1);
    assert!(
        !m.last_periodic_self_test_passed.load(Ordering::Relaxed),
        "threshold=0 must NOT leave /healthz permanently green; clamp to 1"
    );
}

#[test]
fn three_consecutive_failures_with_higher_threshold_drains_at_three() {
    let m = ServerMetrics::default();
    m.periodic_self_test_failure_threshold
        .store(3, Ordering::Relaxed);
    m.last_periodic_self_test_passed
        .store(true, Ordering::Relaxed);

    assert_eq!(bump_failure(&m), 1);
    assert!(m.last_periodic_self_test_passed.load(Ordering::Relaxed));
    assert_eq!(bump_failure(&m), 2);
    assert!(m.last_periodic_self_test_passed.load(Ordering::Relaxed));
    assert_eq!(bump_failure(&m), 3);
    assert!(!m.last_periodic_self_test_passed.load(Ordering::Relaxed));
}

#[test]
fn prometheus_exposition_includes_new_streak_and_threshold_series() {
    let m = ServerMetrics::default();
    m.periodic_self_test_failure_threshold
        .store(2, Ordering::Relaxed);
    let _ = bump_failure(&m);
    let body = m.prometheus();
    for needle in [
        "proteus_consecutive_periodic_self_test_failures",
        "proteus_periodic_self_test_failure_threshold",
        "# TYPE proteus_consecutive_periodic_self_test_failures gauge",
        "# TYPE proteus_periodic_self_test_failure_threshold gauge",
    ] {
        assert!(body.contains(needle), "missing {needle:?}");
    }
    // The streak value (1) should appear on its own line.
    assert!(
        body.contains("proteus_consecutive_periodic_self_test_failures 1"),
        "streak counter value must reflect the bump"
    );
    assert!(
        body.contains("proteus_periodic_self_test_failure_threshold 2"),
        "threshold gauge must reflect the configured value"
    );
}

#[test]
fn alternating_fail_pass_keeps_streak_at_zero_after_each_pass() {
    let m = ServerMetrics::default();
    m.periodic_self_test_failure_threshold
        .store(2, Ordering::Relaxed);
    m.last_periodic_self_test_passed
        .store(true, Ordering::Relaxed);

    // Simulate a flaky environment that fails once every other
    // cycle. With threshold=2, /healthz must stay 200 across
    // 10 iterations — because the streak never crosses 1.
    for _ in 0..5 {
        let _ = bump_failure(&m);
        mark_success(&m);
    }
    assert!(
        m.last_periodic_self_test_passed.load(Ordering::Relaxed),
        "flaky alternating fail/pass must NOT drain /healthz when threshold=2"
    );
    assert_eq!(
        m.consecutive_periodic_self_test_failures
            .load(Ordering::Relaxed),
        0
    );
}
