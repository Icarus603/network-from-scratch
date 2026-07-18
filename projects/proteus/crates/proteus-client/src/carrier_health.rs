//! Client-side carrier-health tracker — back-off + probe scheduling
//! for the β (QUIC) fallback path.
//!
//! ## Problem
//!
//! The default β-first dual-stack dispatch (`socks::handle_socks5`)
//! tries β first per CONNECT and pays the full
//! `beta_first_timeout_secs` (default 3 s) on every CONNECT before
//! falling back to α. Under realistic 2026 GFW conditions — UDP/QUIC
//! throttling (threat-intel main line 5), short-window
//! `CONNECTION_CLOSE` events from prefix-noise classification, or
//! plain "the corporate network blocks UDP egress" — that 3 s tax
//! lands on every interactive request the user makes. A typical
//! web page generates dozens of CONNECTs (one per origin); the
//! cumulative latency cost is what users describe as "the proxy
//! feels broken even though it's working".
//!
//! ## Solution
//!
//! `CarrierHealth` is a small atomic-only state tracker that holds:
//!
//!   - **failure streak count** for β — incremented on every β
//!     failure, reset on success.
//!   - **suppression deadline** — when the streak hits the threshold,
//!     subsequent β attempts are skipped until this instant passes
//!     (capped exponential back-off, max 5 minutes).
//!   - **last-probe instant** — when β is suppressed, every Nth
//!     CONNECT (governed by `probe_interval`) probes β anyway to
//!     test recovery. If the probe succeeds, suppression clears.
//!
//! ## What this is NOT
//!
//! - **Not a circuit breaker in the Hystrix sense.** No half-open
//!   state, no rolling success/failure ratio. Simple
//!   streak-and-backoff is sufficient for the binary "is UDP
//!   currently blocked?" question.
//! - **Not a permanent disable.** β always recovers automatically
//!   when the underlying network condition clears; no operator
//!   intervention needed.
//! - **Not load-balancing.** This module decides "try β or skip to
//!   α", not "which of several β endpoints". Multi-endpoint β
//!   support is M3+ (spec §10.4 multipath QUIC).
//!
//! ## Threading
//!
//! Pure atomics; no mutex. Reads are `Relaxed`, writes are
//! `Relaxed` for counters and `Release`/`Acquire` for the
//! suppression-deadline instant pair. The data race on the
//! deadline ns/secs pair is benign — at worst we suppress one
//! extra request or skip one suppression cycle, both of which
//! self-correct on the next call.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tracing::{info, warn};

/// Default consecutive failures before β suppression engages.
///
/// Rationale: 3 is the smallest number that distinguishes "transient
/// connection blip" (1-2 failures absorbed silently) from "sustained
/// network condition" (3+ failures = the path is genuinely degraded
/// right now). Hy2 and other quinn-based stacks use similar values
/// for their internal back-off heuristics.
pub const DEFAULT_FAILURE_THRESHOLD: u32 = 3;

/// Initial suppression window after the threshold is hit. Doubles
/// on every subsequent failure inside the suppression window, capped
/// at `MAX_SUPPRESSION`.
pub const INITIAL_SUPPRESSION: Duration = Duration::from_secs(15);

/// Maximum suppression window. After this, every CONNECT will
/// probe β again until either it succeeds (clear suppression) or
/// fails (reset to MAX). Keeps recovery latency bounded under
/// permanent UDP block.
pub const MAX_SUPPRESSION: Duration = Duration::from_secs(300);

/// While β is suppressed, allow one probe every `PROBE_INTERVAL`
/// CONNECTs to test recovery. A single successful probe clears
/// suppression entirely.
///
/// Default 1-in-32: a typical browser CONNECT burst (~20 origins
/// per page) almost never re-probes within one page load, but a
/// continuously-used proxy session (one CONNECT/sec) re-probes
/// every ~30 s — fast enough that transient outages recover
/// while the user is still actively browsing.
pub const PROBE_INTERVAL: u32 = 32;

/// Carrier-health state for the β path. Cheap to clone via `Arc`
/// when sharing across the accept-loop's spawned per-connection
/// tasks; the actual state lives in atomics.
pub struct CarrierHealth {
    failure_streak: AtomicU32,
    /// Suppression deadline encoded as nanoseconds since the process
    /// epoch (loosely — see `now_nanos()` for the encoding). Zero
    /// means "no suppression in effect".
    suppression_deadline_ns: AtomicU64,
    /// Running count of CONNECTs observed while β is suppressed.
    /// Wraps freely; we only care about the modulo-`PROBE_INTERVAL`
    /// value.
    suppressed_connect_count: AtomicU32,
    /// Failure threshold (configurable for tests / aggressive ops).
    failure_threshold: u32,
    /// Process start time used as the "epoch" for the
    /// `suppression_deadline_ns` encoding. Captured at construction.
    epoch: Instant,
}

/// Decision returned by `decide_beta`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BetaDecision {
    /// Operator hasn't configured β at all (`server_endpoint_beta`
    /// unset) — skip β unconditionally.
    SkipNoConfig,
    /// β is healthy / not suppressed — try β as the primary carrier.
    TryBeta,
    /// β is suppressed but this CONNECT is the periodic recovery
    /// probe — try β. If it works, suppression clears.
    Probe,
    /// β is suppressed and this CONNECT is not a probe — skip
    /// β, dial α directly. Saves `beta_first_timeout_secs` of
    /// pointless waiting.
    SkipSuppressed,
}

impl CarrierHealth {
    /// Construct a tracker with the documented defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::with_threshold(DEFAULT_FAILURE_THRESHOLD)
    }

    /// Construct with an explicit failure threshold. Used by tests
    /// to exercise short-streak scenarios quickly.
    #[must_use]
    pub fn with_threshold(failure_threshold: u32) -> Self {
        Self {
            failure_streak: AtomicU32::new(0),
            suppression_deadline_ns: AtomicU64::new(0),
            suppressed_connect_count: AtomicU32::new(0),
            failure_threshold: failure_threshold.max(1),
            epoch: Instant::now(),
        }
    }

    /// Decide whether to attempt β for a CONNECT initiated `now`.
    /// `beta_configured = false` short-circuits to `SkipNoConfig` so
    /// the caller doesn't have to repeat the check.
    pub fn decide_beta(&self, beta_configured: bool, now: Instant) -> BetaDecision {
        if !beta_configured {
            return BetaDecision::SkipNoConfig;
        }
        let deadline_ns = self.suppression_deadline_ns.load(Ordering::Acquire);
        if deadline_ns == 0 || now >= self.decode_nanos(deadline_ns) {
            // Either no suppression or the window expired — try β.
            // If the window just expired, leave the deadline as-is;
            // on the next FAILURE we'll re-arm; on SUCCESS we'll
            // clear via `record_beta_success`.
            return BetaDecision::TryBeta;
        }
        // Suppressed: count this CONNECT; every PROBE_INTERVAL-th
        // call returns `Probe`. fetch_add wraps cleanly.
        let n = self
            .suppressed_connect_count
            .fetch_add(1, Ordering::Relaxed);
        if n.checked_rem(PROBE_INTERVAL) == Some(0) {
            // Log at DEBUG (not INFO) — a probe attempt is routine
            // operator-curiosity material, not actionable. The actual
            // outcome (success/failure) is logged by
            // `record_beta_success` / `record_beta_failure`.
            tracing::debug!(
                target: "proteus_client::carrier_health",
                "β recovery probe scheduled (1-in-{} during suppression)",
                PROBE_INTERVAL
            );
            BetaDecision::Probe
        } else {
            BetaDecision::SkipSuppressed
        }
    }

    /// Record one β success. Clears the failure streak and lifts
    /// any active suppression. Safe to call on every β success
    /// (cheap atomics).
    ///
    /// Emits an `info!` log line ONLY when this success transitions
    /// the carrier OUT of suppression — so the operator gets a
    /// clear "β recovered" signal in `journalctl` without one log
    /// line per CONNECT in the happy path.
    pub fn record_beta_success(&self) {
        // Swap the deadline to zero. The previous value tells us if
        // we were suppressed (non-zero) — that's the transition we
        // want to log. Releasing the zero makes the "no longer
        // suppressed" view visible to other threads atomically.
        let prev_deadline_ns = self.suppression_deadline_ns.swap(0, Ordering::AcqRel);
        let prev_streak = self.failure_streak.swap(0, Ordering::Relaxed);
        self.suppressed_connect_count.store(0, Ordering::Relaxed);
        if prev_deadline_ns != 0 {
            info!(
                target: "proteus_client::carrier_health",
                prev_streak,
                "β carrier RECOVERED (suppression cleared on successful CONNECT)"
            );
        }
    }

    /// Record one β failure. Bumps the streak; if the streak hits
    /// the threshold, engages or extends suppression with capped
    /// exponential back-off.
    ///
    /// Emits a `warn!` log when crossing the suppression threshold
    /// (first time → operator should care) and a lower-noise `info!`
    /// when extending an already-active suppression. Sub-threshold
    /// failures (the first N-1 in a streak) are silent because
    /// they're indistinguishable from transient network blips and
    /// would otherwise flood logs during legitimate retries.
    pub fn record_beta_failure(&self, now: Instant) {
        let streak = self.failure_streak.fetch_add(1, Ordering::Relaxed) + 1;
        if streak < self.failure_threshold {
            return;
        }
        // Back-off: INITIAL << min(streak - threshold, 5).
        // streak == threshold: 15 s
        // threshold + 1: 30 s
        // threshold + 2: 60 s
        // threshold + 3: 120 s
        // threshold + 4: 240 s
        // threshold + 5+: 300 s (cap)
        let extra = streak.saturating_sub(self.failure_threshold).min(5);
        let window = INITIAL_SUPPRESSION
            .checked_mul(1u32 << extra)
            .unwrap_or(MAX_SUPPRESSION)
            .min(MAX_SUPPRESSION);
        let deadline = now + window;
        // Pre-transition check: if deadline was zero we're entering
        // suppression for the first time (this burst); otherwise
        // we're extending an existing window.
        let prev_deadline = self
            .suppression_deadline_ns
            .swap(self.to_nanos(deadline), Ordering::Release);
        let window_secs = window.as_secs();
        if prev_deadline == 0 {
            warn!(
                target: "proteus_client::carrier_health",
                streak,
                threshold = self.failure_threshold,
                window_secs,
                "β carrier SUPPRESSED — consecutive failures hit threshold; \
                 subsequent CONNECTs skip β for the back-off window (1-in-{} probe interval)",
                PROBE_INTERVAL
            );
        } else {
            info!(
                target: "proteus_client::carrier_health",
                streak,
                window_secs,
                "β suppression extended (back-off escalated by another failure)"
            );
        }
    }

    /// Diagnostic: current failure streak count.
    #[must_use]
    pub fn failure_streak(&self) -> u32 {
        self.failure_streak.load(Ordering::Relaxed)
    }

    /// Diagnostic: current suppression deadline as an `Instant`, or
    /// `None` if not currently suppressed. Useful for the
    /// `proteus-client status` surface when it lands.
    #[must_use]
    pub fn suppression_deadline(&self) -> Option<Instant> {
        let ns = self.suppression_deadline_ns.load(Ordering::Acquire);
        if ns == 0 {
            None
        } else {
            Some(self.decode_nanos(ns))
        }
    }

    /// Diagnostic: true iff β is currently suppressed at instant
    /// `now`.
    #[must_use]
    pub fn is_suppressed(&self, now: Instant) -> bool {
        let d = self.suppression_deadline_ns.load(Ordering::Acquire);
        d != 0 && now < self.decode_nanos(d)
    }

    /// Encode an `Instant` as ns-since-epoch (where epoch is this
    /// tracker's construction time). Saturates at u64::MAX on the
    /// rare case the process runs for > 584 years.
    fn to_nanos(&self, t: Instant) -> u64 {
        let d = t.saturating_duration_since(self.epoch);
        u64::try_from(d.as_nanos()).unwrap_or(u64::MAX).max(1)
    }

    /// Decode an ns-since-epoch value back into an `Instant`. Named
    /// `decode_*` (not `from_*`) to satisfy clippy's
    /// `wrong_self_convention` lint — `from_*` methods are expected
    /// to be associated functions, not `&self` methods.
    fn decode_nanos(&self, ns: u64) -> Instant {
        self.epoch + Duration::from_nanos(ns)
    }
}

impl Default for CarrierHealth {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skip_no_config_when_beta_unset() {
        let h = CarrierHealth::new();
        assert_eq!(
            h.decide_beta(false, Instant::now()),
            BetaDecision::SkipNoConfig,
        );
    }

    #[test]
    fn try_beta_when_healthy() {
        let h = CarrierHealth::new();
        assert_eq!(h.decide_beta(true, Instant::now()), BetaDecision::TryBeta);
    }

    #[test]
    fn failures_below_threshold_do_not_suppress() {
        let h = CarrierHealth::with_threshold(3);
        let t = Instant::now();
        h.record_beta_failure(t);
        h.record_beta_failure(t);
        assert!(!h.is_suppressed(t));
        assert_eq!(h.decide_beta(true, t), BetaDecision::TryBeta);
    }

    #[test]
    fn failures_at_threshold_engage_suppression() {
        let h = CarrierHealth::with_threshold(3);
        let t = Instant::now();
        for _ in 0..3 {
            h.record_beta_failure(t);
        }
        assert!(h.is_suppressed(t));
        // First post-suppression CONNECT (count = 0 % PROBE_INTERVAL = 0)
        // hits the probe branch — that's the recovery probe.
        let first = h.decide_beta(true, t);
        assert_eq!(first, BetaDecision::Probe);
        // Next several CONNECTs are skipped until count cycles around.
        for i in 1..PROBE_INTERVAL {
            assert_eq!(
                h.decide_beta(true, t),
                BetaDecision::SkipSuppressed,
                "expected skip at count i={i} while suppressed"
            );
        }
        // Count wrapped — next is another probe.
        assert_eq!(h.decide_beta(true, t), BetaDecision::Probe);
    }

    #[test]
    fn success_during_suppression_clears_it() {
        let h = CarrierHealth::with_threshold(3);
        let t = Instant::now();
        for _ in 0..3 {
            h.record_beta_failure(t);
        }
        assert!(h.is_suppressed(t));
        h.record_beta_success();
        assert!(!h.is_suppressed(t));
        assert_eq!(h.failure_streak(), 0);
        assert_eq!(h.decide_beta(true, t), BetaDecision::TryBeta);
    }

    #[test]
    fn suppression_lifts_after_window() {
        // Use small threshold for fast test; INITIAL_SUPPRESSION is 15s.
        let h = CarrierHealth::with_threshold(3);
        let t0 = Instant::now();
        for _ in 0..3 {
            h.record_beta_failure(t0);
        }
        assert!(h.is_suppressed(t0));
        // 16 seconds later: window expired.
        let t1 = t0 + Duration::from_secs(16);
        assert!(!h.is_suppressed(t1));
        assert_eq!(h.decide_beta(true, t1), BetaDecision::TryBeta);
    }

    #[test]
    fn repeated_failures_expand_suppression_window_with_cap() {
        let h = CarrierHealth::with_threshold(1);
        let t0 = Instant::now();
        // 1st failure (streak = 1 = threshold): 15s window
        h.record_beta_failure(t0);
        assert!(h.is_suppressed(t0 + Duration::from_secs(14)));
        assert!(!h.is_suppressed(t0 + Duration::from_secs(16)));
        // 2nd failure: 30s window
        h.record_beta_failure(t0);
        assert!(h.is_suppressed(t0 + Duration::from_secs(29)));
        assert!(!h.is_suppressed(t0 + Duration::from_secs(31)));
        // 3rd: 60s
        h.record_beta_failure(t0);
        assert!(h.is_suppressed(t0 + Duration::from_secs(59)));
        assert!(!h.is_suppressed(t0 + Duration::from_secs(61)));
        // 4th: 120s
        h.record_beta_failure(t0);
        assert!(h.is_suppressed(t0 + Duration::from_secs(119)));
        assert!(!h.is_suppressed(t0 + Duration::from_secs(121)));
        // 5th: 240s
        h.record_beta_failure(t0);
        assert!(h.is_suppressed(t0 + Duration::from_secs(239)));
        assert!(!h.is_suppressed(t0 + Duration::from_secs(241)));
        // 6th+: capped at MAX_SUPPRESSION = 300s
        for _ in 0..10 {
            h.record_beta_failure(t0);
        }
        assert!(h.is_suppressed(t0 + Duration::from_secs(299)));
        assert!(!h.is_suppressed(t0 + Duration::from_secs(301)));
    }

    #[test]
    fn probe_success_during_suppression_clears_suppression() {
        // The "Probe" decision is what the dispatch path uses to try
        // β anyway during the suppression window. If that probe
        // succeeds, the dispatch calls `record_beta_success`, which
        // clears suppression. Verify the full cycle.
        let h = CarrierHealth::with_threshold(2);
        let t = Instant::now();
        h.record_beta_failure(t);
        h.record_beta_failure(t);
        assert!(h.is_suppressed(t));

        // The 1st suppressed CONNECT is the probe.
        assert_eq!(h.decide_beta(true, t), BetaDecision::Probe);

        // The probe succeeded — caller records success.
        h.record_beta_success();
        assert!(!h.is_suppressed(t));
        assert_eq!(h.decide_beta(true, t), BetaDecision::TryBeta);
    }

    #[test]
    fn streak_resets_on_any_success() {
        let h = CarrierHealth::with_threshold(5);
        let t = Instant::now();
        h.record_beta_failure(t);
        h.record_beta_failure(t);
        h.record_beta_failure(t);
        assert_eq!(h.failure_streak(), 3);
        // One success — streak back to zero, no suppression engaged.
        h.record_beta_success();
        assert_eq!(h.failure_streak(), 0);
        // Need a fresh full streak to suppress again.
        for _ in 0..4 {
            h.record_beta_failure(t);
        }
        assert!(!h.is_suppressed(t));
        h.record_beta_failure(t);
        assert!(h.is_suppressed(t));
    }
}
