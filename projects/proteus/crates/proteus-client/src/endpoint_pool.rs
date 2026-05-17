//! Client-side multi-endpoint pool with per-endpoint health tracking.
//!
//! ## Problem
//!
//! A single-VPS deploy goes down for any reason — IDC outage, OS
//! reboot, GFW IP-blackholing the prefix, ISP routing flap — and the
//! operator's users see hard connection failures until the operator
//! manually rotates `server_endpoint` in `client.yaml` and restarts.
//! That's an unacceptable outage window for a personal proxy stack
//! that's meant to "just work".
//!
//! ## Solution
//!
//! `EndpointPool` holds an ordered list of `host:port` strings the
//! operator pre-configured as `server_endpoints: [primary, backup1,
//! backup2]` in `client.yaml`. Each entry has its own
//! `EndpointHealth` (a sibling type of `CarrierHealth`) that tracks
//! consecutive failure streaks and applies streak-based suppression
//! with periodic recovery probes.
//!
//! The dispatcher consults the pool per CONNECT, picking the first
//! entry whose health says "try me right now". When all entries
//! are suppressed, it falls back to a forced probe of the primary
//! entry — so we never reach a "no endpoint to dial" state; the
//! worst case is we re-attempt the primary every CONNECT, which is
//! exactly the pre-pool single-endpoint behavior.
//!
//! ## Design choice: per-endpoint health, NOT shared CarrierHealth
//!
//! The existing `CarrierHealth` tracks "is β alive on the current
//! endpoint?". The pool's `EndpointHealth` tracks "is THIS endpoint
//! alive at all?". They compose:
//!
//!   - Pool picks endpoint E (E's health says it's worth a try).
//!   - Within E, CarrierHealth decides β vs α.
//!   - On any failure inside E, both that endpoint's health AND the
//!     CarrierHealth get a failure recorded (because the failure
//!     was on E's β / E's α).
//!   - On success, both clear their streaks.
//!
//! This composition gives the right semantics: a VPS that goes down
//! marks its `EndpointHealth` as unhealthy but doesn't poison
//! `CarrierHealth` (which still has accurate β-vs-α state for the
//! other endpoints).
//!
//! ## Why streak-based, not health-check pinging
//!
//! Same rationale as `CarrierHealth`'s doc — the GFW failure mode is
//! binary on/off, not graceful degradation, and active health
//! checks would themselves be a fingerprint (a client pinging
//! random `server_endpoints[i]:443` at a fixed cadence is very
//! different from real-browser behavior). The streak-based reactive
//! model only generates traffic for actual user CONNECTs.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::carrier_health::{INITIAL_SUPPRESSION, MAX_SUPPRESSION, PROBE_INTERVAL};

/// Default consecutive failures per endpoint before suppression
/// engages. Aligns with `CarrierHealth::DEFAULT_FAILURE_THRESHOLD`
/// (3) — same "transient blip vs sustained issue" boundary.
pub const DEFAULT_ENDPOINT_FAILURE_THRESHOLD: u32 = 3;

/// Snapshot of the three cumulative per-endpoint counters. Operators
/// read these to demote chronically-flaky endpoints — "VPS-A handled
/// 99 % of attempts vs VPS-B handled 60 %" tells them which entry
/// to investigate. Returned by [`EndpointHealth::counters`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EndpointCounters {
    /// Lifetime CONNECT attempts (every dispatcher try, regardless
    /// of outcome).
    pub attempts: u64,
    /// Subset of `attempts` that succeeded.
    pub successes: u64,
    /// Subset of `attempts` that failed.
    pub failures: u64,
}

/// One endpoint's health record. Atomic-only; cheap to share across
/// per-CONNECT spawned tasks via `Arc`.
///
/// Mirrors `CarrierHealth`'s state machine 1:1 — chosen deliberately
/// so a future refactor can collapse the two types into one generic
/// "streak suppressor" if the duplication ever becomes a maintenance
/// burden. For now they stay separate so each can evolve its
/// failure-detection heuristics independently.
pub struct EndpointHealth {
    failure_streak: AtomicU32,
    /// ns-since-tracker-epoch; 0 = not suppressed.
    suppression_deadline_ns: AtomicU64,
    /// CONNECT counter while suppressed; every Nth (PROBE_INTERVAL)
    /// CONNECT becomes a recovery probe.
    suppressed_connect_count: AtomicU32,
    failure_threshold: u32,
    epoch: Instant,
    /// Lifetime cumulative CONNECT attempts against this endpoint.
    /// Bumped by the dispatcher EVERY time it tries this entry,
    /// regardless of outcome (success / failure / fall-through to
    /// next entry). Operators read this for per-VPS demote
    /// decisions ("VPS-A handled 99% of attempts vs VPS-B handled
    /// 60% — investigate VPS-B before raising the threshold"). Wraps
    /// freely past u64::MAX which would take 5+ billion years at
    /// 10 ns/dial.
    attempts_total: AtomicU64,
    /// Subset of `attempts_total` that returned Ok from the
    /// dispatcher. The gap `attempts - successes - failures` is
    /// always zero in normal operation (we bump exactly one outcome
    /// per attempt). Operators alert when the gap grows — that's
    /// an outcome-recording bug.
    successes_total: AtomicU64,
    /// Subset of `attempts_total` that returned Err.
    failures_total: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointDecision {
    /// Endpoint is healthy / not suppressed; try it.
    TryEndpoint,
    /// Endpoint is suppressed but THIS CONNECT is the periodic
    /// recovery probe; try it. On success, suppression clears.
    Probe,
    /// Endpoint is suppressed and this CONNECT is not a probe; skip
    /// to the next endpoint in the pool.
    SkipSuppressed,
}

impl EndpointHealth {
    #[must_use]
    pub fn new() -> Self {
        Self::with_threshold(DEFAULT_ENDPOINT_FAILURE_THRESHOLD)
    }

    #[must_use]
    pub fn with_threshold(failure_threshold: u32) -> Self {
        Self {
            failure_streak: AtomicU32::new(0),
            suppression_deadline_ns: AtomicU64::new(0),
            suppressed_connect_count: AtomicU32::new(0),
            failure_threshold: failure_threshold.max(1),
            epoch: Instant::now(),
            attempts_total: AtomicU64::new(0),
            successes_total: AtomicU64::new(0),
            failures_total: AtomicU64::new(0),
        }
    }

    /// Record one CONNECT attempt against this endpoint, regardless
    /// of outcome. Bumps `attempts_total`. The matching outcome bump
    /// (`record_success` / `record_failure`) MUST follow.
    pub fn record_attempt(&self) {
        self.attempts_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Snapshot of the three cumulative per-endpoint counters.
    /// Atomic per-field; readers don't need consistency across the
    /// triple (they're cumulative totals).
    #[must_use]
    pub fn counters(&self) -> EndpointCounters {
        EndpointCounters {
            attempts: self.attempts_total.load(Ordering::Relaxed),
            successes: self.successes_total.load(Ordering::Relaxed),
            failures: self.failures_total.load(Ordering::Relaxed),
        }
    }

    /// Decide whether to attempt this endpoint at `now`.
    pub fn decide(&self, now: Instant) -> EndpointDecision {
        let deadline_ns = self.suppression_deadline_ns.load(Ordering::Acquire);
        if deadline_ns == 0 || now >= self.decode_nanos(deadline_ns) {
            return EndpointDecision::TryEndpoint;
        }
        let n = self
            .suppressed_connect_count
            .fetch_add(1, Ordering::Relaxed);
        if n.is_multiple_of(PROBE_INTERVAL) {
            EndpointDecision::Probe
        } else {
            EndpointDecision::SkipSuppressed
        }
    }

    /// Record one success — clears streak + suppression. Returns
    /// `true` IFF this call transitioned the endpoint OUT of an
    /// active suppression window. The dispatch site uses this return
    /// value to emit a single structured `info!` log per recovery
    /// (no log noise during the steady-state happy path).
    pub fn record_success(&self) -> bool {
        let prev_deadline_ns = self.suppression_deadline_ns.swap(0, Ordering::AcqRel);
        self.failure_streak.store(0, Ordering::Relaxed);
        self.suppressed_connect_count.store(0, Ordering::Relaxed);
        // Cumulative counter — bumped on every success regardless of
        // transition. The transition signal stays the function's
        // return value so the dispatch site's noise-discipline rules
        // (one info! per recovery) still hold.
        self.successes_total.fetch_add(1, Ordering::Relaxed);
        prev_deadline_ns != 0
    }

    /// Record one failure — bumps streak; engages capped exponential
    /// suppression at/past threshold. Identical schedule to
    /// `CarrierHealth`.
    ///
    /// Returns `Some(window_secs)` when this failure newly engages
    /// suppression (i.e. the previous deadline was zero AND this
    /// failure crossed the threshold) so the dispatch site can log a
    /// structured `warn!`. Returns `None` for both sub-threshold
    /// failures AND for additional failures during an already-active
    /// suppression window (the second case is logged at `debug!` by
    /// the caller if desired).
    pub fn record_failure(&self, now: Instant) -> Option<u64> {
        // Cumulative failure counter — bumped on every failure,
        // regardless of whether this one engages suppression. The
        // return value continues to signal the engagement transition
        // for the dispatch site's structured warn! log.
        self.failures_total.fetch_add(1, Ordering::Relaxed);
        let streak = self.failure_streak.fetch_add(1, Ordering::Relaxed) + 1;
        if streak < self.failure_threshold {
            return None;
        }
        let extra = streak.saturating_sub(self.failure_threshold).min(5);
        let window = INITIAL_SUPPRESSION
            .checked_mul(1u32 << extra)
            .unwrap_or(MAX_SUPPRESSION)
            .min(MAX_SUPPRESSION);
        let deadline = now + window;
        let prev_deadline = self
            .suppression_deadline_ns
            .swap(self.to_nanos(deadline), Ordering::Release);
        if prev_deadline == 0 {
            Some(window.as_secs())
        } else {
            None
        }
    }

    #[must_use]
    pub fn failure_streak(&self) -> u32 {
        self.failure_streak.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn is_suppressed(&self, now: Instant) -> bool {
        let d = self.suppression_deadline_ns.load(Ordering::Acquire);
        d != 0 && now < self.decode_nanos(d)
    }

    fn to_nanos(&self, t: Instant) -> u64 {
        let d = t.saturating_duration_since(self.epoch);
        u64::try_from(d.as_nanos()).unwrap_or(u64::MAX).max(1)
    }

    fn decode_nanos(&self, ns: u64) -> Instant {
        self.epoch + Duration::from_nanos(ns)
    }
}

impl Default for EndpointHealth {
    fn default() -> Self {
        Self::new()
    }
}

/// Ordered list of `host:port` endpoints with per-endpoint health.
///
/// Construction:
///
///   - `EndpointPool::single(addr)` — back-compat 1-entry pool (used
///     for operators who haven't migrated to `server_endpoints:`).
///   - `EndpointPool::new(vec)` — N-entry pool; returns `None` if
///     `vec` is empty.
///
/// The dispatch convention is "iterate in order until a healthy entry
/// is found; on failure inside a chosen entry, fall to the next".
/// We do NOT randomize — operator order encodes preference (e.g.
/// closest-RTT first, then geographic backups).
#[derive(Clone)]
pub struct EndpointPool {
    /// Pairs of `(endpoint_string, health)`. Cloning the pool clones
    /// the Vec of pairs but the `Arc<EndpointHealth>` inside stays
    /// shared so per-CONNECT tasks all see the same health state.
    entries: Vec<(String, Arc<EndpointHealth>)>,
}

impl EndpointPool {
    /// Single-endpoint pool — exactly mirrors pre-pool behavior.
    #[must_use]
    pub fn single(endpoint: String) -> Self {
        Self {
            entries: vec![(endpoint, Arc::new(EndpointHealth::new()))],
        }
    }

    /// N-endpoint pool. Returns `None` for empty input so the caller
    /// can fall back to the legacy single-endpoint path explicitly.
    #[must_use]
    pub fn new(endpoints: Vec<String>) -> Option<Self> {
        if endpoints.is_empty() {
            return None;
        }
        let entries = endpoints
            .into_iter()
            .map(|s| (s, Arc::new(EndpointHealth::new())))
            .collect();
        Some(Self { entries })
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Walk the pool in operator order. For each entry, the caller's
    /// closure decides whether to use the endpoint based on the
    /// returned `EndpointDecision`. The closure should:
    ///
    ///   - Return `Some(result)` when the CONNECT succeeded on
    ///     that endpoint OR when the failure-mode means we should
    ///     STOP iterating (e.g., a SOCKS-level protocol violation
    ///     that has nothing to do with endpoint health).
    ///   - Return `None` to continue iterating to the next entry.
    ///
    /// Returns whatever the closure returned the first time it
    /// produced `Some(_)`, OR `None` after walking the entire pool
    /// with no decision.
    ///
    /// **NOTE**: callers MUST call `record_success` or
    /// `record_failure` on the chosen endpoint's `EndpointHealth`
    /// inside the closure — `dispatch_with` doesn't update health
    /// itself because it doesn't know the outcome of the underlying
    /// network operation. The closure receives the health reference
    /// as an argument explicitly.
    pub async fn dispatch_with<T, Fut, F>(&self, now: Instant, mut try_one: F) -> Option<T>
    where
        F: FnMut(&str, Arc<EndpointHealth>, EndpointDecision) -> Fut,
        Fut: std::future::Future<Output = Option<T>>,
    {
        for (addr, health) in &self.entries {
            let decision = health.decide(now);
            if matches!(decision, EndpointDecision::SkipSuppressed) {
                continue;
            }
            if let Some(result) = try_one(addr, Arc::clone(health), decision).await {
                return Some(result);
            }
        }
        // All entries were either skipped or returned None. Fall back:
        // force one more attempt against the primary (index 0) so we
        // never end up in a "no endpoint to dial" state. Equivalent
        // to the pre-pool single-endpoint behavior under sustained
        // outage.
        if let Some((addr, health)) = self.entries.first() {
            let _ = try_one(addr, Arc::clone(health), EndpointDecision::Probe).await;
        }
        None
    }

    /// Borrow a per-entry health handle by index. Returns `None`
    /// when `index >= len()`. Used by the SOCKS dispatcher to record
    /// per-attempt success/failure into the right bucket without
    /// having to walk the whole entries vec.
    #[must_use]
    pub fn endpoint_health(&self, index: usize) -> Option<Arc<EndpointHealth>> {
        self.entries.get(index).map(|(_, h)| Arc::clone(h))
    }

    /// Borrow the address+health pair by index. Same indexing as
    /// `endpoint_health` but also returns the address string.
    #[must_use]
    pub fn entry(&self, index: usize) -> Option<(String, Arc<EndpointHealth>)> {
        self.entries
            .get(index)
            .map(|(a, h)| (a.clone(), Arc::clone(h)))
    }

    /// Diagnostic accessor for ops tooling: snapshot of every
    /// entry's `(address, current_failure_streak, is_suppressed)`
    /// at `now`.
    #[must_use]
    pub fn diagnostic_snapshot(&self, now: Instant) -> Vec<(String, u32, bool)> {
        self.entries
            .iter()
            .map(|(addr, h)| (addr.clone(), h.failure_streak(), h.is_suppressed(now)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_pool_len_1() {
        let pool = EndpointPool::single("a:1".into());
        assert_eq!(pool.len(), 1);
        assert!(!pool.is_empty());
    }

    #[test]
    fn empty_vec_returns_none() {
        assert!(EndpointPool::new(Vec::new()).is_none());
    }

    #[test]
    fn multi_pool_preserves_order() {
        let pool =
            EndpointPool::new(vec!["first:1".into(), "second:2".into(), "third:3".into()]).unwrap();
        assert_eq!(pool.len(), 3);
        let snap = pool.diagnostic_snapshot(Instant::now());
        assert_eq!(snap[0].0, "first:1");
        assert_eq!(snap[1].0, "second:2");
        assert_eq!(snap[2].0, "third:3");
    }

    #[test]
    fn endpoint_health_below_threshold_does_not_suppress() {
        let h = EndpointHealth::with_threshold(3);
        let t = Instant::now();
        h.record_failure(t);
        h.record_failure(t);
        assert!(!h.is_suppressed(t));
        assert_eq!(h.decide(t), EndpointDecision::TryEndpoint);
    }

    #[test]
    fn endpoint_health_at_threshold_suppresses() {
        let h = EndpointHealth::with_threshold(3);
        let t = Instant::now();
        for _ in 0..3 {
            h.record_failure(t);
        }
        assert!(h.is_suppressed(t));
        // First post-suppression decide = Probe.
        assert_eq!(h.decide(t), EndpointDecision::Probe);
        // Next several = SkipSuppressed.
        for _ in 1..PROBE_INTERVAL {
            assert_eq!(h.decide(t), EndpointDecision::SkipSuppressed);
        }
        // Wraps back to Probe.
        assert_eq!(h.decide(t), EndpointDecision::Probe);
    }

    /// Cumulative attempt counter starts at zero and increments on
    /// each call to record_attempt(), independent of success/failure
    /// counters.
    #[test]
    fn endpoint_counters_start_at_zero() {
        let h = EndpointHealth::new();
        let c = h.counters();
        assert_eq!(c.attempts, 0);
        assert_eq!(c.successes, 0);
        assert_eq!(c.failures, 0);
    }

    #[test]
    fn endpoint_counters_attempt_independent_of_outcome() {
        let h = EndpointHealth::with_threshold(2);
        let t = Instant::now();
        h.record_attempt();
        h.record_attempt();
        h.record_attempt();
        // No outcome recorded yet — counters reflect the asymmetry.
        let c = h.counters();
        assert_eq!(c.attempts, 3);
        assert_eq!(c.successes, 0);
        assert_eq!(c.failures, 0);
        // Now record outcomes for the 3 attempts: 2 ok, 1 failed.
        h.record_success();
        h.record_success();
        h.record_failure(t);
        let c = h.counters();
        assert_eq!(c.attempts, 3);
        assert_eq!(c.successes, 2);
        assert_eq!(c.failures, 1);
        assert_eq!(c.attempts, c.successes + c.failures);
    }

    /// Every record_success bumps the cumulative success counter,
    /// regardless of whether it transitions out of suppression.
    #[test]
    fn endpoint_counter_success_bumps_on_every_call() {
        let h = EndpointHealth::with_threshold(2);
        let t = Instant::now();
        h.record_success(); // not previously suppressed → returns false
        h.record_success();
        // Drive into suppression then recover.
        h.record_failure(t);
        h.record_failure(t);
        let lifted = h.record_success(); // transition out
        assert!(lifted);
        assert_eq!(h.counters().successes, 3);
    }

    /// Every record_failure bumps the cumulative failure counter,
    /// regardless of whether it engages new suppression or extends
    /// an existing window.
    #[test]
    fn endpoint_counter_failure_bumps_on_every_call() {
        let h = EndpointHealth::with_threshold(2);
        let t = Instant::now();
        h.record_failure(t); // sub-threshold
        let engaged1 = h.record_failure(t); // engages (window=15s)
        assert!(engaged1.is_some());
        let engaged2 = h.record_failure(t); // extends, returns None
        assert!(engaged2.is_none());
        let engaged3 = h.record_failure(t); // extends, returns None
        assert!(engaged3.is_none());
        // 4 failures total → 4 counter bumps.
        assert_eq!(h.counters().failures, 4);
    }

    #[test]
    fn endpoint_health_success_clears_state() {
        let h = EndpointHealth::with_threshold(2);
        let t = Instant::now();
        h.record_failure(t);
        h.record_failure(t);
        assert!(h.is_suppressed(t));
        h.record_success();
        assert!(!h.is_suppressed(t));
        assert_eq!(h.failure_streak(), 0);
    }

    /// `record_success` returns `true` exactly when this success
    /// transitions OUT of an active suppression window. Two-phase
    /// proof: sub-threshold success returns `false` (we were never
    /// suppressed), post-suppression success returns `true`.
    #[test]
    fn endpoint_health_record_success_returns_true_only_on_recovery() {
        let h = EndpointHealth::with_threshold(2);
        let t = Instant::now();
        assert!(
            !h.record_success(),
            "fresh-state success must NOT report a transition"
        );
        h.record_failure(t);
        // Single sub-threshold failure; success here clears the
        // streak but didn't lift suppression (none existed).
        assert!(
            !h.record_success(),
            "sub-threshold success must NOT report a transition"
        );
        // Now drive to suppression.
        h.record_failure(t);
        h.record_failure(t);
        assert!(h.is_suppressed(t));
        // The success that clears it must return true.
        assert!(
            h.record_success(),
            "success that lifts suppression MUST report a transition"
        );
        // A second success in a row is a no-op transition.
        assert!(!h.record_success());
    }

    /// `record_failure` returns `Some(window_secs)` exactly on the
    /// failure that newly engages suppression; further failures
    /// during the active window extend back-off silently (return
    /// None) so the dispatch site only logs one suppression-engaged
    /// event per burst.
    #[test]
    fn endpoint_health_record_failure_returns_window_only_on_engagement() {
        let h = EndpointHealth::with_threshold(2);
        let t = Instant::now();
        // First failure: sub-threshold, no engagement.
        assert_eq!(h.record_failure(t), None);
        // Second failure: hits threshold, suppression engaged.
        let engaged = h.record_failure(t);
        assert_eq!(
            engaged,
            Some(INITIAL_SUPPRESSION.as_secs()),
            "first cross-threshold failure must report the back-off window"
        );
        // Third+ failures while still suppressed: extension, no
        // re-engagement log.
        assert_eq!(
            h.record_failure(t),
            None,
            "additional failures during active suppression must NOT re-report engagement"
        );
        assert_eq!(h.record_failure(t), None);
        // After success + a fresh streak hits threshold again, we
        // get a new engagement.
        h.record_success();
        h.record_failure(t);
        assert_eq!(
            h.record_failure(t),
            Some(INITIAL_SUPPRESSION.as_secs()),
            "fresh streak crossing threshold after recovery must report engagement"
        );
    }

    #[tokio::test]
    async fn dispatch_picks_first_healthy_entry() {
        let pool = EndpointPool::new(vec!["a:1".into(), "b:2".into(), "c:3".into()]).unwrap();
        let now = Instant::now();
        // First call: every entry is healthy → closure returns
        // Some on entry 0 → dispatch returns.
        let picked = pool
            .dispatch_with(now, |addr, _h, _d| {
                let addr = addr.to_string();
                async move { Some(addr) }
            })
            .await;
        assert_eq!(picked.as_deref(), Some("a:1"));
    }

    #[tokio::test]
    async fn dispatch_skips_to_next_when_first_returns_none() {
        let pool = EndpointPool::new(vec!["a:1".into(), "b:2".into()]).unwrap();
        let now = Instant::now();
        // First closure returns None (simulating connect failure
        // that should fall to next endpoint); second returns Some.
        let picked = pool
            .dispatch_with(now, |addr, _h, _d| {
                let addr = addr.to_string();
                async move {
                    if addr == "a:1" {
                        None
                    } else {
                        Some(addr)
                    }
                }
            })
            .await;
        assert_eq!(picked.as_deref(), Some("b:2"));
    }

    #[tokio::test]
    async fn dispatch_skips_suppressed_entries_entirely() {
        let pool = EndpointPool::new(vec!["a:1".into(), "b:2".into()]).unwrap();
        let now = Instant::now();
        // Suppress entry 0 by hammering it with failures via the
        // dispatch closure. We use `Option<()>` explicitly to give
        // the type inference a target. Each closure call sees the
        // current entry's `&str` addr; we copy what we need into the
        // async block to avoid lifetime issues across the await.
        for _ in 0..DEFAULT_ENDPOINT_FAILURE_THRESHOLD {
            pool.dispatch_with::<(), _, _>(now, |a, h, _d| {
                let is_a = a == "a:1";
                async move {
                    if is_a {
                        h.record_failure(Instant::now());
                    }
                    None
                }
            })
            .await;
        }
        // Now entry 0 should be suppressed. Dispatch should land on
        // entry 1.
        let picked = pool
            .dispatch_with(Instant::now(), |addr, _h, _d| {
                let addr = addr.to_string();
                async move { Some(addr) }
            })
            .await;
        assert_eq!(picked.as_deref(), Some("b:2"));
    }

    #[tokio::test]
    async fn dispatch_all_suppressed_falls_back_to_primary_probe() {
        let pool = EndpointPool::new(vec!["a:1".into(), "b:2".into()]).unwrap();
        let now = Instant::now();
        // Beat both entries down to suppression.
        for _ in 0..DEFAULT_ENDPOINT_FAILURE_THRESHOLD {
            pool.dispatch_with::<(), _, _>(now, |_a, h, _d| async move {
                h.record_failure(Instant::now());
                None
            })
            .await;
        }
        // All suppressed (except whichever periodic Probe slot
        // happens to land — we don't strictly care which one, as
        // long as something gets dialed; the load-bearing assertion
        // is "dispatch keeps trying SOMETHING").
        let mut hit_count = 0u32;
        pool.dispatch_with::<(), _, _>(Instant::now(), |_a, _h, _d| {
            hit_count += 1;
            async move { None }
        })
        .await;
        // The fall-back forces at least one probe of the primary
        // (entry 0). So even in the worst case where every entry
        // returns SkipSuppressed in `decide`, hit_count ≥ 1.
        assert!(
            hit_count >= 1,
            "dispatch never invoked closure; hit_count={hit_count}"
        );
    }
}
