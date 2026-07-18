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

/// Reloadable wrapper around an `EndpointPool`.
///
/// Production clients see the operator edit `server_endpoints:` in
/// `client.yaml` (e.g. add a new backup VPS, demote a burned one)
/// and **cannot** afford to restart the binary — every in-flight
/// SOCKS5 session would tear down. With [`ReloadablePool`] the
/// operator just SIGHUPs and:
///
///   - Every NEW CONNECT after the reload uses the new pool order.
///   - Existing in-flight sessions keep using their already-chosen
///     endpoint until they complete naturally.
///   - Per-endpoint suppression state + cumulative counters are
///     transplanted for any entry whose address string is identical
///     across the two pools (see
///     [`EndpointPool::new_with_carryover`]).
///
/// Implementation: a `std::sync::RwLock<Option<Arc<EndpointPool>>>`.
/// `current()` is the hot path; read-locks for one Arc-clone (one
/// atomic increment) per CONNECT. `reload()` is rare (operator
/// SIGHUP) and takes the write lock.
///
/// The `Option` lets the operator transition between "single
/// endpoint" (cfg.server_endpoint only) and "pool" (server_endpoints
/// list) modes without restart: a reload that supplies an empty
/// list clears the pool back to `None`, falling back to the legacy
/// single-endpoint dispatch path.
#[derive(Clone)]
pub struct ReloadablePool {
    inner: Arc<std::sync::RwLock<Option<Arc<EndpointPool>>>>,
    /// Cumulative reload counters mirror the server's
    /// `ReloadableAcceptor` counters — operators alert when
    /// `attempts - succeeded > 0` (someone SIGHUPed but the reload
    /// path errored).
    reload_attempts: Arc<std::sync::atomic::AtomicU64>,
    reload_succeeded: Arc<std::sync::atomic::AtomicU64>,
}

impl ReloadablePool {
    /// Wrap an initial pool (or no pool at all — `None` = legacy
    /// single-endpoint dispatch).
    #[must_use]
    pub fn new(initial: Option<Arc<EndpointPool>>) -> Self {
        Self {
            inner: Arc::new(std::sync::RwLock::new(initial)),
            reload_attempts: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            reload_succeeded: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Clone the current pool handle. Cheap (one Arc clone under a
    /// read lock); called once per SOCKS5 CONNECT.
    #[must_use]
    pub fn current(&self) -> Option<Arc<EndpointPool>> {
        self.inner.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Swap in a freshly-built pool. Per-endpoint counter +
    /// suppression-state carryover is the caller's responsibility —
    /// build the new pool via [`EndpointPool::new_with_carryover`]
    /// against the result of [`Self::current`].
    pub fn reload(&self, new_pool: Option<Arc<EndpointPool>>) {
        self.reload_attempts
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        {
            let mut w = self.inner.write().unwrap_or_else(|p| p.into_inner());
            *w = new_pool;
        }
        self.reload_succeeded
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Record one reload attempt that ABORTED before reaching the
    /// atomic swap — e.g., the operator SIGHUPed but the on-disk
    /// `client.yaml` failed to parse, or some I/O error prevented
    /// reading the new endpoint list. Bumps `reload_attempts`
    /// WITHOUT bumping `reload_succeeded`, so the gap
    /// `(attempts - succeeded) > 0` becomes the alertable signal
    /// that `ProteusClientPoolReloadFailing` (iter-36 alert +
    /// in-process check + iter-37 dashboard panel) was designed
    /// to detect.
    ///
    /// Iter-40 bug fix: pre-iter-40, the SIGHUP handler in
    /// main.rs early-returned on a config-parse error WITHOUT
    /// bumping any counter, leaving the operator's silent
    /// edit-didn't-apply event invisible to the entire
    /// observability stack — the alert that was meant to catch
    /// this exact failure mode could literally never fire,
    /// because every call into `reload_from_addrs` always
    /// incremented both counters in lockstep.
    pub fn record_attempt_failed(&self) {
        self.reload_attempts
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // Deliberately DO NOT bump reload_succeeded — that's the
        // whole point. The gap is the alertable signal.
    }

    /// Build a new pool from `endpoints`, transplanting counters
    /// from the current pool, then atomically swap it in. Convenience
    /// wrapper around the [`Self::current`] →
    /// [`EndpointPool::new_with_carryover`] → [`Self::reload`]
    /// sequence the SIGHUP handler runs.
    ///
    /// Returns `(prev_addrs, new_addrs)` so the caller can log a
    /// diff (added / removed entries).
    pub fn reload_from_addrs(&self, endpoints: Vec<String>) -> (Vec<String>, Vec<String>) {
        let prev = self.current();
        let prev_addrs: Vec<String> = prev
            .as_ref()
            .map(|p| p.addresses().map(str::to_string).collect())
            .unwrap_or_default();
        let new_addrs = endpoints.clone();
        let new_pool = if endpoints.is_empty() {
            None
        } else {
            // Carry over only if we had a prior pool; otherwise
            // we're entering pool mode for the first time and every
            // entry is fresh.
            match prev.as_ref() {
                Some(p) => EndpointPool::new_with_carryover(endpoints, p).map(Arc::new),
                None => EndpointPool::new(endpoints).map(Arc::new),
            }
        };
        self.reload(new_pool);
        (prev_addrs, new_addrs)
    }

    /// Reload-attempt counter (every reload call, regardless of
    /// whether the resulting pool was `Some` or `None`).
    #[must_use]
    pub fn reload_attempts(&self) -> u64 {
        self.reload_attempts
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Reload-succeeded counter (every reload that completed the
    /// atomic swap). Iter-40: the gap
    /// `(reload_attempts - reload_succeeded)` now reflects real
    /// failed-SIGHUP events because the main.rs SIGHUP handler
    /// calls [`Self::record_attempt_failed`] on config-parse
    /// errors. Symmetric with the server-side reloadable surfaces.
    #[must_use]
    pub fn reload_succeeded(&self) -> u64 {
        self.reload_succeeded
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Compute the diff between two address lists for SIGHUP logging.
/// Returns `(added, removed)` where `added` are addrs in `new` but
/// not `prev`, and `removed` are addrs in `prev` but not `new`.
/// Pure utility; tests can call it without spinning up a pool.
#[must_use]
pub fn pool_addr_diff(prev: &[String], new: &[String]) -> (Vec<String>, Vec<String>) {
    let prev_set: std::collections::HashSet<&str> = prev.iter().map(String::as_str).collect();
    let new_set: std::collections::HashSet<&str> = new.iter().map(String::as_str).collect();
    let added = new
        .iter()
        .filter(|a| !prev_set.contains(a.as_str()))
        .cloned()
        .collect();
    let removed = prev
        .iter()
        .filter(|a| !new_set.contains(a.as_str()))
        .cloned()
        .collect();
    (added, removed)
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
        if n.checked_rem(PROBE_INTERVAL) == Some(0) {
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

    /// Build a new pool from `endpoints`, transplanting the
    /// `Arc<EndpointHealth>` from `prev` for any entry whose address
    /// string is identical. This is the SIGHUP hot-reload primitive:
    /// after the operator edits `server_endpoints:` and SIGHUPs, the
    /// new pool keeps the suppression state + per-endpoint cumulative
    /// counters for entries the operator left alone, while freshly
    /// inserted entries start at zero.
    ///
    /// Semantics:
    ///   - `addr in prev AND addr in endpoints`  → reuse prev's
    ///     `Arc<EndpointHealth>` (counters + suppression state
    ///     preserved).
    ///   - `addr in prev AND NOT in endpoints`   → drop (entry removed
    ///     from config; its counters are gone, which is what the
    ///     operator asked for).
    ///   - `addr in endpoints AND NOT in prev`   → mint a fresh
    ///     `EndpointHealth` (new entry).
    ///   - Order is taken from `endpoints` (matches operator's new
    ///     preference order; old order is irrelevant).
    ///
    /// Returns `None` for empty input — same convention as `new`.
    #[must_use]
    pub fn new_with_carryover(endpoints: Vec<String>, prev: &Self) -> Option<Self> {
        if endpoints.is_empty() {
            return None;
        }
        // Build a lookup of prev entries' Arc<EndpointHealth> by addr
        // so transplant is O(N+M) rather than O(N*M).
        let prev_lookup: std::collections::HashMap<&str, &Arc<EndpointHealth>> = prev
            .entries
            .iter()
            .map(|(addr, h)| (addr.as_str(), h))
            .collect();
        let entries = endpoints
            .into_iter()
            .map(|s| {
                let h = match prev_lookup.get(s.as_str()) {
                    Some(&existing) => Arc::clone(existing),
                    None => Arc::new(EndpointHealth::new()),
                };
                (s, h)
            })
            .collect();
        Some(Self { entries })
    }

    /// Iterate the address strings in declaration order. Used by
    /// `ReloadablePool` diff logging and by tests that want to assert
    /// "after reload, the pool has these N entries in this order".
    pub fn addresses(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|(a, _)| a.as_str())
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

    // ----- Hot-reload + counter-carryover tests -----

    /// Identical input list → identical Arc<EndpointHealth> shared
    /// across both pools. The whole point of carryover.
    #[test]
    fn carryover_preserves_health_arcs_for_unchanged_entries() {
        let old = EndpointPool::new(vec!["a:1".into(), "b:2".into(), "c:3".into()]).unwrap();
        // Bump some counters on old so we have something concrete to
        // verify the transplant carried.
        let a_old = old.endpoint_health(0).unwrap();
        a_old.record_attempt();
        a_old.record_success();
        let b_old = old.endpoint_health(1).unwrap();
        b_old.record_attempt();
        b_old.record_failure(Instant::now());

        let new =
            EndpointPool::new_with_carryover(vec!["a:1".into(), "b:2".into(), "c:3".into()], &old)
                .expect("non-empty");
        // Every entry's Arc<EndpointHealth> must be ptr_eq with the
        // old one — the whole point is shared state across reload.
        for i in 0..3 {
            let old_h = old.endpoint_health(i).unwrap();
            let new_h = new.endpoint_health(i).unwrap();
            assert!(
                Arc::ptr_eq(&old_h, &new_h),
                "entry {i}: health Arc must be the SAME instance after carryover"
            );
        }
        // Counter values survived (sanity — implied by ptr_eq but
        // explicit for documentation).
        assert_eq!(new.endpoint_health(0).unwrap().counters().successes, 1);
        assert_eq!(new.endpoint_health(1).unwrap().counters().failures, 1);
    }

    /// Reorder: counters move with the addr, NOT the position.
    #[test]
    fn carryover_follows_addr_not_index_when_reordered() {
        let old = EndpointPool::new(vec!["a:1".into(), "b:2".into(), "c:3".into()]).unwrap();
        // Bump a's counter so we can distinguish it.
        for _ in 0..10 {
            old.endpoint_health(0).unwrap().record_attempt();
        }
        // Reverse the order in the new pool.
        let new =
            EndpointPool::new_with_carryover(vec!["c:3".into(), "b:2".into(), "a:1".into()], &old)
                .unwrap();
        // a:1 is now at index 2 in new, but its counter MUST still
        // show 10 attempts — counters follow addr, not position.
        let a_in_new: Vec<_> = new
            .entries
            .iter()
            .find(|(addr, _)| addr == "a:1")
            .map(|(_, h)| h.counters().attempts)
            .into_iter()
            .collect();
        assert_eq!(a_in_new, vec![10]);
    }

    /// Adding a new entry: fresh health, zero counters.
    #[test]
    fn carryover_inserts_fresh_health_for_new_addrs() {
        let old = EndpointPool::new(vec!["a:1".into(), "b:2".into()]).unwrap();
        old.endpoint_health(0).unwrap().record_attempt();
        let new = EndpointPool::new_with_carryover(
            vec!["a:1".into(), "b:2".into(), "c:NEW".into()],
            &old,
        )
        .unwrap();
        assert_eq!(new.len(), 3);
        // c:NEW has fresh counters.
        let c_counters = new
            .entries
            .iter()
            .find(|(a, _)| a == "c:NEW")
            .map(|(_, h)| h.counters())
            .unwrap();
        assert_eq!(c_counters.attempts, 0);
        assert_eq!(c_counters.successes, 0);
        assert_eq!(c_counters.failures, 0);
        // a:1 still has its 1 attempt (carryover worked alongside
        // the new entry).
        assert_eq!(new.endpoint_health(0).unwrap().counters().attempts, 1);
    }

    /// Removing an entry: it just doesn't appear in the new pool;
    /// its Arc<EndpointHealth> is dropped (or kept alive by other
    /// holders — caller's concern).
    #[test]
    fn carryover_drops_removed_addrs() {
        let old = EndpointPool::new(vec!["a:1".into(), "b:2".into(), "c:3".into()]).unwrap();
        let new = EndpointPool::new_with_carryover(vec!["a:1".into(), "c:3".into()], &old).unwrap();
        assert_eq!(new.len(), 2);
        let addrs: Vec<&str> = new.addresses().collect();
        assert_eq!(addrs, vec!["a:1", "c:3"]);
    }

    /// Empty new list → None (semantically: operator turned the
    /// pool off entirely, falling back to single-endpoint mode).
    #[test]
    fn carryover_empty_list_returns_none() {
        let old = EndpointPool::new(vec!["a:1".into()]).unwrap();
        let new = EndpointPool::new_with_carryover(vec![], &old);
        assert!(new.is_none());
    }

    /// ReloadablePool: hot-swap a fresh pool, then `current()`
    /// returns the new one.
    #[test]
    fn reloadable_pool_swap_returns_new_pool_to_callers() {
        let initial = Arc::new(EndpointPool::new(vec!["a:1".into()]).unwrap());
        let r = ReloadablePool::new(Some(initial));
        assert_eq!(r.current().unwrap().len(), 1);
        let new = Arc::new(EndpointPool::new(vec!["x:1".into(), "y:2".into()]).unwrap());
        r.reload(Some(new));
        let curr = r.current().unwrap();
        assert_eq!(curr.len(), 2);
        let addrs: Vec<&str> = curr.addresses().collect();
        assert_eq!(addrs, vec!["x:1", "y:2"]);
    }

    /// ReloadablePool: clearing the pool drops back to None
    /// (single-endpoint dispatch mode).
    #[test]
    fn reloadable_pool_clear_falls_back_to_single_endpoint() {
        let initial = Arc::new(EndpointPool::new(vec!["a:1".into()]).unwrap());
        let r = ReloadablePool::new(Some(initial));
        r.reload(None);
        assert!(r.current().is_none());
    }

    /// ReloadablePool: reload counters increment on every call.
    #[test]
    fn reloadable_pool_reload_counters_increment() {
        let r = ReloadablePool::new(None);
        assert_eq!(r.reload_attempts(), 0);
        assert_eq!(r.reload_succeeded(), 0);
        r.reload(Some(Arc::new(
            EndpointPool::new(vec!["a:1".into()]).unwrap(),
        )));
        assert_eq!(r.reload_attempts(), 1);
        assert_eq!(r.reload_succeeded(), 1);
        r.reload(None);
        assert_eq!(r.reload_attempts(), 2);
        assert_eq!(r.reload_succeeded(), 2);
    }

    /// reload_from_addrs: end-to-end SIGHUP scenario — operator
    /// adds a backup VPS, primary's counters are preserved.
    #[test]
    fn reload_from_addrs_preserves_primary_counters_when_adding_backup() {
        let initial = Arc::new(EndpointPool::new(vec!["primary:8443".into()]).unwrap());
        // Bump primary's counter.
        for _ in 0..5 {
            initial.endpoint_health(0).unwrap().record_attempt();
            initial.endpoint_health(0).unwrap().record_success();
        }
        let r = ReloadablePool::new(Some(initial));
        // Operator adds a backup.
        let (prev_addrs, new_addrs) =
            r.reload_from_addrs(vec!["primary:8443".into(), "backup:8443".into()]);
        assert_eq!(prev_addrs, vec!["primary:8443"]);
        assert_eq!(new_addrs, vec!["primary:8443", "backup:8443"]);
        // Primary's counters survived.
        let curr = r.current().unwrap();
        assert_eq!(curr.endpoint_health(0).unwrap().counters().attempts, 5);
        assert_eq!(curr.endpoint_health(0).unwrap().counters().successes, 5);
        // Backup is fresh.
        assert_eq!(curr.endpoint_health(1).unwrap().counters().attempts, 0);
    }

    /// reload_from_addrs: empty list clears the pool.
    #[test]
    fn reload_from_addrs_empty_list_clears_pool() {
        let initial = Arc::new(EndpointPool::new(vec!["a:1".into()]).unwrap());
        let r = ReloadablePool::new(Some(initial));
        let (prev_addrs, new_addrs) = r.reload_from_addrs(vec![]);
        assert_eq!(prev_addrs, vec!["a:1"]);
        assert!(new_addrs.is_empty());
        assert!(r.current().is_none());
    }

    // ----- Iter-40 failed-attempt counter tests -----

    /// record_attempt_failed bumps attempts WITHOUT bumping succeeded
    /// — this is what makes the (attempts - succeeded) gap a true
    /// signal of failed SIGHUP events.
    #[test]
    fn record_attempt_failed_creates_gap() {
        let r = ReloadablePool::new(None);
        assert_eq!(r.reload_attempts(), 0);
        assert_eq!(r.reload_succeeded(), 0);

        r.record_attempt_failed();
        assert_eq!(
            r.reload_attempts(),
            1,
            "attempts must increment on failed reload"
        );
        assert_eq!(
            r.reload_succeeded(),
            0,
            "succeeded must NOT increment on failed reload"
        );
        // Gap = 1 — this is what the alert detects.
        assert_eq!(r.reload_attempts() - r.reload_succeeded(), 1);
    }

    /// Mixed sequence: real reloads succeed, failed-config events
    /// create asymmetry. Pre-iter-40 this asymmetry was impossible
    /// because every failure path silently no-oped — the alert
    /// could literally never fire.
    #[test]
    fn record_attempt_failed_interleaved_with_real_reloads() {
        let r = ReloadablePool::new(Some(Arc::new(
            EndpointPool::new(vec!["a:1".into()]).unwrap(),
        )));
        // Two good SIGHUPs.
        r.reload(Some(Arc::new(
            EndpointPool::new(vec!["b:2".into()]).unwrap(),
        )));
        r.reload(Some(Arc::new(
            EndpointPool::new(vec!["c:3".into()]).unwrap(),
        )));
        assert_eq!(r.reload_attempts(), 2);
        assert_eq!(r.reload_succeeded(), 2);

        // One bad SIGHUP (config parse failed in main.rs path).
        r.record_attempt_failed();
        assert_eq!(r.reload_attempts(), 3);
        assert_eq!(r.reload_succeeded(), 2);
        assert_eq!(
            r.reload_attempts() - r.reload_succeeded(),
            1,
            "gap == 1 → ProteusClientPoolReloadFailing fires"
        );

        // Subsequent good SIGHUP doesn't retroactively close the
        // gap — the failed event remains observable in the
        // cumulative totals. This is intentional: operators want
        // to see "you had 1 failed reload at some point" even
        // after subsequent successes, because the underlying
        // config-parse bug may still be lurking.
        r.reload(Some(Arc::new(
            EndpointPool::new(vec!["d:4".into()]).unwrap(),
        )));
        assert_eq!(r.reload_attempts(), 4);
        assert_eq!(r.reload_succeeded(), 3);
        assert_eq!(
            r.reload_attempts() - r.reload_succeeded(),
            1,
            "successful reload does NOT close the historical gap; \
             operator alerting still trips until the metric is reset \
             on process restart"
        );
    }

    /// Multiple consecutive failures all count.
    #[test]
    fn record_attempt_failed_accumulates() {
        let r = ReloadablePool::new(None);
        for _ in 0..5 {
            r.record_attempt_failed();
        }
        assert_eq!(r.reload_attempts(), 5);
        assert_eq!(r.reload_succeeded(), 0);
    }

    /// pool_addr_diff: standard add/remove case.
    #[test]
    fn pool_addr_diff_reports_added_and_removed() {
        let prev: Vec<String> = vec!["a:1".into(), "b:2".into(), "c:3".into()];
        let new: Vec<String> = vec!["a:1".into(), "c:3".into(), "d:NEW".into()];
        let (added, removed) = pool_addr_diff(&prev, &new);
        assert_eq!(added, vec!["d:NEW".to_string()]);
        assert_eq!(removed, vec!["b:2".to_string()]);
    }

    /// pool_addr_diff: no changes → empty diffs.
    #[test]
    fn pool_addr_diff_unchanged_returns_empty() {
        let v: Vec<String> = vec!["a:1".into(), "b:2".into()];
        let (added, removed) = pool_addr_diff(&v, &v);
        assert!(added.is_empty());
        assert!(removed.is_empty());
    }

    /// pool_addr_diff: order changes → empty diffs (we care about
    /// SET membership for diff purposes, not position).
    #[test]
    fn pool_addr_diff_order_only_changes_are_no_diff() {
        let prev: Vec<String> = vec!["a:1".into(), "b:2".into()];
        let new: Vec<String> = vec!["b:2".into(), "a:1".into()];
        let (added, removed) = pool_addr_diff(&prev, &new);
        assert!(added.is_empty());
        assert!(removed.is_empty());
    }
}
