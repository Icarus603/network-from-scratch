//! Shared per-process client context.
//!
//! Carries the runtime-mutable handles + cumulative counters that
//! were previously scattered across `main.rs` locals + `Arc` clones
//! threaded through every spawn. Consolidating them in a single type
//! means:
//!
//! - The admin `/status` snapshot can read in-flight session count
//!   and cumulative dial counters without a `&Semaphore` parameter
//!   threaded through admin::serve.
//! - The dispatch path (socks::handle_socks5_with_*) can bump
//!   counters without a second `&Counters` parameter.
//! - The drain logic in main.rs reads `available_permits()` from the
//!   same handle the admin endpoint reads.
//!
//! The fields are intentionally `pub` (not getter-wrapped). This is
//! a process-internal aggregate, not a public API surface — keeping
//! it transparent avoids boilerplate, and field names double as
//! documentation.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::Semaphore;

use crate::carrier_health::CarrierHealth;
use crate::endpoint_pool::EndpointPool;

/// Per-process shared context. Cheap to clone (the inner state is
/// behind `Arc` / atomics); typical usage is one `Arc<ClientCtx>`
/// created during startup, cloned into every spawned task.
#[derive(Clone)]
pub struct ClientCtx {
    /// β carrier health tracker. Always wired (β can be configured
    /// or not — that's a config concern; the tracker itself always
    /// exists so callers don't need to branch).
    pub carrier: Arc<CarrierHealth>,
    /// Multi-VPS endpoint pool. `None` for single-endpoint deploys.
    pub pool: Option<Arc<EndpointPool>>,
    /// Concurrency cap on in-flight SOCKS5 sessions. `None` when
    /// `max_inflight_sessions = 0` (cap disabled).
    pub session_slots: Option<Arc<Semaphore>>,
    /// Configured ceiling — used by the drain loop and the admin
    /// snapshot to compute "in-flight = max - available".
    pub max_inflight: usize,
    /// Cumulative dial counters. Each `handle_socks5_with_*` bumps
    /// `dials_attempted` on entry and `dials_succeeded` /
    /// `dials_failed` on exit (mutually exclusive). Operators read
    /// the difference as the in-flight count's longitudinal sum.
    pub dials_attempted: Arc<AtomicU64>,
    pub dials_succeeded: Arc<AtomicU64>,
    pub dials_failed: Arc<AtomicU64>,
    /// Whether β is configured (carrier health tracker presence
    /// doesn't tell us — it's always created).
    pub beta_configured: bool,
}

impl ClientCtx {
    /// Build from the runtime knobs decided at startup.
    #[must_use]
    pub fn new(
        carrier: Arc<CarrierHealth>,
        pool: Option<Arc<EndpointPool>>,
        session_slots: Option<Arc<Semaphore>>,
        max_inflight: usize,
        beta_configured: bool,
    ) -> Self {
        Self {
            carrier,
            pool,
            session_slots,
            max_inflight,
            dials_attempted: Arc::new(AtomicU64::new(0)),
            dials_succeeded: Arc::new(AtomicU64::new(0)),
            dials_failed: Arc::new(AtomicU64::new(0)),
            beta_configured,
        }
    }

    /// Current in-flight session count. Computed as `max_inflight -
    /// available_permits()` when the cap is configured; returns `None`
    /// when the cap is disabled (we don't track in-flight count
    /// without the semaphore as a source of truth).
    #[must_use]
    pub fn in_flight_sessions(&self) -> Option<usize> {
        self.session_slots
            .as_ref()
            .map(|s| self.max_inflight.saturating_sub(s.available_permits()))
    }

    /// Bump `dials_attempted`. Returns the new value (post-increment).
    pub fn record_dial_attempt(&self) -> u64 {
        self.dials_attempted.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Bump `dials_succeeded`. Returns the new value.
    pub fn record_dial_success(&self) -> u64 {
        self.dials_succeeded.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Bump `dials_failed`. Returns the new value.
    pub fn record_dial_failure(&self) -> u64 {
        self.dials_failed.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Snapshot of the three counters. Atomic per-field, NOT a
    /// consistent triple — readers don't need consistency here,
    /// they're cumulative totals.
    #[must_use]
    pub fn dial_counters(&self) -> DialCounters {
        DialCounters {
            attempted: self.dials_attempted.load(Ordering::Relaxed),
            succeeded: self.dials_succeeded.load(Ordering::Relaxed),
            failed: self.dials_failed.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of the three cumulative dial counters.
#[derive(Debug, Clone, Copy, Default)]
pub struct DialCounters {
    pub attempted: u64,
    pub succeeded: u64,
    pub failed: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_ctx(slots: Option<usize>, max_inflight: usize) -> ClientCtx {
        let sem = slots.map(|n| Arc::new(Semaphore::new(n)));
        ClientCtx::new(
            Arc::new(CarrierHealth::new()),
            None,
            sem,
            max_inflight,
            false,
        )
    }

    #[test]
    fn in_flight_returns_none_when_cap_disabled() {
        let ctx = mk_ctx(None, 0);
        assert!(ctx.in_flight_sessions().is_none());
    }

    #[test]
    fn in_flight_starts_at_zero_when_cap_configured() {
        let ctx = mk_ctx(Some(8), 8);
        assert_eq!(ctx.in_flight_sessions(), Some(0));
    }

    #[tokio::test]
    async fn in_flight_reflects_held_permits() {
        let ctx = mk_ctx(Some(4), 4);
        let sem = ctx.session_slots.as_ref().unwrap().clone();
        let _p1 = sem.acquire().await.unwrap();
        let _p2 = sem.acquire().await.unwrap();
        assert_eq!(ctx.in_flight_sessions(), Some(2));
    }

    #[test]
    fn dial_counters_start_at_zero() {
        let ctx = mk_ctx(Some(4), 4);
        let c = ctx.dial_counters();
        assert_eq!(c.attempted, 0);
        assert_eq!(c.succeeded, 0);
        assert_eq!(c.failed, 0);
    }

    #[test]
    fn record_dial_attempt_returns_post_increment_value() {
        let ctx = mk_ctx(None, 0);
        assert_eq!(ctx.record_dial_attempt(), 1);
        assert_eq!(ctx.record_dial_attempt(), 2);
        assert_eq!(ctx.dial_counters().attempted, 2);
    }

    #[test]
    fn record_dial_success_independently_of_attempts() {
        let ctx = mk_ctx(None, 0);
        ctx.record_dial_success();
        ctx.record_dial_success();
        ctx.record_dial_failure();
        let c = ctx.dial_counters();
        assert_eq!(c.attempted, 0);
        assert_eq!(c.succeeded, 2);
        assert_eq!(c.failed, 1);
    }

    #[test]
    fn typical_dial_lifecycle_bumps_attempt_then_outcome() {
        let ctx = mk_ctx(None, 0);
        // Simulate 10 dials: 7 succeed, 3 fail.
        for _ in 0..10 {
            ctx.record_dial_attempt();
        }
        for _ in 0..7 {
            ctx.record_dial_success();
        }
        for _ in 0..3 {
            ctx.record_dial_failure();
        }
        let c = ctx.dial_counters();
        assert_eq!(c.attempted, 10);
        assert_eq!(c.succeeded + c.failed, c.attempted);
    }
}
