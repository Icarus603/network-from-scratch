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
use crate::endpoint_pool::{EndpointPool, ReloadablePool};

/// Per-process shared context. Cheap to clone (the inner state is
/// behind `Arc` / atomics); typical usage is one `Arc<ClientCtx>`
/// created during startup, cloned into every spawned task.
#[derive(Clone)]
pub struct ClientCtx {
    /// β carrier health tracker. Always wired (β can be configured
    /// or not — that's a config concern; the tracker itself always
    /// exists so callers don't need to branch).
    pub carrier: Arc<CarrierHealth>,
    /// Multi-VPS endpoint pool — reloadable. Dispatch path reads
    /// the current pool via `reloadable_pool.current()` (one
    /// Arc-clone under a read-lock); SIGHUP reload swaps the inner
    /// pool transparently with per-entry counter carryover.
    /// `current()` returns `None` when no pool is configured
    /// (single-endpoint deployment); when `Some(_)`, dispatch walks
    /// the pool.
    pub reloadable_pool: ReloadablePool,
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
    /// Cumulative bootstrap-DNS resolution counters, partitioned by
    /// the path the resolver took. Bumped exactly once per
    /// successful `bootstrap::resolve_*` call (the dispatcher calls
    /// resolve once per per-pool-entry per-carrier try, so the sum
    /// of these three counters approximates the dispatcher's
    /// pre-dial activity volume).
    ///
    /// **Operator value**: a non-zero `bootstrap_via_system_resolver_total`
    /// in a deployment that was supposed to use `bootstrap_dns:
    /// direct_ip` is the silent signal that something in the config
    /// chain is wrong — either the YAML didn't apply, the operator
    /// edited the wrong file, or one of the `server_endpoints`
    /// entries is a hostname while others are IPs. Without these
    /// counters the misconfiguration is invisible until the GFW
    /// flags the bootstrap DoH (threat-intel main line 6).
    pub bootstrap_via_ip_literal: Arc<AtomicU64>,
    pub bootstrap_via_pinned_direct_ip: Arc<AtomicU64>,
    pub bootstrap_via_system_resolver: Arc<AtomicU64>,
    /// Whether β is configured (carrier health tracker presence
    /// doesn't tell us — it's always created).
    pub beta_configured: bool,
    /// Process-lifecycle info — captured once at startup, read at
    /// scrape time by the admin endpoint for the
    /// `proteus_client_process_*` Prometheus block + the `/status`
    /// "Process" section. Always present; `from_parts_for_tests`
    /// stubs let tests construct deterministic instances.
    pub process_info: Arc<proteus_transport_alpha::process_info::ProcessInfo>,
}

impl ClientCtx {
    /// Build from the runtime knobs decided at startup. `pool` is
    /// wrapped in a `ReloadablePool` so SIGHUP can hot-swap it.
    /// Process-lifecycle info captured here (default fields empty);
    /// the main binary calls [`Self::with_process_info`] to attach
    /// the real CARGO_PKG_VERSION / rustc / target metadata.
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
            reloadable_pool: ReloadablePool::new(pool),
            session_slots,
            max_inflight,
            dials_attempted: Arc::new(AtomicU64::new(0)),
            dials_succeeded: Arc::new(AtomicU64::new(0)),
            dials_failed: Arc::new(AtomicU64::new(0)),
            bootstrap_via_ip_literal: Arc::new(AtomicU64::new(0)),
            bootstrap_via_pinned_direct_ip: Arc::new(AtomicU64::new(0)),
            bootstrap_via_system_resolver: Arc::new(AtomicU64::new(0)),
            beta_configured,
            // Default process_info: empty strings + start_unix
            // captured at construction. Real binary overrides via
            // `with_process_info` so /metrics reports the actual
            // CARGO_PKG_VERSION + rustc + target.
            process_info: Arc::new(proteus_transport_alpha::process_info::ProcessInfo::capture(
                "", "", "",
            )),
        }
    }

    /// Replace the default empty `process_info` with operator-
    /// supplied build metadata. Used by `main.rs` to bake in
    /// `env!("CARGO_PKG_VERSION")` etc. Returns a fresh ctx
    /// (consumes self) so the field is set once-and-final at
    /// startup. Tests that don't care about process metadata use
    /// `new` directly.
    #[must_use]
    pub fn with_process_info(
        mut self,
        pi: Arc<proteus_transport_alpha::process_info::ProcessInfo>,
    ) -> Self {
        self.process_info = pi;
        self
    }

    /// Bump the appropriate bootstrap-resolver counter based on the
    /// `ResolvedVia` discriminator. Called by the dispatch path's
    /// resolve helper immediately after a successful resolution.
    pub fn record_bootstrap_resolution(&self, via: crate::bootstrap::ResolvedVia) {
        use crate::bootstrap::ResolvedVia;
        match via {
            ResolvedVia::IpLiteralInEndpoint => {
                self.bootstrap_via_ip_literal
                    .fetch_add(1, Ordering::Relaxed);
            }
            ResolvedVia::PinnedDirectIp => {
                self.bootstrap_via_pinned_direct_ip
                    .fetch_add(1, Ordering::Relaxed);
            }
            ResolvedVia::SystemResolver => {
                self.bootstrap_via_system_resolver
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Snapshot of the three bootstrap-resolver counters. Operators
    /// read these to verify their `bootstrap_dns: direct_ip` config
    /// is actually skipping the OS resolver. A non-zero
    /// `via_system_resolver` in a deployment that was supposed to
    /// be all-pinned-IPs is the misconfig signal — DoH transit is
    /// the 2026 GFW's bootstrap-layer attack vector (threat-intel
    /// main line 6).
    #[must_use]
    pub fn bootstrap_counters(&self) -> BootstrapCounters {
        BootstrapCounters {
            via_ip_literal: self.bootstrap_via_ip_literal.load(Ordering::Relaxed),
            via_pinned_direct_ip: self.bootstrap_via_pinned_direct_ip.load(Ordering::Relaxed),
            via_system_resolver: self.bootstrap_via_system_resolver.load(Ordering::Relaxed),
        }
    }

    /// Cheap-to-clone counter handle for the dispatch path. Threaded
    /// through `socks::handle_socks5_with_ctx` → `try_alpha` /
    /// `try_beta` so they can bump the bootstrap counters without
    /// holding a full `Arc<ClientCtx>` reference.
    #[must_use]
    pub fn bootstrap_counter_handles(&self) -> BootstrapCounterHandles {
        BootstrapCounterHandles {
            via_ip_literal: Arc::clone(&self.bootstrap_via_ip_literal),
            via_pinned_direct_ip: Arc::clone(&self.bootstrap_via_pinned_direct_ip),
            via_system_resolver: Arc::clone(&self.bootstrap_via_system_resolver),
        }
    }

    /// Current pool handle — cheap snapshot for the dispatch path.
    /// Equivalent to `self.reloadable_pool.current()`; exposed as a
    /// method so callers don't have to know about ReloadablePool's
    /// internals.
    #[must_use]
    pub fn pool(&self) -> Option<Arc<EndpointPool>> {
        self.reloadable_pool.current()
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

/// Cheap-to-clone handle on the three bootstrap-DNS counter
/// atomics. Threaded down the dispatch path to `try_alpha` /
/// `try_beta` so they can bump the counter without needing the
/// full `ClientCtx` as a parameter (which would couple the carrier-
/// transport layer to the SOCKS layer's context type).
///
/// Construct via [`ClientCtx::bootstrap_counter_handles`].
#[derive(Clone)]
pub struct BootstrapCounterHandles {
    pub via_ip_literal: Arc<AtomicU64>,
    pub via_pinned_direct_ip: Arc<AtomicU64>,
    pub via_system_resolver: Arc<AtomicU64>,
}

impl BootstrapCounterHandles {
    /// Bump the counter matching the resolution path. Same semantics
    /// as `ClientCtx::record_bootstrap_resolution` but doesn't
    /// require the full ctx.
    pub fn record(&self, via: crate::bootstrap::ResolvedVia) {
        use crate::bootstrap::ResolvedVia;
        let counter = match via {
            ResolvedVia::IpLiteralInEndpoint => &self.via_ip_literal,
            ResolvedVia::PinnedDirectIp => &self.via_pinned_direct_ip,
            ResolvedVia::SystemResolver => &self.via_system_resolver,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

/// Snapshot of the three bootstrap-DNS resolution counters,
/// partitioned by the path the resolver took. See
/// [`ClientCtx::record_bootstrap_resolution`] for the bump
/// semantics and [`ClientCtx::bootstrap_counters`] for the read
/// path.
#[derive(Debug, Clone, Copy, Default)]
pub struct BootstrapCounters {
    /// Resolutions where the endpoint string was already an IP
    /// literal — no DNS consulted at all. Anti-censorship-strongest
    /// path; ideally where every resolution lands in a production
    /// deploy that pins literal IPs in `server_endpoints:`.
    pub via_ip_literal: u64,
    /// Resolutions where `bootstrap_dns: direct_ip: X` matched a
    /// hostname endpoint and `X:port` was used directly. Also
    /// DNS-skipping; the operator's preferred path when they want
    /// the hostname visible in YAML for SNI clarity.
    pub via_pinned_direct_ip: u64,
    /// Resolutions that went through `tokio::net::lookup_host` →
    /// OS resolver chain. **The path the 2026 GFW DoH-identification
    /// attack targets.** A non-zero count here in a deployment that
    /// was supposed to be all-pinned is the misconfig signal.
    pub via_system_resolver: u64,
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
    fn bootstrap_counters_start_at_zero() {
        let ctx = mk_ctx(None, 0);
        let b = ctx.bootstrap_counters();
        assert_eq!(b.via_ip_literal, 0);
        assert_eq!(b.via_pinned_direct_ip, 0);
        assert_eq!(b.via_system_resolver, 0);
    }

    #[test]
    fn record_bootstrap_resolution_bumps_correct_counter() {
        use crate::bootstrap::ResolvedVia;
        let ctx = mk_ctx(None, 0);
        ctx.record_bootstrap_resolution(ResolvedVia::IpLiteralInEndpoint);
        ctx.record_bootstrap_resolution(ResolvedVia::IpLiteralInEndpoint);
        ctx.record_bootstrap_resolution(ResolvedVia::PinnedDirectIp);
        ctx.record_bootstrap_resolution(ResolvedVia::SystemResolver);
        let b = ctx.bootstrap_counters();
        assert_eq!(b.via_ip_literal, 2);
        assert_eq!(b.via_pinned_direct_ip, 1);
        assert_eq!(b.via_system_resolver, 1);
    }

    #[test]
    fn bootstrap_counter_handles_bump_same_atomics_as_ctx() {
        use crate::bootstrap::ResolvedVia;
        let ctx = mk_ctx(None, 0);
        let handles = ctx.bootstrap_counter_handles();
        // Bump via the handle (the path the dispatch uses).
        handles.record(ResolvedVia::PinnedDirectIp);
        handles.record(ResolvedVia::PinnedDirectIp);
        handles.record(ResolvedVia::SystemResolver);
        // Reading through ctx must see the same values — handles
        // and ctx share the same Arc<AtomicU64>.
        let b = ctx.bootstrap_counters();
        assert_eq!(b.via_pinned_direct_ip, 2);
        assert_eq!(b.via_system_resolver, 1);
        assert_eq!(b.via_ip_literal, 0);
    }

    #[test]
    fn process_info_defaults_to_empty_build_metadata() {
        let ctx = mk_ctx(None, 0);
        assert!(ctx.process_info.version.is_empty());
        assert!(ctx.process_info.rustc.is_empty());
        assert!(ctx.process_info.target.is_empty());
        // start_unix and uptime are set even with empty metadata.
        assert!(ctx.process_info.start_unix_seconds() > 0);
    }

    #[test]
    fn with_process_info_overrides_default_metadata() {
        let custom = Arc::new(proteus_transport_alpha::process_info::ProcessInfo::capture(
            "0.5.0",
            "1.85.0",
            "aarch64-unknown-linux-gnu",
        ));
        let ctx = mk_ctx(None, 0).with_process_info(Arc::clone(&custom));
        assert_eq!(&*ctx.process_info.version, "0.5.0");
        assert_eq!(&*ctx.process_info.rustc, "1.85.0");
        assert_eq!(&*ctx.process_info.target, "aarch64-unknown-linux-gnu");
        // The Arc is the SAME instance (shared, not cloned).
        assert!(Arc::ptr_eq(&ctx.process_info, &custom));
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
