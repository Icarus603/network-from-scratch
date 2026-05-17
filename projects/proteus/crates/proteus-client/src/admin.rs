//! Client-side admin / observability surface.
//!
//! Symmetric to `proteus-server`'s `admin.rs`: an opt-in loopback HTTP
//! endpoint exposing the in-process health state so an operator can
//! answer "what is my client doing right now?" without `grep
//! journalctl` for transition lines.
//!
//! ## What this surfaces
//!
//! - **CarrierHealth (β-vs-α)**: configured? alive? suppressed? for
//!   how much longer? what's the current failure streak?
//! - **EndpointPool / EndpointHealth (multi-VPS)**: configured? how
//!   many entries? for each entry: address, suppressed?, expires-in,
//!   streak.
//!
//! ## What this is NOT
//!
//! - Not a Prometheus exporter. The client process is per-user, not
//!   per-fleet — the right tool for "is my proxy working" is a `curl
//!   :9091/status` from the operator's shell, not a metrics-scrape
//!   pipeline. JSON output is provided for scripted consumption (e.g.
//!   a small status-bar widget) but the schema is hand-rolled to keep
//!   the dependency surface minimal.
//! - Not authenticated. The endpoint binds loopback-only by default;
//!   on a personal-VPN client deployment, anything that can reach
//!   `127.0.0.1` already has the process's identity. If an operator
//!   binds to a non-loopback address, they get a startup `warn!` line.
//!   No bearer-token gating because there's no useful threat model in
//!   the personal-client deployment (server's `/metrics` is
//!   different because it's often exposed for fleet observability;
//!   the client status is loopback-only and personal).
//!
//! ## What's missing here (future iterations)
//!
//! - SOCKS5 in-flight session count exposed in the snapshot. Today
//!   the slot semaphore lives in `main.rs`; threading its
//!   `available_permits()` through the admin surface needs the
//!   semaphore to be a first-class field of a shared `ClientCtx` —
//!   refactor work; not in this iteration.
//! - Per-session byte counters. The server tracks these; the client
//!   could mirror but the data path doesn't currently bump anything.

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{info, warn};

use crate::carrier_health::CarrierHealth;
use crate::ctx::{BootstrapCounters, ClientCtx, DialCounters};
use crate::endpoint_pool::EndpointPool;

/// In-process snapshot built at scrape time. All fields are `Option`
/// because the client may be running without one or both of the
/// health trackers (e.g. β not configured, or single-endpoint
/// deployment without a pool).
#[derive(Debug, Clone, Default)]
pub struct ClientStatusSnapshot {
    /// `true` once the SOCKS5 listener has bound and we accept
    /// inbound. Used for a `/healthz` style probe.
    pub alive: bool,
    /// β carrier health, when β is configured. `None` means α-only
    /// (no β endpoint was supplied, so β suppression state is N/A).
    pub carrier: Option<CarrierHealthView>,
    /// Multi-VPS endpoint pool state, when one was wired. `None`
    /// means single-endpoint deployment (legacy `server_endpoint`
    /// only, no `server_endpoints: [...]`).
    pub pool: Option<EndpointPoolView>,
    /// Concurrency view — in-flight session count + configured cap.
    /// `None` when `max_inflight_sessions = 0` (cap disabled).
    pub concurrency: Option<ConcurrencyView>,
    /// Cumulative dial counters. Always present; zero-valued when
    /// no CONNECTs have been dispatched yet.
    pub dials: DialCounters,
    /// Reload-attempt / reload-success counters from the
    /// ReloadablePool — operators verify SIGHUP took effect by
    /// watching these increment. Always present; zero-valued at
    /// startup.
    pub pool_reload: PoolReloadCounters,
    /// Bootstrap-DNS resolution counters partitioned by path
    /// (ip-literal / pinned-direct-ip / system-resolver). Always
    /// present; zero-valued before any CONNECT has been
    /// dispatched. Critical for verifying `bootstrap_dns: direct_ip`
    /// is actually skipping the OS resolver — a non-zero
    /// `via_system_resolver` in a deployment that was supposed to
    /// be all-pinned is the silent-misconfig signal (threat-intel
    /// main line 6: DoH identification).
    pub bootstrap: BootstrapCounters,
    /// Process-lifecycle snapshot — start time, uptime, build
    /// metadata. Always present; rendered on `/status` text /
    /// JSON / `/metrics` with the `proteus_client_process_*`
    /// prefix so a single Prometheus instance can scrape both
    /// client and server without collisions.
    pub process: ProcessView,
}

/// Operator-friendly process view rendered from a
/// `transport_alpha::process_info::ProcessInfo`. Field-by-field
/// shadow so `ClientStatusSnapshot` doesn't expose the underlying
/// Arc — JSON output stays the same shape regardless of how the
/// upstream type evolves.
#[derive(Debug, Clone, Default)]
pub struct ProcessView {
    pub start_unix_seconds: i64,
    pub uptime_seconds: u64,
    pub version: String,
    pub rustc: String,
    pub target: String,
}

/// Snapshot of the ReloadablePool's cumulative reload counters.
/// `attempts - succeeded` is always zero today (reload doesn't have
/// a failure case at the swap layer; YAML-load failures are logged
/// but don't reach the swap), but the shape is kept symmetric with
/// the server's TLS-reload counters for operator muscle memory.
#[derive(Debug, Clone, Copy, Default)]
pub struct PoolReloadCounters {
    pub attempts: u64,
    pub succeeded: u64,
}

/// Concurrency view rendered from the slot semaphore + configured
/// ceiling. Operator gets "how saturated am I" in one place.
#[derive(Debug, Clone, Copy)]
pub struct ConcurrencyView {
    /// Active SOCKS5 sessions right now.
    pub in_flight: u64,
    /// Configured `max_inflight_sessions`.
    pub max_inflight: u64,
}

/// Single-host carrier-health view rendered from a `CarrierHealth`.
#[derive(Debug, Clone)]
pub struct CarrierHealthView {
    /// Current consecutive-failure streak count (resets to 0 on any
    /// β success). Above the threshold the carrier transitions to
    /// suppressed.
    pub failure_streak: u32,
    /// `true` iff β is currently inside a back-off window.
    pub suppressed: bool,
    /// Seconds remaining in the back-off window when suppressed;
    /// `None` when not suppressed.
    pub suppression_secs_remaining: Option<u64>,
}

/// Per-entry pool view rendered from `EndpointPool`. Operator gets
/// "which VPS is the dispatcher currently using" + "which are
/// suppressed and for how much longer" without grepping logs.
#[derive(Debug, Clone)]
pub struct EndpointPoolView {
    pub entries: Vec<EndpointEntryView>,
}

#[derive(Debug, Clone, Default)]
pub struct EndpointEntryView {
    pub addr: String,
    pub failure_streak: u32,
    pub suppressed: bool,
    pub suppression_secs_remaining: Option<u64>,
    /// Lifetime attempts against this entry (sourced from
    /// `EndpointHealth::counters().attempts`). Operators read the
    /// per-entry success rate as `successes / attempts` and demote
    /// chronic-flaky entries based on it.
    pub attempts_total: u64,
    /// Lifetime successes against this entry.
    pub successes_total: u64,
    /// Lifetime failures against this entry.
    pub failures_total: u64,
}

impl ClientStatusSnapshot {
    /// Build a snapshot from a live [`ClientCtx`] + the alive flag.
    /// This is the production path — the one the admin endpoint
    /// uses. Carries through every field including the concurrency
    /// view and cumulative dial counters.
    #[must_use]
    pub fn from_ctx(alive: bool, ctx: &ClientCtx, now: Instant) -> Self {
        // Snapshot the pool once so the rest of from_ctx works
        // against a consistent Arc — a SIGHUP between capture and
        // any future reads would otherwise risk surfacing
        // half-replaced state.
        let pool = ctx.pool();
        let mut snap = Self::capture(
            alive,
            Some(&ctx.carrier),
            ctx.beta_configured,
            pool.as_deref(),
            now,
        );
        // If β isn't configured, downgrade the carrier view back to
        // None — operator should see "carrier: not configured" not
        // "carrier: healthy" when there's no β endpoint at all. The
        // capture() helper above doesn't know about beta_configured
        // (it always returns carrier=Some when a tracker is supplied)
        // so we patch it here. This keeps capture() the
        // tracker-state-only primitive and from_ctx() the
        // policy-aware view.
        if !ctx.beta_configured {
            snap.carrier = None;
        }
        snap.concurrency = ctx.in_flight_sessions().map(|n| ConcurrencyView {
            in_flight: n as u64,
            max_inflight: ctx.max_inflight as u64,
        });
        snap.dials = ctx.dial_counters();
        snap.pool_reload = PoolReloadCounters {
            attempts: ctx.reloadable_pool.reload_attempts(),
            succeeded: ctx.reloadable_pool.reload_succeeded(),
        };
        snap.bootstrap = ctx.bootstrap_counters();
        snap.process = ProcessView {
            start_unix_seconds: ctx.process_info.start_unix_seconds(),
            uptime_seconds: ctx.process_info.uptime_seconds(),
            version: ctx.process_info.version.to_string(),
            rustc: ctx.process_info.rustc.to_string(),
            target: ctx.process_info.target.to_string(),
        };
        snap
    }

    /// Build a snapshot from the live in-process state at instant
    /// `now`. Pure read — no mutation, no atomics touched besides
    /// the existing accessors.
    ///
    /// **Note**: this lower-level constructor does NOT populate
    /// `concurrency` or `dials` — use [`Self::from_ctx`] for the
    /// full snapshot. `capture` is kept for tests that drive
    /// individual fields without building a full `ClientCtx`.
    #[must_use]
    pub fn capture(
        alive: bool,
        carrier: Option<&CarrierHealth>,
        beta_configured: bool,
        pool: Option<&EndpointPool>,
        now: Instant,
    ) -> Self {
        let carrier_view = carrier.map(|h| {
            let suppressed = h.is_suppressed(now);
            let suppression_secs_remaining = if suppressed {
                h.suppression_deadline().map(|d| {
                    // saturating_duration_since returns 0 if the
                    // deadline is in the past (shouldn't happen
                    // when is_suppressed says yes, but defense-in-
                    // depth — we never want a negative number here).
                    d.saturating_duration_since(now).as_secs()
                })
            } else {
                None
            };
            // β-not-configured collapses suppression state to N/A
            // by zeroing it out — a config without β shouldn't
            // surface "suppressed = false" as if β were live but
            // healthy. We model "β unwired" as carrier = None
            // upstream of this view, so the explicit guard here is
            // belt-and-braces.
            let _ = beta_configured;
            CarrierHealthView {
                failure_streak: h.failure_streak(),
                suppressed,
                suppression_secs_remaining,
            }
        });
        let pool_view = pool.map(|p| {
            let snap = p.diagnostic_snapshot(now);
            let entries = snap
                .into_iter()
                .enumerate()
                .map(|(ix, (addr, streak, suppressed))| {
                    let secs = if suppressed {
                        p.endpoint_health(ix).and_then(|h| {
                            // Pool's diagnostic_snapshot doesn't
                            // expose the deadline directly; fetch
                            // the health handle and compute.
                            //
                            // Note: EndpointHealth currently lacks a
                            // public suppression_deadline accessor;
                            // we fall back to None when the pool
                            // says suppressed but we can't read the
                            // deadline. This is a small information
                            // gap (operator sees "suppressed" but
                            // not "for how long") — fix-up next
                            // iteration when EndpointHealth grows
                            // the accessor.
                            let _ = h;
                            None
                        })
                    } else {
                        None
                    };
                    // Read the new per-entry cumulative counters.
                    // Default to zero-valued if the EndpointHealth
                    // can't be fetched (shouldn't happen — index is
                    // from diagnostic_snapshot's enumeration).
                    let counters = p
                        .endpoint_health(ix)
                        .map(|h| h.counters())
                        .unwrap_or_default();
                    EndpointEntryView {
                        addr,
                        failure_streak: streak,
                        suppressed,
                        suppression_secs_remaining: secs,
                        attempts_total: counters.attempts,
                        successes_total: counters.successes,
                        failures_total: counters.failures,
                    }
                })
                .collect();
            EndpointPoolView { entries }
        });
        Self {
            alive,
            carrier: carrier_view,
            pool: pool_view,
            // `capture` is the low-level constructor — concurrency,
            // dials, and pool_reload are populated by `from_ctx`
            // which has access to the `ClientCtx`. Tests that call
            // `capture` directly get default-zero values here.
            concurrency: None,
            dials: DialCounters::default(),
            pool_reload: PoolReloadCounters::default(),
            bootstrap: BootstrapCounters::default(),
            process: ProcessView::default(),
        }
    }

    /// Hand-rolled JSON. Single line + trailing newline; same
    /// streaming-jq-friendly shape as the bench harness's
    /// `RunReport`. Field order is stable across releases;
    /// additions append, never reorder or rename.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(512);
        s.push('{');
        s.push_str(r#""alive":"#);
        s.push_str(if self.alive { "true" } else { "false" });

        // carrier: nested object or null.
        s.push_str(r#","carrier":"#);
        match &self.carrier {
            None => s.push_str("null"),
            Some(c) => {
                s.push('{');
                let _ = write!(s, r#""failure_streak":{}"#, c.failure_streak);
                s.push_str(r#","suppressed":"#);
                s.push_str(if c.suppressed { "true" } else { "false" });
                s.push_str(r#","suppression_secs_remaining":"#);
                match c.suppression_secs_remaining {
                    Some(v) => {
                        let _ = write!(s, "{v}");
                    }
                    None => s.push_str("null"),
                }
                s.push('}');
            }
        }

        // pool: nested array-of-objects or null.
        s.push_str(r#","pool":"#);
        match &self.pool {
            None => s.push_str("null"),
            Some(p) => {
                s.push('[');
                let mut first = true;
                for e in &p.entries {
                    if !first {
                        s.push(',');
                    }
                    first = false;
                    s.push_str(r#"{"addr":""#);
                    push_json_str_inner(&mut s, &e.addr);
                    let _ = write!(s, r#"","failure_streak":{}"#, e.failure_streak);
                    s.push_str(r#","suppressed":"#);
                    s.push_str(if e.suppressed { "true" } else { "false" });
                    s.push_str(r#","suppression_secs_remaining":"#);
                    match e.suppression_secs_remaining {
                        Some(v) => {
                            let _ = write!(s, "{v}");
                        }
                        None => s.push_str("null"),
                    }
                    let _ = write!(
                        s,
                        r#","attempts_total":{},"successes_total":{},"failures_total":{}"#,
                        e.attempts_total, e.successes_total, e.failures_total
                    );
                    s.push('}');
                }
                s.push(']');
            }
        }

        // concurrency: nested object or null. Operators script
        // saturation alerts against the `in_flight / max_inflight`
        // ratio (PromQL-equivalent: client-side saturation gauge).
        s.push_str(r#","concurrency":"#);
        match self.concurrency {
            None => s.push_str("null"),
            Some(c) => {
                let _ = write!(
                    s,
                    r#"{{"in_flight":{},"max_inflight":{}}}"#,
                    c.in_flight, c.max_inflight
                );
            }
        }

        // dials: cumulative counters. Always emitted so scripts can
        // rely on the field's presence (zero-valued when nothing's
        // happened yet).
        s.push_str(r#","dials":"#);
        let _ = write!(
            s,
            r#"{{"attempted":{},"succeeded":{},"failed":{}}}"#,
            self.dials.attempted, self.dials.succeeded, self.dials.failed
        );

        // pool_reload: SIGHUP reload counters. Always emitted —
        // operators alert when `attempts > succeeded` (the swap
        // layer doesn't fail today, but the YAML-load step
        // upstream of it can — see main.rs SIGHUP handler).
        s.push_str(r#","pool_reload":"#);
        let _ = write!(
            s,
            r#"{{"attempts":{},"succeeded":{}}}"#,
            self.pool_reload.attempts, self.pool_reload.succeeded
        );

        // bootstrap: DNS resolution counters partitioned by path.
        // Always emitted; operators alert on
        // `via_system_resolver > 0` when their deployment was
        // supposed to be all-pinned-IP (= silent DoH leak).
        s.push_str(r#","bootstrap":"#);
        let _ = write!(
            s,
            r#"{{"via_ip_literal":{},"via_pinned_direct_ip":{},"via_system_resolver":{}}}"#,
            self.bootstrap.via_ip_literal,
            self.bootstrap.via_pinned_direct_ip,
            self.bootstrap.via_system_resolver
        );

        // process: start_unix + uptime + build metadata.
        // Always emitted (start_unix is captured at ctx
        // construction, never absent).
        s.push_str(r#","process":{"start_unix_seconds":"#);
        let _ = write!(s, "{}", self.process.start_unix_seconds);
        s.push_str(r#","uptime_seconds":"#);
        let _ = write!(s, "{}", self.process.uptime_seconds);
        s.push_str(r#","version":""#);
        push_json_str_inner(&mut s, &self.process.version);
        s.push_str(r#"","rustc":""#);
        push_json_str_inner(&mut s, &self.process.rustc);
        s.push_str(r#"","target":""#);
        push_json_str_inner(&mut s, &self.process.target);
        s.push_str(r#""}"#);

        s.push_str("}\n");
        s
    }
}

/// JSON-quote inner-string escaping. Same minimal set as the bench
/// harness's `RunReport` — quotes, backslashes, and the three
/// control characters that JSON forbids unquoted.
fn push_json_str_inner(s: &mut String, v: &str) {
    for c in v.chars() {
        match c {
            '"' => s.push_str(r#"\""#),
            '\\' => s.push_str(r#"\\"#),
            '\n' => s.push_str(r#"\n"#),
            '\r' => s.push_str(r#"\r"#),
            '\t' => s.push_str(r#"\t"#),
            c if (c as u32) < 0x20 => {
                let _ = write!(s, r#"\u{:04x}"#, c as u32);
            }
            c => s.push(c),
        }
    }
}

impl ClientStatusSnapshot {
    /// Emit Prometheus 0.0.4 text exposition. Stable metric names
    /// (`proteus_client_*` prefix) so a single Prometheus instance
    /// can scrape both server and client without collisions.
    ///
    /// Series shape:
    ///   - `proteus_client_up` (gauge 0/1) — SOCKS5 listener bound
    ///   - `proteus_client_dials_attempted_total` (counter)
    ///   - `proteus_client_dials_succeeded_total` (counter)
    ///   - `proteus_client_dials_failed_total` (counter)
    ///   - `proteus_client_in_flight_sessions` (gauge; omitted when
    ///     cap disabled)
    ///   - `proteus_client_max_inflight_sessions` (gauge; same omission)
    ///   - `proteus_client_carrier_suppressed` (gauge 0/1; omitted
    ///     when β unconfigured)
    ///   - `proteus_client_carrier_failure_streak` (gauge; same)
    ///   - `proteus_client_carrier_suppression_secs_remaining` (gauge;
    ///     emitted only while currently suppressed)
    ///   - `proteus_client_endpoint_attempts_total{addr="..."}`
    ///   - `proteus_client_endpoint_successes_total{addr="..."}`
    ///   - `proteus_client_endpoint_failures_total{addr="..."}`
    ///   - `proteus_client_endpoint_suppressed{addr="..."}` (gauge 0/1)
    ///   - `proteus_client_endpoint_failure_streak{addr="..."}` (gauge)
    ///   - `proteus_client_endpoint_suppression_secs_remaining{addr="..."}`
    ///     (gauge; emitted only while currently suppressed)
    ///
    /// Per-endpoint series are labelled with the entry's `addr` so a
    /// single PromQL `sum by (addr)(rate(proteus_client_endpoint_failures_total[5m]))`
    /// surfaces "which VPS am I currently demoting" without operator
    /// intervention.
    #[must_use]
    pub fn to_prometheus(&self) -> String {
        let mut s = String::with_capacity(1024);
        use std::fmt::Write;

        // up gauge — symmetric with server's `proteus_up`.
        let _ = writeln!(
            s,
            "# HELP proteus_client_up SOCKS5 listener bound and accepting."
        );
        let _ = writeln!(s, "# TYPE proteus_client_up gauge");
        let _ = writeln!(s, "proteus_client_up {}", if self.alive { 1 } else { 0 });

        // Global dial counters.
        let _ = writeln!(
            s,
            "# HELP proteus_client_dials_attempted_total Lifetime SOCKS5 CONNECTs dispatched (every try)."
        );
        let _ = writeln!(s, "# TYPE proteus_client_dials_attempted_total counter");
        let _ = writeln!(
            s,
            "proteus_client_dials_attempted_total {}",
            self.dials.attempted
        );
        let _ = writeln!(
            s,
            "# HELP proteus_client_dials_succeeded_total Subset of dials_attempted_total that returned Ok."
        );
        let _ = writeln!(s, "# TYPE proteus_client_dials_succeeded_total counter");
        let _ = writeln!(
            s,
            "proteus_client_dials_succeeded_total {}",
            self.dials.succeeded
        );
        let _ = writeln!(
            s,
            "# HELP proteus_client_dials_failed_total Subset of dials_attempted_total that returned Err."
        );
        let _ = writeln!(s, "# TYPE proteus_client_dials_failed_total counter");
        let _ = writeln!(s, "proteus_client_dials_failed_total {}", self.dials.failed);

        // Bootstrap-DNS resolution counters — partitioned by path.
        // Always emitted from t=0 so PromQL `rate(...)` doesn't see
        // absent-counter gaps. Operators alert on:
        //   rate(proteus_client_bootstrap_via_system_resolver_total[5m]) > 0
        // for a deployment intended to be all-pinned-IP — the 2026
        // GFW DoH-identification attack vector silently bypassed.
        let _ = writeln!(
            s,
            "# HELP proteus_client_bootstrap_via_ip_literal_total Bootstrap resolutions where the endpoint was already an IP literal."
        );
        let _ = writeln!(
            s,
            "# TYPE proteus_client_bootstrap_via_ip_literal_total counter"
        );
        let _ = writeln!(
            s,
            "proteus_client_bootstrap_via_ip_literal_total {}",
            self.bootstrap.via_ip_literal
        );
        let _ = writeln!(
            s,
            "# HELP proteus_client_bootstrap_via_pinned_direct_ip_total Bootstrap resolutions that used bootstrap_dns.direct_ip — DNS skipped."
        );
        let _ = writeln!(
            s,
            "# TYPE proteus_client_bootstrap_via_pinned_direct_ip_total counter"
        );
        let _ = writeln!(
            s,
            "proteus_client_bootstrap_via_pinned_direct_ip_total {}",
            self.bootstrap.via_pinned_direct_ip
        );
        let _ = writeln!(
            s,
            "# HELP proteus_client_bootstrap_via_system_resolver_total Bootstrap resolutions that transited the OS resolver (DoH-vulnerable per 2026 GFW threat intel)."
        );
        let _ = writeln!(
            s,
            "# TYPE proteus_client_bootstrap_via_system_resolver_total counter"
        );
        let _ = writeln!(
            s,
            "proteus_client_bootstrap_via_system_resolver_total {}",
            self.bootstrap.via_system_resolver
        );

        // Pool reload counters — symmetric with the server-side
        // proteus_tls_reload_attempts_total / _succeeded_total.
        // Always emitted (zero-valued at startup) so PromQL
        // `rate(proteus_client_pool_reload_attempts_total[5m])`
        // doesn't see absent-counter gaps.
        let _ = writeln!(
            s,
            "# HELP proteus_client_pool_reload_attempts_total SIGHUP-style endpoint pool reload attempts."
        );
        let _ = writeln!(
            s,
            "# TYPE proteus_client_pool_reload_attempts_total counter"
        );
        let _ = writeln!(
            s,
            "proteus_client_pool_reload_attempts_total {}",
            self.pool_reload.attempts
        );
        let _ = writeln!(
            s,
            "# HELP proteus_client_pool_reload_succeeded_total Reloads that completed the atomic swap."
        );
        let _ = writeln!(
            s,
            "# TYPE proteus_client_pool_reload_succeeded_total counter"
        );
        let _ = writeln!(
            s,
            "proteus_client_pool_reload_succeeded_total {}",
            self.pool_reload.succeeded
        );

        // Concurrency (omit when cap disabled — operator sees the
        // "no series" as "no cap" rather than a confusing zero).
        if let Some(c) = self.concurrency {
            let _ = writeln!(
                s,
                "# HELP proteus_client_in_flight_sessions Active SOCKS5 sessions right now."
            );
            let _ = writeln!(s, "# TYPE proteus_client_in_flight_sessions gauge");
            let _ = writeln!(s, "proteus_client_in_flight_sessions {}", c.in_flight);
            let _ = writeln!(
                s,
                "# HELP proteus_client_max_inflight_sessions Configured concurrency cap."
            );
            let _ = writeln!(s, "# TYPE proteus_client_max_inflight_sessions gauge");
            let _ = writeln!(s, "proteus_client_max_inflight_sessions {}", c.max_inflight);
        }

        // Carrier (β) — omitted entirely when β isn't configured.
        if let Some(cv) = &self.carrier {
            let _ = writeln!(
                s,
                "# HELP proteus_client_carrier_suppressed β carrier suppression state (1 = suppressed)."
            );
            let _ = writeln!(s, "# TYPE proteus_client_carrier_suppressed gauge");
            let _ = writeln!(
                s,
                "proteus_client_carrier_suppressed {}",
                if cv.suppressed { 1 } else { 0 }
            );
            let _ = writeln!(
                s,
                "# HELP proteus_client_carrier_failure_streak Consecutive β failures (resets on success)."
            );
            let _ = writeln!(s, "# TYPE proteus_client_carrier_failure_streak gauge");
            let _ = writeln!(
                s,
                "proteus_client_carrier_failure_streak {}",
                cv.failure_streak
            );
            if let Some(secs) = cv.suppression_secs_remaining {
                let _ = writeln!(
                    s,
                    "# HELP proteus_client_carrier_suppression_secs_remaining Seconds left in the current β back-off window."
                );
                let _ = writeln!(
                    s,
                    "# TYPE proteus_client_carrier_suppression_secs_remaining gauge"
                );
                let _ = writeln!(
                    s,
                    "proteus_client_carrier_suppression_secs_remaining {secs}"
                );
            }
        }

        // Per-endpoint pool series — labelled. Emit HELP/TYPE rows
        // ONCE before the labelled values (Prometheus 0.0.4 requires
        // exactly one HELP per metric name; subsequent values on
        // different label sets share it).
        if let Some(p) = &self.pool {
            if !p.entries.is_empty() {
                let _ = writeln!(
                    s,
                    "# HELP proteus_client_endpoint_attempts_total Per-endpoint lifetime CONNECT attempts."
                );
                let _ = writeln!(s, "# TYPE proteus_client_endpoint_attempts_total counter");
                for e in &p.entries {
                    let _ = writeln!(
                        s,
                        r#"proteus_client_endpoint_attempts_total{{addr="{}"}} {}"#,
                        escape_label(&e.addr),
                        e.attempts_total
                    );
                }
                let _ = writeln!(
                    s,
                    "# HELP proteus_client_endpoint_successes_total Per-endpoint lifetime CONNECT successes."
                );
                let _ = writeln!(s, "# TYPE proteus_client_endpoint_successes_total counter");
                for e in &p.entries {
                    let _ = writeln!(
                        s,
                        r#"proteus_client_endpoint_successes_total{{addr="{}"}} {}"#,
                        escape_label(&e.addr),
                        e.successes_total
                    );
                }
                let _ = writeln!(
                    s,
                    "# HELP proteus_client_endpoint_failures_total Per-endpoint lifetime CONNECT failures."
                );
                let _ = writeln!(s, "# TYPE proteus_client_endpoint_failures_total counter");
                for e in &p.entries {
                    let _ = writeln!(
                        s,
                        r#"proteus_client_endpoint_failures_total{{addr="{}"}} {}"#,
                        escape_label(&e.addr),
                        e.failures_total
                    );
                }
                let _ = writeln!(
                    s,
                    "# HELP proteus_client_endpoint_suppressed Per-endpoint suppression state (1 = suppressed)."
                );
                let _ = writeln!(s, "# TYPE proteus_client_endpoint_suppressed gauge");
                for e in &p.entries {
                    let _ = writeln!(
                        s,
                        r#"proteus_client_endpoint_suppressed{{addr="{}"}} {}"#,
                        escape_label(&e.addr),
                        if e.suppressed { 1 } else { 0 }
                    );
                }
                let _ = writeln!(
                    s,
                    "# HELP proteus_client_endpoint_failure_streak Per-endpoint consecutive failure count."
                );
                let _ = writeln!(s, "# TYPE proteus_client_endpoint_failure_streak gauge");
                for e in &p.entries {
                    let _ = writeln!(
                        s,
                        r#"proteus_client_endpoint_failure_streak{{addr="{}"}} {}"#,
                        escape_label(&e.addr),
                        e.failure_streak
                    );
                }
                // suppression_secs_remaining: only emit for currently-
                // suppressed entries — otherwise the gauge would be
                // perpetually zero for healthy entries, which Grafana's
                // "absent or zero" alerting can't distinguish.
                let suppressed: Vec<_> = p
                    .entries
                    .iter()
                    .filter(|e| e.suppression_secs_remaining.is_some())
                    .collect();
                if !suppressed.is_empty() {
                    let _ = writeln!(
                        s,
                        "# HELP proteus_client_endpoint_suppression_secs_remaining Seconds left in each suppressed entry's back-off window."
                    );
                    let _ = writeln!(
                        s,
                        "# TYPE proteus_client_endpoint_suppression_secs_remaining gauge"
                    );
                    for e in suppressed {
                        let secs = e.suppression_secs_remaining.unwrap_or(0);
                        let _ = writeln!(
                            s,
                            r#"proteus_client_endpoint_suppression_secs_remaining{{addr="{}"}} {}"#,
                            escape_label(&e.addr),
                            secs
                        );
                    }
                }
            }
        }
        // Process-lifecycle block under the `proteus_client` prefix.
        // We reconstruct a transient ProcessInfo from the snapshot
        // view so the same rendering helper used by the server is
        // reused — single source of truth for the wire format.
        let pi = proteus_transport_alpha::process_info::ProcessInfo::from_parts(
            self.process.start_unix_seconds,
            // The reconstructed ProcessInfo's start_instant doesn't
            // match the original; uptime would drift. We override
            // by computing uptime ourselves at snapshot time —
            // the helper's `prometheus_with_prefix` reads
            // `uptime_seconds()` from its own start_instant. To
            // get a stable view-time uptime, render to the helper
            // then patch the uptime line.
            std::time::Instant::now(),
            &self.process.version,
            &self.process.rustc,
            &self.process.target,
        );
        let block = pi.prometheus_with_prefix("proteus_client");
        // Replace the helper's "fresh-instant" uptime with the
        // snapshot's recorded uptime. The helper emits the line as
        // `proteus_client_process_uptime_seconds 0` (because we
        // just constructed the Instant). The snapshot's
        // `self.process.uptime_seconds` is the operator-visible
        // value taken at snapshot time, which is what we want.
        for line in block.lines() {
            if let Some(_v) = line.strip_prefix("proteus_client_process_uptime_seconds ") {
                let _ = writeln!(
                    s,
                    "proteus_client_process_uptime_seconds {}",
                    self.process.uptime_seconds
                );
            } else {
                s.push_str(line);
                s.push('\n');
            }
        }
        s
    }
}

/// Escape a Prometheus label value per the 0.0.4 exposition spec:
/// `\` → `\\`, `"` → `\"`, `\n` → `\n` (literal two chars). Most
/// host:port strings need no escaping; this is the defense-in-depth
/// path for unusual hostnames.
fn escape_label(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '\\' => out.push_str(r"\\"),
            '"' => out.push_str(r#"\""#),
            '\n' => out.push_str(r"\n"),
            c => out.push(c),
        }
    }
    out
}

impl std::fmt::Display for ClientStatusSnapshot {
    /// Operator-friendly text rendering — what `proteus-client
    /// status` or `curl -s :9091/status` returns when the caller
    /// wants a human-readable summary.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            " Status: {}",
            if self.alive { "alive" } else { "starting" }
        )?;
        match &self.carrier {
            None => writeln!(f, " Carrier (β): not configured (α-only deployment)")?,
            Some(c) => {
                let state = if c.suppressed {
                    match c.suppression_secs_remaining {
                        Some(s) => format!("SUPPRESSED ({s}s remaining)"),
                        None => "SUPPRESSED".to_string(),
                    }
                } else {
                    "healthy".to_string()
                };
                writeln!(f, " Carrier (β): {state}")?;
                writeln!(f, "   failure_streak: {}", c.failure_streak)?;
            }
        }
        match &self.pool {
            None => writeln!(f, " EndpointPool: not configured (single-endpoint deploy)")?,
            Some(p) => {
                writeln!(f, " EndpointPool: {} entries", p.entries.len())?;
                for (ix, e) in p.entries.iter().enumerate() {
                    let state = if e.suppressed {
                        match e.suppression_secs_remaining {
                            Some(s) => format!("SUPPRESSED ({s}s remaining)"),
                            None => "SUPPRESSED".to_string(),
                        }
                    } else {
                        "healthy".to_string()
                    };
                    writeln!(
                        f,
                        "   [{ix}] {addr}: {state}, streak={streak}, dials={attempts} ({succ} ok, {fail} failed)",
                        addr = e.addr,
                        streak = e.failure_streak,
                        attempts = e.attempts_total,
                        succ = e.successes_total,
                        fail = e.failures_total,
                    )?;
                }
            }
        }
        match self.concurrency {
            None => writeln!(f, " Concurrency: cap disabled (max_inflight_sessions = 0)")?,
            Some(c) => writeln!(
                f,
                " Concurrency: {in_flight}/{max_inflight} in-flight",
                in_flight = c.in_flight,
                max_inflight = c.max_inflight,
            )?,
        }
        writeln!(
            f,
            " Dials: {attempted} attempted ({succeeded} ok, {failed} failed)",
            attempted = self.dials.attempted,
            succeeded = self.dials.succeeded,
            failed = self.dials.failed,
        )?;
        // Bootstrap-DNS resolution paths. Always render — operators
        // need to see at a glance whether their direct_ip config is
        // taking effect. If `via_system_resolver` is nonzero AND
        // the operator believed they had all-pinned IPs, that's the
        // misconfig signal worth a paragraph in the text output.
        let total_bootstrap = self.bootstrap.via_ip_literal
            + self.bootstrap.via_pinned_direct_ip
            + self.bootstrap.via_system_resolver;
        if total_bootstrap > 0 {
            let warning = if self.bootstrap.via_system_resolver > 0 {
                " — WARN: system-resolver path used; check bootstrap_dns config"
            } else {
                ""
            };
            writeln!(
                f,
                " Bootstrap DNS: {ipl} ip-literal, {pin} pinned-direct-ip, {sys} system-resolver{warning}",
                ipl = self.bootstrap.via_ip_literal,
                pin = self.bootstrap.via_pinned_direct_ip,
                sys = self.bootstrap.via_system_resolver,
            )?;
        }
        // Quiet by default — only render the line once at least one
        // SIGHUP has happened, so steady-state output stays tight
        // for operators who don't use the reload surface.
        if self.pool_reload.attempts > 0 {
            let failed = self
                .pool_reload
                .attempts
                .saturating_sub(self.pool_reload.succeeded);
            let label = if failed > 0 {
                format!(
                    "{} ({} ok, {} failed — check journalctl for YAML reload errors)",
                    self.pool_reload.attempts, self.pool_reload.succeeded, failed
                )
            } else {
                format!(
                    "{} ({} ok)",
                    self.pool_reload.attempts, self.pool_reload.succeeded
                )
            };
            writeln!(f, " Pool reloads (SIGHUP): {label}")?;
        }
        // Process block — always rendered. Even on a brand-new
        // process this is useful (operator sees start_unix +
        // uptime ≈ 0 + version), and the rendering stays compact.
        let up = self.process.uptime_seconds;
        let (h, m, sec) = (up / 3600, (up % 3600) / 60, up % 60);
        let version_label = if self.process.version.is_empty() {
            "(unset)".to_string()
        } else {
            self.process.version.clone()
        };
        let rustc_label = if self.process.rustc.is_empty() {
            "(unset)".to_string()
        } else {
            self.process.rustc.clone()
        };
        let target_label = if self.process.target.is_empty() {
            "(unset)".to_string()
        } else {
            self.process.target.clone()
        };
        writeln!(
            f,
            " Process: start_unix={ts}, uptime={up}s ({h}h {m}m {sec}s), version={version_label}, rustc={rustc_label}, target={target_label}",
            ts = self.process.start_unix_seconds,
        )?;
        Ok(())
    }
}

/// Shared reference cell for the alive flag — flipped to `true` once
/// the main accept loop has bound the SOCKS5 listener. Wrapping in
/// `Arc<AtomicBool>` so the admin handle can read it without owning
/// a copy.
pub type AliveFlag = Arc<std::sync::atomic::AtomicBool>;

/// Bind a loopback HTTP listener and serve the status snapshot.
///
/// Four routes:
///   - `GET /healthz`     → 200 "alive" once SOCKS5 has bound; 503 before.
///   - `GET /status`      → 200 text snapshot (Content-Type: text/plain).
///   - `GET /status.json` → 200 JSON snapshot (Content-Type:
///     application/json), line-delimited (one record + trailing `\n`).
///   - `GET /metrics`     → 200 Prometheus 0.0.4 exposition with
///     `proteus_client_*`-prefixed series (Content-Type:
///     `text/plain; version=0.0.4`). Per-endpoint counters are
///     labelled with `addr="host:port"` so PromQL can group by VPS.
///
/// Any other path returns 404. POST / other methods return 404 too —
/// the surface is strictly read-only.
///
/// `bind_addr` should be a loopback address (`127.0.0.1:N` /
/// `[::1]:N`). If the operator binds to a non-loopback interface, we
/// emit a startup `warn!` — there is no auth on this endpoint.
pub async fn serve(
    bind_addr: String,
    alive: AliveFlag,
    carrier: Option<Arc<CarrierHealth>>,
    beta_configured: bool,
    pool: Option<Arc<EndpointPool>>,
) -> std::io::Result<()> {
    // Back-compat wrapper: build a minimal ClientCtx synthesized
    // from the legacy arguments. The full-fidelity entry point is
    // `serve_with_ctx` which takes a ClientCtx (so it can surface
    // concurrency + dial counters).
    let ctx = Arc::new(ClientCtx::new(
        carrier.unwrap_or_else(|| Arc::new(CarrierHealth::new())),
        pool,
        None, // no semaphore handle → concurrency view stays None
        0,
        beta_configured,
    ));
    serve_with_ctx(bind_addr, alive, ctx).await
}

/// Full-featured serve: takes a `ClientCtx` so the snapshot includes
/// the concurrency view + cumulative dial counters. This is the
/// entry point `main.rs` calls in production; the legacy `serve`
/// wrapper above is kept for tests that don't build a full ctx.
pub async fn serve_with_ctx(
    bind_addr: String,
    alive: AliveFlag,
    ctx: Arc<ClientCtx>,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(&bind_addr).await?;
    let local = listener.local_addr()?;
    if !is_loopback(local) {
        warn!(
            addr = %local,
            "client admin endpoint bound on a NON-loopback interface — \
             /status exposes in-process health state to anyone who can \
             reach this address. There is no authentication on this \
             surface; bind 127.0.0.1 / [::1] in production."
        );
    } else {
        info!(addr = %local, "client admin endpoint bound (loopback)");
    }
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                warn!(error = %e, "client admin accept failed");
                continue;
            }
        };
        let alive = Arc::clone(&alive);
        let ctx = Arc::clone(&ctx);
        tokio::spawn(async move {
            if let Err(e) = handle_connection_ctx(stream, alive, ctx).await {
                warn!(peer = %peer, error = %e, "client admin connection ended");
            }
        });
    }
}

async fn handle_connection_ctx(
    mut stream: tokio::net::TcpStream,
    alive: AliveFlag,
    ctx: Arc<ClientCtx>,
) -> std::io::Result<()> {
    let mut req = [0u8; 1024];
    let n = stream.read(&mut req).await?;
    let head = std::str::from_utf8(&req[..n]).unwrap_or("");
    let snap = ClientStatusSnapshot::from_ctx(alive.load(Ordering::Relaxed), &ctx, Instant::now());
    let (status_line, content_type, body) = route(head, &snap);
    let response = format!(
        "{status_line}\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\r\n\
         {body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    let _ = stream.shutdown().await;
    Ok(())
}

/// Pure routing: given a request head + snapshot, return `(status,
/// content-type, body)`. Public so tests can hit the router without
/// a TCP listener.
#[must_use]
pub fn route(
    request_head: &str,
    snap: &ClientStatusSnapshot,
) -> (&'static str, &'static str, String) {
    if matches_path(request_head, "/healthz") {
        if snap.alive {
            ("HTTP/1.1 200 OK\r\n", "text/plain", "alive\n".to_string())
        } else {
            (
                "HTTP/1.1 503 Service Unavailable\r\n",
                "text/plain",
                "starting\n".to_string(),
            )
        }
    } else if matches_path(request_head, "/status") {
        (
            "HTTP/1.1 200 OK\r\n",
            "text/plain; charset=utf-8",
            format!("{snap}"),
        )
    } else if matches_path(request_head, "/status.json") {
        ("HTTP/1.1 200 OK\r\n", "application/json", snap.to_json())
    } else if matches_path(request_head, "/metrics") {
        (
            "HTTP/1.1 200 OK\r\n",
            "text/plain; version=0.0.4",
            snap.to_prometheus(),
        )
    } else {
        (
            "HTTP/1.1 404 Not Found\r\n",
            "text/plain",
            "not found\n".to_string(),
        )
    }
}

/// Match a request line against an exact path. Mirrors the
/// server-side admin endpoint's `matches_path` so the routing
/// rules are uniform across the codebase.
fn matches_path(request_head: &str, path: &str) -> bool {
    let with_space = format!("GET {path} ");
    let with_query = format!("GET {path}?");
    request_head.starts_with(&with_space) || request_head.starts_with(&with_query)
}

fn is_loopback(addr: SocketAddr) -> bool {
    addr.ip().is_loopback()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Helper: minimal snapshot with everything quiet (α-only, no
    /// pool, not yet alive). Used as a baseline so every test
    /// asserts only the field it changes.
    fn empty_snap() -> ClientStatusSnapshot {
        ClientStatusSnapshot::default()
    }

    #[test]
    fn json_alive_false_serializes_correctly() {
        let s = empty_snap().to_json();
        assert!(s.starts_with('{'));
        assert!(s.ends_with("}\n"));
        assert!(s.contains(r#""alive":false"#));
        assert!(s.contains(r#""carrier":null"#));
        assert!(s.contains(r#""pool":null"#));
    }

    #[test]
    fn json_alive_true_with_healthy_carrier() {
        let snap = ClientStatusSnapshot {
            alive: true,
            carrier: Some(CarrierHealthView {
                failure_streak: 0,
                suppressed: false,
                suppression_secs_remaining: None,
            }),
            ..ClientStatusSnapshot::default()
        };
        let s = snap.to_json();
        assert!(s.contains(r#""alive":true"#));
        assert!(s.contains(
            r#""carrier":{"failure_streak":0,"suppressed":false,"suppression_secs_remaining":null}"#
        ));
    }

    #[test]
    fn json_carrier_suppressed_with_remaining_secs() {
        let snap = ClientStatusSnapshot {
            alive: true,
            carrier: Some(CarrierHealthView {
                failure_streak: 5,
                suppressed: true,
                suppression_secs_remaining: Some(42),
            }),
            ..ClientStatusSnapshot::default()
        };
        let s = snap.to_json();
        assert!(s.contains(r#""failure_streak":5"#));
        assert!(s.contains(r#""suppressed":true"#));
        assert!(s.contains(r#""suppression_secs_remaining":42"#));
    }

    #[test]
    fn json_pool_renders_every_entry_in_order() {
        let snap = ClientStatusSnapshot {
            alive: true,
            pool: Some(EndpointPoolView {
                entries: vec![
                    EndpointEntryView {
                        addr: "primary:8443".into(),
                        failure_streak: 0,
                        suppressed: false,
                        suppression_secs_remaining: None,
                        ..EndpointEntryView::default()
                    },
                    EndpointEntryView {
                        addr: "backup:8443".into(),
                        failure_streak: 7,
                        suppressed: true,
                        suppression_secs_remaining: Some(120),
                        ..EndpointEntryView::default()
                    },
                ],
            }),
            ..ClientStatusSnapshot::default()
        };
        let s = snap.to_json();
        let primary_at = s.find("primary:8443").expect("primary line missing");
        let backup_at = s.find("backup:8443").expect("backup line missing");
        assert!(
            primary_at < backup_at,
            "pool entries must render in declaration order"
        );
        assert!(s.contains(r#""failure_streak":7"#));
        assert!(s.contains(r#""suppression_secs_remaining":120"#));
    }

    #[test]
    fn json_escapes_quotes_in_endpoint_addr() {
        // Pathological-but-possible: a hostname with a quote — we
        // shouldn't allow it through unescaped because it would
        // break parsers downstream.
        let snap = ClientStatusSnapshot {
            alive: true,
            pool: Some(EndpointPoolView {
                entries: vec![EndpointEntryView {
                    addr: r#"weird"host:8443"#.into(),
                    failure_streak: 0,
                    suppressed: false,
                    suppression_secs_remaining: None,
                    ..EndpointEntryView::default()
                }],
            }),
            ..ClientStatusSnapshot::default()
        };
        let s = snap.to_json();
        assert!(
            s.contains(r#"weird\"host:8443"#),
            "must escape quotes in addr: {s}"
        );
    }

    #[test]
    fn text_alive_false_shows_starting() {
        let s = format!("{}", empty_snap());
        assert!(s.contains("Status: starting"));
    }

    #[test]
    fn text_alive_true_shows_alive() {
        let snap = ClientStatusSnapshot {
            alive: true,
            ..empty_snap()
        };
        let s = format!("{snap}");
        assert!(s.contains("Status: alive"));
    }

    #[test]
    fn text_carrier_suppressed_includes_remaining_secs_in_header() {
        let snap = ClientStatusSnapshot {
            alive: true,
            carrier: Some(CarrierHealthView {
                failure_streak: 3,
                suppressed: true,
                suppression_secs_remaining: Some(60),
            }),
            ..ClientStatusSnapshot::default()
        };
        let s = format!("{snap}");
        assert!(s.contains("SUPPRESSED (60s remaining)"), "{s}");
        assert!(s.contains("failure_streak: 3"));
    }

    #[test]
    fn text_pool_entry_renders_index_addr_state_streak() {
        let snap = ClientStatusSnapshot {
            alive: true,
            pool: Some(EndpointPoolView {
                entries: vec![EndpointEntryView {
                    addr: "vps1:8443".into(),
                    failure_streak: 2,
                    suppressed: false,
                    suppression_secs_remaining: None,
                    ..EndpointEntryView::default()
                }],
            }),
            ..ClientStatusSnapshot::default()
        };
        let s = format!("{snap}");
        assert!(s.contains("[0] vps1:8443: healthy, streak=2"), "{s}");
    }

    #[test]
    fn capture_with_no_carrier_no_pool() {
        let snap = ClientStatusSnapshot::capture(true, None, false, None, Instant::now());
        assert!(snap.alive);
        assert!(snap.carrier.is_none());
        assert!(snap.pool.is_none());
    }

    #[test]
    fn capture_healthy_carrier() {
        let carrier = CarrierHealth::new();
        let snap = ClientStatusSnapshot::capture(true, Some(&carrier), true, None, Instant::now());
        let c = snap.carrier.expect("carrier should be Some");
        assert!(!c.suppressed);
        assert_eq!(c.failure_streak, 0);
        assert!(c.suppression_secs_remaining.is_none());
    }

    #[test]
    fn capture_suppressed_carrier_includes_remaining_secs() {
        let carrier = CarrierHealth::with_threshold(2);
        let t0 = Instant::now();
        carrier.record_beta_failure(t0);
        carrier.record_beta_failure(t0);
        // capture immediately so most of the back-off window is
        // still in the future.
        let snap = ClientStatusSnapshot::capture(
            true,
            Some(&carrier),
            true,
            None,
            t0 + Duration::from_millis(100),
        );
        let c = snap.carrier.expect("carrier should be Some");
        assert!(c.suppressed, "should be suppressed: {c:?}");
        let secs = c
            .suppression_secs_remaining
            .expect("should have remaining secs");
        // INITIAL_SUPPRESSION = 15s; we burned 100ms.
        assert!(
            (13..=15).contains(&secs),
            "expected ~14s remaining, got {secs}"
        );
    }

    #[test]
    fn capture_pool_renders_every_entry() {
        let pool =
            EndpointPool::new(vec!["a:1".into(), "b:2".into(), "c:3".into()]).expect("pool builds");
        let snap = ClientStatusSnapshot::capture(true, None, false, Some(&pool), Instant::now());
        let p = snap.pool.expect("pool should be Some");
        assert_eq!(p.entries.len(), 3);
        assert_eq!(p.entries[0].addr, "a:1");
        assert_eq!(p.entries[1].addr, "b:2");
        assert_eq!(p.entries[2].addr, "c:3");
        for e in &p.entries {
            assert!(!e.suppressed);
            assert_eq!(e.failure_streak, 0);
        }
    }

    #[test]
    fn route_healthz_200_when_alive() {
        let snap = ClientStatusSnapshot {
            alive: true,
            ..empty_snap()
        };
        let (status, ctype, body) = route("GET /healthz HTTP/1.1\r\n\r\n", &snap);
        assert!(status.starts_with("HTTP/1.1 200"));
        assert_eq!(ctype, "text/plain");
        assert_eq!(body, "alive\n");
    }

    #[test]
    fn route_healthz_503_when_not_alive() {
        let (status, ctype, body) = route("GET /healthz HTTP/1.1\r\n\r\n", &empty_snap());
        assert!(status.starts_with("HTTP/1.1 503"));
        assert_eq!(ctype, "text/plain");
        assert_eq!(body, "starting\n");
    }

    #[test]
    fn route_status_200_text() {
        let snap = ClientStatusSnapshot {
            alive: true,
            ..empty_snap()
        };
        let (status, ctype, body) = route("GET /status HTTP/1.1\r\n\r\n", &snap);
        assert!(status.starts_with("HTTP/1.1 200"));
        assert!(ctype.starts_with("text/plain"));
        assert!(body.contains("Status: alive"));
    }

    #[test]
    fn route_status_json_200_json() {
        let snap = ClientStatusSnapshot {
            alive: true,
            ..empty_snap()
        };
        let (status, ctype, body) = route("GET /status.json HTTP/1.1\r\n\r\n", &snap);
        assert!(status.starts_with("HTTP/1.1 200"));
        assert_eq!(ctype, "application/json");
        assert!(body.starts_with("{"));
        assert!(body.ends_with("}\n"));
    }

    #[test]
    fn route_404_on_random_path() {
        let (status, _ctype, body) = route("GET /admin HTTP/1.1\r\n\r\n", &empty_snap());
        assert!(status.starts_with("HTTP/1.1 404"));
        assert_eq!(body, "not found\n");
    }

    #[test]
    fn route_404_on_post() {
        let (status, _ctype, _body) = route("POST /status HTTP/1.1\r\n\r\n", &empty_snap());
        assert!(status.starts_with("HTTP/1.1 404"));
    }

    #[test]
    fn route_404_on_status_substring_path() {
        // /statusleak should NOT match /status.
        let (status, _ctype, _body) = route("GET /statusleak HTTP/1.1\r\n\r\n", &empty_snap());
        assert!(status.starts_with("HTTP/1.1 404"));
    }

    #[test]
    fn route_status_with_query_string_matches() {
        let snap = ClientStatusSnapshot {
            alive: true,
            ..empty_snap()
        };
        let (status, _ctype, _body) = route("GET /status?fmt=text HTTP/1.1\r\n\r\n", &snap);
        assert!(status.starts_with("HTTP/1.1 200"));
    }

    // ----- New ClientCtx-aware snapshot tests -----

    fn ctx_with_slots(
        slots: Option<usize>,
        max_inflight: usize,
        beta_configured: bool,
    ) -> Arc<ClientCtx> {
        let sem = slots.map(|n| Arc::new(tokio::sync::Semaphore::new(n)));
        Arc::new(ClientCtx::new(
            Arc::new(CarrierHealth::new()),
            None,
            sem,
            max_inflight,
            beta_configured,
        ))
    }

    #[test]
    fn from_ctx_includes_concurrency_when_cap_configured() {
        let ctx = ctx_with_slots(Some(4), 4, true);
        let snap = ClientStatusSnapshot::from_ctx(true, &ctx, Instant::now());
        let c = snap.concurrency.expect("concurrency should be Some");
        assert_eq!(c.max_inflight, 4);
        assert_eq!(c.in_flight, 0);
    }

    #[test]
    fn from_ctx_omits_concurrency_when_cap_disabled() {
        let ctx = ctx_with_slots(None, 0, true);
        let snap = ClientStatusSnapshot::from_ctx(true, &ctx, Instant::now());
        assert!(snap.concurrency.is_none());
    }

    #[test]
    fn from_ctx_carrier_is_none_when_beta_unconfigured() {
        // β not configured: carrier view must collapse to None even
        // though the tracker exists internally — operator should see
        // "carrier: not configured", not "carrier: healthy".
        let ctx = ctx_with_slots(Some(4), 4, false);
        let snap = ClientStatusSnapshot::from_ctx(true, &ctx, Instant::now());
        assert!(
            snap.carrier.is_none(),
            "carrier must be None when beta_configured=false: {:?}",
            snap.carrier
        );
    }

    #[test]
    fn from_ctx_carrier_is_some_when_beta_configured() {
        let ctx = ctx_with_slots(Some(4), 4, true);
        let snap = ClientStatusSnapshot::from_ctx(true, &ctx, Instant::now());
        assert!(
            snap.carrier.is_some(),
            "carrier must be Some when beta_configured=true"
        );
    }

    #[test]
    fn from_ctx_dials_default_to_zero() {
        let ctx = ctx_with_slots(Some(4), 4, true);
        let snap = ClientStatusSnapshot::from_ctx(true, &ctx, Instant::now());
        assert_eq!(snap.dials.attempted, 0);
        assert_eq!(snap.dials.succeeded, 0);
        assert_eq!(snap.dials.failed, 0);
    }

    #[test]
    fn from_ctx_dials_reflect_bumps() {
        let ctx = ctx_with_slots(Some(4), 4, true);
        ctx.record_dial_attempt();
        ctx.record_dial_attempt();
        ctx.record_dial_success();
        ctx.record_dial_failure();
        let snap = ClientStatusSnapshot::from_ctx(true, &ctx, Instant::now());
        assert_eq!(snap.dials.attempted, 2);
        assert_eq!(snap.dials.succeeded, 1);
        assert_eq!(snap.dials.failed, 1);
    }

    #[test]
    fn json_includes_concurrency_object() {
        let snap = ClientStatusSnapshot {
            alive: true,
            concurrency: Some(ConcurrencyView {
                in_flight: 3,
                max_inflight: 16,
            }),
            ..ClientStatusSnapshot::default()
        };
        let s = snap.to_json();
        assert!(
            s.contains(r#""concurrency":{"in_flight":3,"max_inflight":16}"#),
            "expected concurrency object in: {s}"
        );
    }

    #[test]
    fn json_includes_dials_object_always() {
        let s = empty_snap().to_json();
        assert!(
            s.contains(r#""dials":{"attempted":0,"succeeded":0,"failed":0}"#),
            "dials must always be emitted: {s}"
        );
    }

    #[test]
    fn json_includes_concurrency_null_when_disabled() {
        let s = empty_snap().to_json();
        assert!(s.contains(r#""concurrency":null"#), "{s}");
    }

    #[test]
    fn text_renders_concurrency_block_when_cap_configured() {
        let snap = ClientStatusSnapshot {
            alive: true,
            concurrency: Some(ConcurrencyView {
                in_flight: 7,
                max_inflight: 32,
            }),
            ..ClientStatusSnapshot::default()
        };
        let s = format!("{snap}");
        assert!(s.contains("Concurrency: 7/32 in-flight"), "{s}");
    }

    #[test]
    fn text_renders_concurrency_disabled_note_when_cap_off() {
        let s = format!("{}", empty_snap());
        assert!(s.contains("Concurrency: cap disabled"), "{s}");
    }

    #[test]
    fn json_pool_entry_includes_per_endpoint_counters() {
        let snap = ClientStatusSnapshot {
            alive: true,
            pool: Some(EndpointPoolView {
                entries: vec![EndpointEntryView {
                    addr: "vps1:8443".into(),
                    failure_streak: 0,
                    suppressed: false,
                    suppression_secs_remaining: None,
                    attempts_total: 100,
                    successes_total: 97,
                    failures_total: 3,
                }],
            }),
            ..ClientStatusSnapshot::default()
        };
        let s = snap.to_json();
        assert!(
            s.contains(r#""attempts_total":100"#),
            "missing per-entry attempts: {s}"
        );
        assert!(s.contains(r#""successes_total":97"#), "{s}");
        assert!(s.contains(r#""failures_total":3"#), "{s}");
    }

    #[test]
    fn text_pool_entry_renders_per_endpoint_counters() {
        let snap = ClientStatusSnapshot {
            alive: true,
            pool: Some(EndpointPoolView {
                entries: vec![EndpointEntryView {
                    addr: "vps2:8443".into(),
                    failure_streak: 5,
                    suppressed: true,
                    suppression_secs_remaining: Some(30),
                    attempts_total: 50,
                    successes_total: 20,
                    failures_total: 30,
                }],
            }),
            ..ClientStatusSnapshot::default()
        };
        let s = format!("{snap}");
        assert!(
            s.contains("dials=50 (20 ok, 30 failed)"),
            "expected per-entry dial counts in: {s}"
        );
    }

    #[test]
    fn capture_from_pool_includes_counters_after_dispatch_bumps() {
        // Drive a real pool — bump record_attempt + record_success
        // through the EndpointHealth API, then capture the snapshot
        // and assert the per-entry counters propagated. This is the
        // pure-snapshot version of the e2e test that drives the same
        // through TCP.
        let pool = crate::endpoint_pool::EndpointPool::new(vec!["a:1".into(), "b:2".into()])
            .expect("pool");
        let h0 = pool.endpoint_health(0).unwrap();
        let h1 = pool.endpoint_health(1).unwrap();
        h0.record_attempt();
        h0.record_attempt();
        h0.record_success();
        h0.record_success();
        h1.record_attempt();
        h1.record_failure(Instant::now());

        let snap = ClientStatusSnapshot::capture(true, None, false, Some(&pool), Instant::now());
        let entries = snap.pool.expect("pool").entries;
        assert_eq!(entries[0].attempts_total, 2);
        assert_eq!(entries[0].successes_total, 2);
        assert_eq!(entries[0].failures_total, 0);
        assert_eq!(entries[1].attempts_total, 1);
        assert_eq!(entries[1].successes_total, 0);
        assert_eq!(entries[1].failures_total, 1);
    }

    // ----- Prometheus exposition tests -----

    #[test]
    fn prometheus_emits_up_gauge_zero_when_not_alive() {
        let s = empty_snap().to_prometheus();
        assert!(
            s.contains("\nproteus_client_up 0\n"),
            "expected up=0 line in: {s}"
        );
        // Mandatory HELP/TYPE rows.
        assert!(s.contains("# HELP proteus_client_up"));
        assert!(s.contains("# TYPE proteus_client_up gauge"));
    }

    #[test]
    fn prometheus_emits_up_gauge_one_when_alive() {
        let snap = ClientStatusSnapshot {
            alive: true,
            ..empty_snap()
        };
        let s = snap.to_prometheus();
        assert!(
            s.contains("\nproteus_client_up 1\n"),
            "expected up=1 line in: {s}"
        );
    }

    #[test]
    fn prometheus_always_emits_dial_counters() {
        // Even when no dials have happened, the three counters are
        // present with value 0 so scrapers don't see absent-counter
        // gaps that break rate() calculations.
        let s = empty_snap().to_prometheus();
        assert!(
            s.contains("\nproteus_client_dials_attempted_total 0\n"),
            "{s}"
        );
        assert!(
            s.contains("\nproteus_client_dials_succeeded_total 0\n"),
            "{s}"
        );
        assert!(s.contains("\nproteus_client_dials_failed_total 0\n"), "{s}");
    }

    #[test]
    fn prometheus_reflects_dial_counter_values() {
        let snap = ClientStatusSnapshot {
            alive: true,
            dials: DialCounters {
                attempted: 100,
                succeeded: 97,
                failed: 3,
            },
            ..empty_snap()
        };
        let s = snap.to_prometheus();
        assert!(
            s.contains("\nproteus_client_dials_attempted_total 100\n"),
            "{s}"
        );
        assert!(
            s.contains("\nproteus_client_dials_succeeded_total 97\n"),
            "{s}"
        );
        assert!(s.contains("\nproteus_client_dials_failed_total 3\n"), "{s}");
    }

    #[test]
    fn prometheus_omits_concurrency_when_cap_disabled() {
        let s = empty_snap().to_prometheus();
        assert!(!s.contains("proteus_client_in_flight_sessions"), "{s}");
        assert!(!s.contains("proteus_client_max_inflight_sessions"), "{s}");
    }

    #[test]
    fn prometheus_emits_concurrency_when_cap_configured() {
        let snap = ClientStatusSnapshot {
            alive: true,
            concurrency: Some(ConcurrencyView {
                in_flight: 5,
                max_inflight: 32,
            }),
            ..empty_snap()
        };
        let s = snap.to_prometheus();
        assert!(s.contains("\nproteus_client_in_flight_sessions 5\n"), "{s}");
        assert!(
            s.contains("\nproteus_client_max_inflight_sessions 32\n"),
            "{s}"
        );
    }

    #[test]
    fn prometheus_omits_carrier_block_when_unconfigured() {
        // β unconfigured → carrier view is None → no carrier_* series.
        let s = empty_snap().to_prometheus();
        assert!(!s.contains("proteus_client_carrier"), "{s}");
    }

    #[test]
    fn prometheus_emits_carrier_healthy_state() {
        let snap = ClientStatusSnapshot {
            alive: true,
            carrier: Some(CarrierHealthView {
                failure_streak: 0,
                suppressed: false,
                suppression_secs_remaining: None,
            }),
            ..empty_snap()
        };
        let s = snap.to_prometheus();
        assert!(s.contains("\nproteus_client_carrier_suppressed 0\n"), "{s}");
        assert!(
            s.contains("\nproteus_client_carrier_failure_streak 0\n"),
            "{s}"
        );
        // suppression_secs_remaining is omitted when not suppressed
        // (operator's "this gauge exists ⇒ we're currently in
        // back-off" semantics).
        assert!(
            !s.contains("proteus_client_carrier_suppression_secs_remaining"),
            "should NOT emit remaining-secs when healthy: {s}"
        );
    }

    #[test]
    fn prometheus_emits_carrier_suppressed_state_with_remaining_secs() {
        let snap = ClientStatusSnapshot {
            alive: true,
            carrier: Some(CarrierHealthView {
                failure_streak: 8,
                suppressed: true,
                suppression_secs_remaining: Some(45),
            }),
            ..empty_snap()
        };
        let s = snap.to_prometheus();
        assert!(s.contains("\nproteus_client_carrier_suppressed 1\n"), "{s}");
        assert!(
            s.contains("\nproteus_client_carrier_failure_streak 8\n"),
            "{s}"
        );
        assert!(
            s.contains("\nproteus_client_carrier_suppression_secs_remaining 45\n"),
            "{s}"
        );
    }

    #[test]
    fn prometheus_emits_per_endpoint_labelled_series() {
        let snap = ClientStatusSnapshot {
            alive: true,
            pool: Some(EndpointPoolView {
                entries: vec![
                    EndpointEntryView {
                        addr: "primary:8443".into(),
                        failure_streak: 0,
                        suppressed: false,
                        suppression_secs_remaining: None,
                        attempts_total: 50,
                        successes_total: 50,
                        failures_total: 0,
                    },
                    EndpointEntryView {
                        addr: "backup:8443".into(),
                        failure_streak: 3,
                        suppressed: true,
                        suppression_secs_remaining: Some(60),
                        attempts_total: 8,
                        successes_total: 5,
                        failures_total: 3,
                    },
                ],
            }),
            ..empty_snap()
        };
        let s = snap.to_prometheus();
        // Per-entry attempts.
        assert!(
            s.contains(r#"proteus_client_endpoint_attempts_total{addr="primary:8443"} 50"#),
            "{s}"
        );
        assert!(
            s.contains(r#"proteus_client_endpoint_attempts_total{addr="backup:8443"} 8"#),
            "{s}"
        );
        // Successes.
        assert!(
            s.contains(r#"proteus_client_endpoint_successes_total{addr="primary:8443"} 50"#),
            "{s}"
        );
        assert!(
            s.contains(r#"proteus_client_endpoint_successes_total{addr="backup:8443"} 5"#),
            "{s}"
        );
        // Failures.
        assert!(
            s.contains(r#"proteus_client_endpoint_failures_total{addr="backup:8443"} 3"#),
            "{s}"
        );
        // Suppression state.
        assert!(
            s.contains(r#"proteus_client_endpoint_suppressed{addr="primary:8443"} 0"#),
            "{s}"
        );
        assert!(
            s.contains(r#"proteus_client_endpoint_suppressed{addr="backup:8443"} 1"#),
            "{s}"
        );
        // Failure streak.
        assert!(
            s.contains(r#"proteus_client_endpoint_failure_streak{addr="backup:8443"} 3"#),
            "{s}"
        );
        // Per-entry remaining-secs ONLY for suppressed entry.
        assert!(
            s.contains(
                r#"proteus_client_endpoint_suppression_secs_remaining{addr="backup:8443"} 60"#
            ),
            "{s}"
        );
        assert!(
            !s.contains(
                r#"proteus_client_endpoint_suppression_secs_remaining{addr="primary:8443"}"#
            ),
            "should NOT emit remaining-secs for non-suppressed primary: {s}"
        );
    }

    #[test]
    fn prometheus_omits_pool_block_when_pool_unconfigured() {
        let s = empty_snap().to_prometheus();
        assert!(!s.contains("proteus_client_endpoint"), "{s}");
    }

    #[test]
    fn prometheus_omits_pool_block_when_pool_empty() {
        // Edge case: pool wired but no entries (shouldn't happen in
        // practice — EndpointPool::new returns None for empty Vec —
        // but defense-in-depth here).
        let snap = ClientStatusSnapshot {
            alive: true,
            pool: Some(EndpointPoolView { entries: vec![] }),
            ..empty_snap()
        };
        let s = snap.to_prometheus();
        assert!(!s.contains("proteus_client_endpoint_attempts_total"), "{s}");
    }

    #[test]
    fn prometheus_escapes_dangerous_chars_in_addr_label() {
        let snap = ClientStatusSnapshot {
            alive: true,
            pool: Some(EndpointPoolView {
                entries: vec![EndpointEntryView {
                    addr: r#"weird"host:8443"#.into(),
                    attempts_total: 1,
                    ..EndpointEntryView::default()
                }],
            }),
            ..empty_snap()
        };
        let s = snap.to_prometheus();
        // Must contain the escaped form, NOT the raw form.
        assert!(
            s.contains(r#"addr="weird\"host:8443""#),
            "should escape quote in label: {s}"
        );
    }

    #[test]
    fn prometheus_help_and_type_appear_exactly_once_per_metric_name() {
        // Prometheus 0.0.4 requires exactly one HELP + TYPE per
        // metric NAME across the entire payload (label sets share
        // the metadata). Pool series have multiple values but should
        // emit metadata only once.
        let snap = ClientStatusSnapshot {
            alive: true,
            pool: Some(EndpointPoolView {
                entries: vec![
                    EndpointEntryView {
                        addr: "a:1".into(),
                        attempts_total: 1,
                        ..EndpointEntryView::default()
                    },
                    EndpointEntryView {
                        addr: "b:2".into(),
                        attempts_total: 2,
                        ..EndpointEntryView::default()
                    },
                ],
            }),
            ..empty_snap()
        };
        let s = snap.to_prometheus();
        let metric_names = [
            "proteus_client_up",
            "proteus_client_dials_attempted_total",
            "proteus_client_dials_succeeded_total",
            "proteus_client_dials_failed_total",
            "proteus_client_endpoint_attempts_total",
            "proteus_client_endpoint_successes_total",
            "proteus_client_endpoint_failures_total",
            "proteus_client_endpoint_suppressed",
            "proteus_client_endpoint_failure_streak",
        ];
        for name in metric_names {
            let help_count = s.matches(&format!("# HELP {name} ")).count();
            let type_count = s.matches(&format!("# TYPE {name} ")).count();
            assert_eq!(
                help_count, 1,
                "{name}: expected exactly 1 HELP row, got {help_count} in: {s}"
            );
            assert_eq!(
                type_count, 1,
                "{name}: expected exactly 1 TYPE row, got {type_count} in: {s}"
            );
        }
    }

    #[test]
    fn route_metrics_200_with_prometheus_content_type() {
        let snap = ClientStatusSnapshot {
            alive: true,
            ..empty_snap()
        };
        let (status, ctype, body) = route("GET /metrics HTTP/1.1\r\n\r\n", &snap);
        assert!(status.starts_with("HTTP/1.1 200"));
        assert!(
            ctype.contains("text/plain") && ctype.contains("version=0.0.4"),
            "unexpected content-type: {ctype}"
        );
        assert!(body.contains("proteus_client_up 1"), "{body}");
    }

    #[test]
    fn route_metrics_with_query_string_matches() {
        let snap = ClientStatusSnapshot {
            alive: true,
            ..empty_snap()
        };
        let (status, _ctype, _body) = route("GET /metrics?debug=1 HTTP/1.1\r\n\r\n", &snap);
        assert!(status.starts_with("HTTP/1.1 200"));
    }

    // ----- Process-lifecycle tests (client side) -----

    #[test]
    fn prometheus_always_emits_process_lifecycle_under_client_prefix() {
        let snap = ClientStatusSnapshot {
            process: ProcessView {
                start_unix_seconds: 1_747_526_400,
                uptime_seconds: 100,
                version: "0.1.0".into(),
                rustc: "1.85.0".into(),
                target: "aarch64-apple-darwin".into(),
            },
            ..empty_snap()
        };
        let s = snap.to_prometheus();
        assert!(
            s.contains("\nproteus_client_process_start_unix_seconds 1747526400\n"),
            "{s}"
        );
        assert!(
            s.contains("\nproteus_client_process_uptime_seconds 100\n"),
            "missing uptime line (must reflect snapshot value, not Instant::now): {s}"
        );
        assert!(
            s.contains(
                r#"proteus_client_build_info{version="0.1.0",rustc="1.85.0",target="aarch64-apple-darwin"} 1"#
            ),
            "{s}"
        );
        // The default `proteus_*` (no `_client`) prefix MUST NOT
        // leak — otherwise a shared Prometheus would see duplicate
        // series from server + client.
        assert!(
            !s.contains("\nproteus_process_start_unix_seconds"),
            "client must not emit the server-prefixed series: {s}"
        );
    }

    #[test]
    fn json_emits_process_object_with_all_fields() {
        let snap = ClientStatusSnapshot {
            process: ProcessView {
                start_unix_seconds: 42,
                uptime_seconds: 3725,
                version: "9.9.9".into(),
                rustc: "".into(),
                target: "".into(),
            },
            ..empty_snap()
        };
        let s = snap.to_json();
        assert!(
            s.contains(
                r#""process":{"start_unix_seconds":42,"uptime_seconds":3725,"version":"9.9.9","rustc":"","target":""}"#
            ),
            "{s}"
        );
    }

    #[test]
    fn json_process_handles_empty_version_safely() {
        // brand-new ctx with no with_process_info attached: all
        // strings are "" — JSON must still be parseable.
        let s = empty_snap().to_json();
        assert!(s.contains(r#""version":"""#), "{s}");
        assert!(s.contains(r#""rustc":"""#), "{s}");
        assert!(s.contains(r#""target":"""#), "{s}");
    }

    #[test]
    fn text_renders_process_line_with_unset_placeholders_when_empty() {
        let s = format!("{}", empty_snap());
        assert!(s.contains(" Process: start_unix="), "{s}");
        assert!(s.contains("version=(unset)"), "{s}");
        assert!(s.contains("rustc=(unset)"), "{s}");
        assert!(s.contains("target=(unset)"), "{s}");
    }

    #[test]
    fn text_renders_process_line_with_humanized_uptime() {
        let snap = ClientStatusSnapshot {
            process: ProcessView {
                start_unix_seconds: 100,
                uptime_seconds: 3725, // 1h 2m 5s
                version: "0.2.1".into(),
                rustc: "1.85.0".into(),
                target: "x86_64-unknown-linux-gnu".into(),
            },
            ..empty_snap()
        };
        let s = format!("{snap}");
        assert!(
            s.contains("uptime=3725s (1h 2m 5s)"),
            "expected humanized uptime in: {s}"
        );
        assert!(s.contains("version=0.2.1"), "{s}");
    }

    #[test]
    fn from_ctx_propagates_process_info_from_ctx() {
        let custom = Arc::new(proteus_transport_alpha::process_info::ProcessInfo::capture(
            "ctx-version",
            "ctx-rustc",
            "ctx-target",
        ));
        let ctx = Arc::new(
            ClientCtx::new(Arc::new(CarrierHealth::new()), None, None, 0, false)
                .with_process_info(Arc::clone(&custom)),
        );
        let snap = ClientStatusSnapshot::from_ctx(true, &ctx, Instant::now());
        assert_eq!(snap.process.version, "ctx-version");
        assert_eq!(snap.process.rustc, "ctx-rustc");
        assert_eq!(snap.process.target, "ctx-target");
        // start_unix matches what custom captured.
        assert_eq!(snap.process.start_unix_seconds, custom.start_unix_seconds());
    }

    #[test]
    fn prometheus_always_emits_bootstrap_counters() {
        let s = empty_snap().to_prometheus();
        assert!(
            s.contains("\nproteus_client_bootstrap_via_ip_literal_total 0\n"),
            "{s}"
        );
        assert!(
            s.contains("\nproteus_client_bootstrap_via_pinned_direct_ip_total 0\n"),
            "{s}"
        );
        assert!(
            s.contains("\nproteus_client_bootstrap_via_system_resolver_total 0\n"),
            "{s}"
        );
    }

    #[test]
    fn prometheus_reflects_bootstrap_counter_values() {
        let snap = ClientStatusSnapshot {
            bootstrap: BootstrapCounters {
                via_ip_literal: 42,
                via_pinned_direct_ip: 7,
                via_system_resolver: 1,
            },
            ..empty_snap()
        };
        let s = snap.to_prometheus();
        assert!(
            s.contains("\nproteus_client_bootstrap_via_ip_literal_total 42\n"),
            "{s}"
        );
        assert!(
            s.contains("\nproteus_client_bootstrap_via_pinned_direct_ip_total 7\n"),
            "{s}"
        );
        assert!(
            s.contains("\nproteus_client_bootstrap_via_system_resolver_total 1\n"),
            "{s}"
        );
    }

    #[test]
    fn json_always_emits_bootstrap_object() {
        let s = empty_snap().to_json();
        assert!(
            s.contains(
                r#""bootstrap":{"via_ip_literal":0,"via_pinned_direct_ip":0,"via_system_resolver":0}"#
            ),
            "{s}"
        );
    }

    #[test]
    fn json_reflects_bootstrap_values() {
        let snap = ClientStatusSnapshot {
            bootstrap: BootstrapCounters {
                via_ip_literal: 10,
                via_pinned_direct_ip: 5,
                via_system_resolver: 3,
            },
            ..empty_snap()
        };
        let s = snap.to_json();
        assert!(
            s.contains(
                r#""bootstrap":{"via_ip_literal":10,"via_pinned_direct_ip":5,"via_system_resolver":3}"#
            ),
            "{s}"
        );
    }

    #[test]
    fn text_omits_bootstrap_line_when_no_resolutions_happened() {
        let s = format!("{}", empty_snap());
        assert!(
            !s.contains("Bootstrap DNS:"),
            "should not render bootstrap line at zero: {s}"
        );
    }

    #[test]
    fn text_renders_bootstrap_line_when_resolutions_happened() {
        let snap = ClientStatusSnapshot {
            bootstrap: BootstrapCounters {
                via_ip_literal: 50,
                via_pinned_direct_ip: 0,
                via_system_resolver: 0,
            },
            ..empty_snap()
        };
        let s = format!("{snap}");
        assert!(
            s.contains(" Bootstrap DNS: 50 ip-literal, 0 pinned-direct-ip, 0 system-resolver"),
            "{s}"
        );
        // No WARN suffix in the all-ip-literal happy path.
        assert!(!s.contains("WARN"), "{s}");
    }

    #[test]
    fn text_renders_warn_when_system_resolver_used() {
        // Misconfig signal: a deployment that should be all-pinned-IP
        // shouldn't see ANY system-resolver path. The WARN suffix
        // makes the misconfig pop on `proteus-client status`.
        let snap = ClientStatusSnapshot {
            bootstrap: BootstrapCounters {
                via_ip_literal: 5,
                via_pinned_direct_ip: 10,
                via_system_resolver: 3,
            },
            ..empty_snap()
        };
        let s = format!("{snap}");
        assert!(
            s.contains("WARN: system-resolver path used"),
            "expected WARN suffix: {s}"
        );
    }

    #[test]
    fn from_ctx_propagates_bootstrap_counters() {
        use crate::bootstrap::ResolvedVia;
        let ctx = Arc::new(ClientCtx::new(
            Arc::new(CarrierHealth::new()),
            None,
            None,
            0,
            false,
        ));
        ctx.record_bootstrap_resolution(ResolvedVia::IpLiteralInEndpoint);
        ctx.record_bootstrap_resolution(ResolvedVia::PinnedDirectIp);
        ctx.record_bootstrap_resolution(ResolvedVia::PinnedDirectIp);
        let snap = ClientStatusSnapshot::from_ctx(true, &ctx, Instant::now());
        assert_eq!(snap.bootstrap.via_ip_literal, 1);
        assert_eq!(snap.bootstrap.via_pinned_direct_ip, 2);
        assert_eq!(snap.bootstrap.via_system_resolver, 0);
    }

    #[test]
    fn prometheus_always_emits_pool_reload_counters() {
        // Always present even at zero — symmetric with server's
        // tls_reload_*_total. Operators script
        // `rate(proteus_client_pool_reload_attempts_total[5m])` and
        // need the series to exist from t=0.
        let s = empty_snap().to_prometheus();
        assert!(
            s.contains("\nproteus_client_pool_reload_attempts_total 0\n"),
            "{s}"
        );
        assert!(
            s.contains("\nproteus_client_pool_reload_succeeded_total 0\n"),
            "{s}"
        );
    }

    #[test]
    fn prometheus_reflects_pool_reload_counter_values() {
        let snap = ClientStatusSnapshot {
            alive: true,
            pool_reload: PoolReloadCounters {
                attempts: 7,
                succeeded: 7,
            },
            ..empty_snap()
        };
        let s = snap.to_prometheus();
        assert!(
            s.contains("\nproteus_client_pool_reload_attempts_total 7\n"),
            "{s}"
        );
        assert!(
            s.contains("\nproteus_client_pool_reload_succeeded_total 7\n"),
            "{s}"
        );
    }

    #[test]
    fn json_always_emits_pool_reload_object() {
        let s = empty_snap().to_json();
        assert!(
            s.contains(r#""pool_reload":{"attempts":0,"succeeded":0}"#),
            "{s}"
        );
    }

    #[test]
    fn json_reflects_pool_reload_values() {
        let snap = ClientStatusSnapshot {
            alive: true,
            pool_reload: PoolReloadCounters {
                attempts: 3,
                succeeded: 3,
            },
            ..empty_snap()
        };
        let s = snap.to_json();
        assert!(
            s.contains(r#""pool_reload":{"attempts":3,"succeeded":3}"#),
            "{s}"
        );
    }

    #[test]
    fn text_omits_pool_reload_line_when_no_reloads_have_happened() {
        // Steady-state: operator hasn't SIGHUPed → line stays hidden.
        let s = format!("{}", empty_snap());
        assert!(
            !s.contains("Pool reloads"),
            "should not show pool-reload line at zero: {s}"
        );
    }

    #[test]
    fn text_renders_pool_reload_line_after_first_sighup() {
        let snap = ClientStatusSnapshot {
            alive: true,
            pool_reload: PoolReloadCounters {
                attempts: 2,
                succeeded: 2,
            },
            ..empty_snap()
        };
        let s = format!("{snap}");
        assert!(s.contains("Pool reloads (SIGHUP): 2 (2 ok)"), "{s}");
    }

    #[test]
    fn from_ctx_pool_reload_counters_reflect_reloadable_pool_state() {
        // End-to-end: build a ClientCtx, perform 3 reloads on its
        // pool, capture a snapshot, assert the counters propagated
        // through ClientCtx → ReloadablePool → snapshot.
        let ctx = Arc::new(ClientCtx::new(
            Arc::new(CarrierHealth::new()),
            Some(Arc::new(
                crate::endpoint_pool::EndpointPool::new(vec!["a:1".into()]).unwrap(),
            )),
            None,
            0,
            true,
        ));
        ctx.reloadable_pool
            .reload_from_addrs(vec!["a:1".into(), "b:2".into()]);
        ctx.reloadable_pool
            .reload_from_addrs(vec!["a:1".into(), "b:2".into(), "c:3".into()]);
        ctx.reloadable_pool.reload_from_addrs(vec![]);
        let snap = ClientStatusSnapshot::from_ctx(true, &ctx, Instant::now());
        assert_eq!(snap.pool_reload.attempts, 3);
        assert_eq!(snap.pool_reload.succeeded, 3);
    }

    #[test]
    fn from_ctx_pool_snapshot_reflects_post_reload_state() {
        // After a hot-reload, from_ctx should snapshot the NEW pool
        // (not a stale Arc captured pre-reload).
        let ctx = Arc::new(ClientCtx::new(
            Arc::new(CarrierHealth::new()),
            Some(Arc::new(
                crate::endpoint_pool::EndpointPool::new(vec!["old:8443".into()]).unwrap(),
            )),
            None,
            0,
            true,
        ));
        ctx.reloadable_pool
            .reload_from_addrs(vec!["new1:8443".into(), "new2:8443".into()]);
        let snap = ClientStatusSnapshot::from_ctx(true, &ctx, Instant::now());
        let pool = snap.pool.expect("pool should be Some after reload");
        let addrs: Vec<&str> = pool.entries.iter().map(|e| e.addr.as_str()).collect();
        assert_eq!(addrs, vec!["new1:8443", "new2:8443"]);
    }

    #[test]
    fn from_ctx_pool_snapshot_clears_to_none_after_empty_reload() {
        // Operator transitions from pool mode → single-endpoint
        // mode by reloading with an empty list.
        let ctx = Arc::new(ClientCtx::new(
            Arc::new(CarrierHealth::new()),
            Some(Arc::new(
                crate::endpoint_pool::EndpointPool::new(vec!["a:1".into()]).unwrap(),
            )),
            None,
            0,
            true,
        ));
        ctx.reloadable_pool.reload_from_addrs(vec![]);
        let snap = ClientStatusSnapshot::from_ctx(true, &ctx, Instant::now());
        assert!(
            snap.pool.is_none(),
            "pool should be None after empty reload"
        );
    }

    #[test]
    fn route_404_on_metrics_substring_path() {
        // /metricsleak should NOT match /metrics — mirrors the
        // server-side admin endpoint's substring-rejection rule.
        let (status, _ctype, _body) = route("GET /metricsleak HTTP/1.1\r\n\r\n", &empty_snap());
        assert!(status.starts_with("HTTP/1.1 404"));
    }

    #[test]
    fn text_renders_dials_line_always() {
        let snap = ClientStatusSnapshot {
            dials: DialCounters {
                attempted: 100,
                succeeded: 95,
                failed: 5,
            },
            ..ClientStatusSnapshot::default()
        };
        let s = format!("{snap}");
        assert!(s.contains("Dials: 100 attempted (95 ok, 5 failed)"), "{s}");
    }
}
