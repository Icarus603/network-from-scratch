//! Minimal HTTP endpoints for Prometheus scrape + container probes.
//!
//! Deliberately hand-rolled (no external HTTP framework) — three
//! orthogonal single-purpose endpoints:
//!
//! - `GET /metrics`  → Prometheus 0.0.4 text exposition.
//! - `GET /healthz`  → 200 if `metrics.alive`, 503 otherwise.
//!   Container/orchestrator **liveness** probe — a 503 here means the
//!   runtime should restart us.
//! - `GET /readyz`   → 200 if `metrics.ready`, 503 otherwise.
//!   Load-balancer **readiness** probe — a 503 here means stop sending
//!   new traffic but don't kill the process. We deliberately flip this
//!   to `false` during graceful drain so the LB drains us before
//!   SIGTERM finishes.
//!
//! Body of each probe is a single short status line for human
//! debugging via `curl`.
//!
//! Reference: [Prometheus exposition formats](https://prometheus.io/docs/instrumenting/exposition_formats/),
//! Kubernetes [probe HTTP semantics](https://kubernetes.io/docs/concepts/configuration/liveness-readiness-startup-probes/).
//!
//! Usage from the server binary:
//! ```ignore
//! let metrics = Arc::new(ServerMetrics::default());
//! tokio::spawn(metrics_http::serve("127.0.0.1:9090", Arc::clone(&metrics)));
//! ```
//!
//! Bind only to a private interface; the endpoint has no
//! authentication.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::metrics::ServerMetrics;

/// Optional bearer-token gate for `/metrics`.
///
/// Stored in a [`Zeroizing<String>`] so the token is wiped from
/// memory on drop. Compared with [`subtle::ConstantTimeEq`] to avoid
/// timing oracles that could let an attacker bisect the token byte
/// by byte.
///
/// `/healthz` and `/readyz` are **never** gated — orchestrator probes
/// (kubelet, ECS health checks, GCP load balancers) don't carry
/// bearer tokens, and the bodies leak only "alive"/"dead"/"ready"/
/// "draining" anyway.
#[derive(Clone)]
pub struct MetricsAuth {
    token: Arc<Zeroizing<String>>,
}

impl MetricsAuth {
    /// Wrap a bearer token. The string content is zeroized on drop.
    /// Empty tokens are rejected — pass `None` to the serve functions
    /// instead.
    #[must_use]
    pub fn new(token: impl Into<String>) -> Option<Self> {
        let s = token.into();
        if s.is_empty() {
            return None;
        }
        Some(Self {
            token: Arc::new(Zeroizing::new(s)),
        })
    }

    /// Constant-time check that the `Authorization` header value
    /// (after stripping `Bearer ` prefix) matches the configured
    /// token. Returns `false` for any prefix mismatch, empty header,
    /// or token-length mismatch (the length mismatch is divulged
    /// either way, but knowing the length narrows search space by
    /// at most ~7 bits which is negligible for a 32-byte token).
    fn matches(&self, header_value: &str) -> bool {
        let presented = match header_value.strip_prefix("Bearer ") {
            Some(s) => s.trim_end_matches(['\r', '\n', ' ']),
            None => return false,
        };
        let expected = self.token.as_bytes();
        let got = presented.as_bytes();
        if expected.len() != got.len() {
            return false;
        }
        expected.ct_eq(got).into()
    }
}

impl std::fmt::Debug for MetricsAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetricsAuth")
            .field("token", &"<redacted>")
            .finish()
    }
}

/// Spawn an HTTP listener that serves `/metrics`, `/healthz`, `/readyz`
/// from `metrics`. Returns only on listener error (which under normal
/// operation never happens — the task is meant to run for the lifetime
/// of the server).
///
/// Equivalent to calling [`serve_with_auth`] with `auth = None`.
pub async fn serve(addr: &str, metrics: Arc<ServerMetrics>) -> std::io::Result<()> {
    serve_with_auth(addr, metrics, None).await
}

/// Like [`serve`] but optionally requires `Authorization: Bearer <token>`
/// on `/metrics` requests. `/healthz` and `/readyz` are never gated.
pub async fn serve_with_auth(
    addr: &str,
    metrics: Arc<ServerMetrics>,
    auth: Option<MetricsAuth>,
) -> std::io::Result<()> {
    serve_with_auth_full(addr, metrics, auth, None).await
}

/// Full variant of [`serve_with_auth`] that optionally takes a
/// `ProbeAnomalyDetector` so the `/metrics` exposition includes
/// the detector's diagnostic gauges + recent-fires lines. Use this
/// from the production binary when a detector is configured.
/// Back-compat shim — forwards to [`serve_with_auth_full_v2`] with
/// `auto_deny = None`.
pub async fn serve_with_auth_full(
    addr: &str,
    metrics: Arc<ServerMetrics>,
    auth: Option<MetricsAuth>,
    probe_anomaly: Option<Arc<crate::probe_anomaly::ProbeAnomalyDetector>>,
) -> std::io::Result<()> {
    serve_with_auth_full_v2(addr, metrics, auth, probe_anomaly, None).await
}

/// v2 of [`serve_with_auth_full`] — adds an optional `AutoDenyList`
/// so the `/metrics` exposition includes the active-deny gauges +
/// per-prefix `remaining_secs` labelled gauges. Operators see WHO
/// is currently blocked AND for how much longer, directly in
/// Prometheus / Grafana. Back-compat shim — forwards to
/// [`serve_with_auth_full_v3`] with `tls_acceptor = None`.
pub async fn serve_with_auth_full_v2(
    addr: &str,
    metrics: Arc<ServerMetrics>,
    auth: Option<MetricsAuth>,
    probe_anomaly: Option<Arc<crate::probe_anomaly::ProbeAnomalyDetector>>,
    auto_deny: Option<Arc<crate::auto_deny::AutoDenyList>>,
) -> std::io::Result<()> {
    serve_with_auth_full_v3(addr, metrics, auth, probe_anomaly, auto_deny, None).await
}

/// v3 of [`serve_with_auth_full`] — adds an optional
/// `ReloadableAcceptor` so the `/metrics` exposition includes the
/// TLS cert-expiry gauge (`proteus_tls_cert_not_after_unix_seconds`)
/// and the SIGHUP reload counters (`proteus_tls_reload_attempts_total`
/// / `_succeeded_total`). Operators can PromQL-alert on cert expiry
/// approaching (Let's Encrypt 90-day issuance, 60-day renewal) AND
/// detect silent reload failures (when `attempts - succeeded` grows).
pub async fn serve_with_auth_full_v3(
    addr: &str,
    metrics: Arc<ServerMetrics>,
    auth: Option<MetricsAuth>,
    probe_anomaly: Option<Arc<crate::probe_anomaly::ProbeAnomalyDetector>>,
    auto_deny: Option<Arc<crate::auto_deny::AutoDenyList>>,
    tls_acceptor: Option<crate::tls::ReloadableAcceptor>,
) -> std::io::Result<()> {
    // Back-compat shim — forwards to v4 with no config-presence block.
    serve_with_auth_full_v4(
        addr,
        metrics,
        auth,
        probe_anomaly,
        auto_deny,
        tls_acceptor,
        None,
    )
    .await
}

/// v4 of [`serve_with_auth_full`] — adds an optional
/// `config_presence` Prometheus block to the `/metrics` exposition.
/// Operators read the `proteus_config_section_active{section="..."}`
/// gauges to answer "did my YAML edit even land?" without re-reading
/// the on-disk file. The block is rendered once at startup (config
/// is set-at-startup and SIGHUP-stable on the server) and the same
/// string is appended verbatim to every scrape response.
pub async fn serve_with_auth_full_v4(
    addr: &str,
    metrics: Arc<ServerMetrics>,
    auth: Option<MetricsAuth>,
    probe_anomaly: Option<Arc<crate::probe_anomaly::ProbeAnomalyDetector>>,
    auto_deny: Option<Arc<crate::auto_deny::AutoDenyList>>,
    tls_acceptor: Option<crate::tls::ReloadableAcceptor>,
    config_presence: Option<Arc<String>>,
) -> std::io::Result<()> {
    serve_with_auth_full_v5(
        addr,
        metrics,
        auth,
        probe_anomaly,
        auto_deny,
        tls_acceptor,
        config_presence,
        None,
    )
    .await
}

/// v5 of [`serve_with_auth_full`] — adds an optional
/// `ProcessInfo` so the `/metrics` exposition includes the
/// process-lifecycle gauges (`proteus_process_start_unix_seconds`,
/// `proteus_process_uptime_seconds`, `proteus_build_info`).
/// Operators query `proteus_build_info{version!="X.Y.Z"}` to find
/// instances that didn't pick up a fleet rollout, and
/// `(time() - proteus_process_start_unix_seconds) < 60` to detect
/// processes that just restarted (e.g. after an OOM kill).
#[allow(clippy::too_many_arguments)]
pub async fn serve_with_auth_full_v5(
    addr: &str,
    metrics: Arc<ServerMetrics>,
    auth: Option<MetricsAuth>,
    probe_anomaly: Option<Arc<crate::probe_anomaly::ProbeAnomalyDetector>>,
    auto_deny: Option<Arc<crate::auto_deny::AutoDenyList>>,
    tls_acceptor: Option<crate::tls::ReloadableAcceptor>,
    config_presence: Option<Arc<String>>,
    process_info: Option<Arc<crate::process_info::ProcessInfo>>,
) -> std::io::Result<()> {
    // Back-compat shim — forwards to v6 with `per_user = None`.
    serve_with_auth_full_v6(
        addr,
        metrics,
        auth,
        probe_anomaly,
        auto_deny,
        tls_acceptor,
        config_presence,
        process_info,
        None,
    )
    .await
}

/// v6 of [`serve_with_auth_full`] — adds an optional
/// `PerUserBandwidth` accumulator. When supplied, the `/metrics`
/// exposition includes the
/// `proteus_per_user_bytes_{sent,received}_total{user_id="…"}`
/// series + the `proteus_per_user_bandwidth_tracked_users` gauge.
/// Operators query `topk(5, rate(proteus_per_user_bytes_sent_total[1m]))`
/// to see who's hogging bandwidth in real time.
///
/// Back-compat shim — forwards to v7 with
/// `per_user_conn_limiter = None`.
#[allow(clippy::too_many_arguments)]
pub async fn serve_with_auth_full_v6(
    addr: &str,
    metrics: Arc<ServerMetrics>,
    auth: Option<MetricsAuth>,
    probe_anomaly: Option<Arc<crate::probe_anomaly::ProbeAnomalyDetector>>,
    auto_deny: Option<Arc<crate::auto_deny::AutoDenyList>>,
    tls_acceptor: Option<crate::tls::ReloadableAcceptor>,
    config_presence: Option<Arc<String>>,
    process_info: Option<Arc<crate::process_info::ProcessInfo>>,
    per_user: Option<Arc<crate::per_user_bandwidth::PerUserBandwidth>>,
) -> std::io::Result<()> {
    serve_with_auth_full_v7(
        addr,
        metrics,
        auth,
        probe_anomaly,
        auto_deny,
        tls_acceptor,
        config_presence,
        process_info,
        per_user,
        None,
    )
    .await
}

/// v7 of [`serve_with_auth_full`] — adds an optional
/// `PerUserConnLimiter`. When supplied, the `/metrics` exposition
/// includes the
/// `proteus_per_user_conn_limit_{max_per_user,active_users,rejected_total}`
/// series. Operators alert on `rate(proteus_per_user_conn_limit_rejected_total[5m]) > 0`
/// to catch credential abuse via parallel-session amplification.
///
/// Back-compat shim — forwards to v8 with `abuse_fires = None`.
#[allow(clippy::too_many_arguments)]
pub async fn serve_with_auth_full_v7(
    addr: &str,
    metrics: Arc<ServerMetrics>,
    auth: Option<MetricsAuth>,
    probe_anomaly: Option<Arc<crate::probe_anomaly::ProbeAnomalyDetector>>,
    auto_deny: Option<Arc<crate::auto_deny::AutoDenyList>>,
    tls_acceptor: Option<crate::tls::ReloadableAcceptor>,
    config_presence: Option<Arc<String>>,
    process_info: Option<Arc<crate::process_info::ProcessInfo>>,
    per_user: Option<Arc<crate::per_user_bandwidth::PerUserBandwidth>>,
    per_user_conn_limiter: Option<Arc<crate::per_user_conn_limit::PerUserConnLimiter>>,
) -> std::io::Result<()> {
    serve_with_auth_full_v8(
        addr,
        metrics,
        auth,
        probe_anomaly,
        auto_deny,
        tls_acceptor,
        config_presence,
        process_info,
        per_user,
        per_user_conn_limiter,
        None,
    )
    .await
}

/// v8 of [`serve_with_auth_full`] — adds an optional
/// `AbuseFireBuffer`. Back-compat shim — forwards to v9 with
/// `user_quarantine = None`.
#[allow(clippy::too_many_arguments)]
pub async fn serve_with_auth_full_v8(
    addr: &str,
    metrics: Arc<ServerMetrics>,
    auth: Option<MetricsAuth>,
    probe_anomaly: Option<Arc<crate::probe_anomaly::ProbeAnomalyDetector>>,
    auto_deny: Option<Arc<crate::auto_deny::AutoDenyList>>,
    tls_acceptor: Option<crate::tls::ReloadableAcceptor>,
    config_presence: Option<Arc<String>>,
    process_info: Option<Arc<crate::process_info::ProcessInfo>>,
    per_user: Option<Arc<crate::per_user_bandwidth::PerUserBandwidth>>,
    per_user_conn_limiter: Option<Arc<crate::per_user_conn_limit::PerUserConnLimiter>>,
    abuse_fires: Option<Arc<crate::abuse_fires::AbuseFireBuffer>>,
) -> std::io::Result<()> {
    serve_with_auth_full_v9(
        addr,
        metrics,
        auth,
        probe_anomaly,
        auto_deny,
        tls_acceptor,
        config_presence,
        process_info,
        per_user,
        per_user_conn_limiter,
        abuse_fires,
        None,
    )
    .await
}

/// v9 of [`serve_with_auth_full`] — adds an optional
/// `UserQuarantineList`. Back-compat shim — forwards to v10 with
/// `user_quota = None`.
#[allow(clippy::too_many_arguments)]
pub async fn serve_with_auth_full_v9(
    addr: &str,
    metrics: Arc<ServerMetrics>,
    auth: Option<MetricsAuth>,
    probe_anomaly: Option<Arc<crate::probe_anomaly::ProbeAnomalyDetector>>,
    auto_deny: Option<Arc<crate::auto_deny::AutoDenyList>>,
    tls_acceptor: Option<crate::tls::ReloadableAcceptor>,
    config_presence: Option<Arc<String>>,
    process_info: Option<Arc<crate::process_info::ProcessInfo>>,
    per_user: Option<Arc<crate::per_user_bandwidth::PerUserBandwidth>>,
    per_user_conn_limiter: Option<Arc<crate::per_user_conn_limit::PerUserConnLimiter>>,
    abuse_fires: Option<Arc<crate::abuse_fires::AbuseFireBuffer>>,
    user_quarantine: Option<Arc<crate::user_quarantine::UserQuarantineList>>,
) -> std::io::Result<()> {
    serve_with_auth_full_v10(
        addr,
        metrics,
        auth,
        probe_anomaly,
        auto_deny,
        tls_acceptor,
        config_presence,
        process_info,
        per_user,
        per_user_conn_limiter,
        abuse_fires,
        user_quarantine,
        None,
    )
    .await
}

/// v10 of [`serve_with_auth_full`] — adds an optional
/// `PerUserQuotaTracker`. Back-compat shim — forwards to v11
/// with `tls_cert_watcher = None`.
#[allow(clippy::too_many_arguments)]
pub async fn serve_with_auth_full_v10(
    addr: &str,
    metrics: Arc<ServerMetrics>,
    auth: Option<MetricsAuth>,
    probe_anomaly: Option<Arc<crate::probe_anomaly::ProbeAnomalyDetector>>,
    auto_deny: Option<Arc<crate::auto_deny::AutoDenyList>>,
    tls_acceptor: Option<crate::tls::ReloadableAcceptor>,
    config_presence: Option<Arc<String>>,
    process_info: Option<Arc<crate::process_info::ProcessInfo>>,
    per_user: Option<Arc<crate::per_user_bandwidth::PerUserBandwidth>>,
    per_user_conn_limiter: Option<Arc<crate::per_user_conn_limit::PerUserConnLimiter>>,
    abuse_fires: Option<Arc<crate::abuse_fires::AbuseFireBuffer>>,
    user_quarantine: Option<Arc<crate::user_quarantine::UserQuarantineList>>,
    user_quota: Option<Arc<crate::user_quota::PerUserQuotaTracker>>,
) -> std::io::Result<()> {
    serve_with_auth_full_v11(
        addr,
        metrics,
        auth,
        probe_anomaly,
        auto_deny,
        tls_acceptor,
        config_presence,
        process_info,
        per_user,
        per_user_conn_limiter,
        abuse_fires,
        user_quarantine,
        user_quota,
        None,
    )
    .await
}

/// Type alias for a closure that renders a Prometheus exposition
/// block on demand. Lets callers inject a *live-evaluated* block
/// (e.g. a panic counter that mutates over the process lifetime)
/// without re-plumbing every constructor. Stored as `Arc<dyn ...>`
/// so multiple scrape handlers can share a single closure cheaply.
pub type LiveMetricsBlock = dyn Fn() -> String + Send + Sync + 'static;

/// v11 of [`serve_with_auth_full`] — adds an optional
/// `CertFileWatcher`. When supplied, the `/metrics` body
/// includes the four `proteus_tls_cert_watcher_*` counters.
/// Operators alert on
/// `rate(proteus_tls_cert_watcher_auto_reload_failed_total[5m]) > 0`
/// to spot a non-Let's-Encrypt deploy that produced a broken
/// cert (the binary keeps serving the OLD cert; the counter
/// surfaces the silent failure).
///
/// Back-compat shim — forwards to [`serve_with_auth_full_v12`]
/// with `live_blocks = vec![]`.
#[allow(clippy::too_many_arguments)]
pub async fn serve_with_auth_full_v11(
    addr: &str,
    metrics: Arc<ServerMetrics>,
    auth: Option<MetricsAuth>,
    probe_anomaly: Option<Arc<crate::probe_anomaly::ProbeAnomalyDetector>>,
    auto_deny: Option<Arc<crate::auto_deny::AutoDenyList>>,
    tls_acceptor: Option<crate::tls::ReloadableAcceptor>,
    config_presence: Option<Arc<String>>,
    process_info: Option<Arc<crate::process_info::ProcessInfo>>,
    per_user: Option<Arc<crate::per_user_bandwidth::PerUserBandwidth>>,
    per_user_conn_limiter: Option<Arc<crate::per_user_conn_limit::PerUserConnLimiter>>,
    abuse_fires: Option<Arc<crate::abuse_fires::AbuseFireBuffer>>,
    user_quarantine: Option<Arc<crate::user_quarantine::UserQuarantineList>>,
    user_quota: Option<Arc<crate::user_quota::PerUserQuotaTracker>>,
    tls_cert_watcher: Option<Arc<crate::tls_watcher::CertFileWatcher>>,
) -> std::io::Result<()> {
    serve_with_auth_full_v12(
        addr,
        metrics,
        auth,
        probe_anomaly,
        auto_deny,
        tls_acceptor,
        config_presence,
        process_info,
        per_user,
        per_user_conn_limiter,
        abuse_fires,
        user_quarantine,
        user_quota,
        tls_cert_watcher,
        Vec::new(),
    )
    .await
}

/// v12 of [`serve_with_auth_full`] — adds an `Vec<Arc<LiveMetricsBlock>>`
/// of caller-supplied closures whose render output is appended to
/// every `/metrics` scrape AND to the `/diagnose` body. Designed for
/// the panic-counter case where the gauge value can change between
/// scrapes — `config_presence` is one-shot-at-startup so it can't
/// host a live counter without losing scrape-time freshness.
///
/// Closures are invoked once per request, in the order supplied; each
/// must return a self-contained Prometheus block (HELP + TYPE + line)
/// so the order between blocks doesn't matter to dashboards. Failure
/// surface is bounded — closures are run in the same task as the
/// request handler, so a panic inside a closure WOULD be caught by
/// the same panic hook that's likely supplying the counter; expensive
/// closures slow the scrape. Keep them cheap (atomic load + format!()).
#[allow(clippy::too_many_arguments)]
pub async fn serve_with_auth_full_v12(
    addr: &str,
    metrics: Arc<ServerMetrics>,
    auth: Option<MetricsAuth>,
    probe_anomaly: Option<Arc<crate::probe_anomaly::ProbeAnomalyDetector>>,
    auto_deny: Option<Arc<crate::auto_deny::AutoDenyList>>,
    tls_acceptor: Option<crate::tls::ReloadableAcceptor>,
    config_presence: Option<Arc<String>>,
    process_info: Option<Arc<crate::process_info::ProcessInfo>>,
    per_user: Option<Arc<crate::per_user_bandwidth::PerUserBandwidth>>,
    per_user_conn_limiter: Option<Arc<crate::per_user_conn_limit::PerUserConnLimiter>>,
    abuse_fires: Option<Arc<crate::abuse_fires::AbuseFireBuffer>>,
    user_quarantine: Option<Arc<crate::user_quarantine::UserQuarantineList>>,
    user_quota: Option<Arc<crate::user_quota::PerUserQuotaTracker>>,
    tls_cert_watcher: Option<Arc<crate::tls_watcher::CertFileWatcher>>,
    live_blocks: Vec<Arc<LiveMetricsBlock>>,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let auth_enabled = auth.is_some();
    let probe_anomaly_enabled = probe_anomaly.is_some();
    let auto_deny_enabled = auto_deny.is_some();
    let tls_observability = tls_acceptor.is_some();
    let config_presence_enabled = config_presence.is_some();
    let process_info_enabled = process_info.is_some();
    let per_user_enabled = per_user.is_some();
    let per_user_conn_limit_enabled = per_user_conn_limiter.is_some();
    let abuse_fires_enabled = abuse_fires.is_some();
    let user_quarantine_enabled = user_quarantine.is_some();
    let user_quota_enabled = user_quota.is_some();
    let tls_cert_watcher_enabled = tls_cert_watcher.is_some();
    let live_blocks_count = live_blocks.len();
    info!(
        addr = %listener.local_addr()?,
        auth = auth_enabled,
        probe_anomaly = probe_anomaly_enabled,
        auto_deny = auto_deny_enabled,
        tls_observability,
        config_presence = config_presence_enabled,
        process_info = process_info_enabled,
        per_user_bandwidth = per_user_enabled,
        per_user_conn_limit = per_user_conn_limit_enabled,
        abuse_fires = abuse_fires_enabled,
        user_quarantine = user_quarantine_enabled,
        user_quota = user_quota_enabled,
        tls_cert_watcher = tls_cert_watcher_enabled,
        live_blocks = live_blocks_count,
        "metrics endpoint bound",
    );
    loop {
        let (stream, _peer) = listener.accept().await?;
        let metrics = Arc::clone(&metrics);
        let auth = auth.clone();
        let probe_anomaly = probe_anomaly.clone();
        let auto_deny = auto_deny.clone();
        let tls_acceptor = tls_acceptor.clone();
        let config_presence = config_presence.clone();
        let process_info = process_info.clone();
        let per_user = per_user.clone();
        let per_user_conn_limiter = per_user_conn_limiter.clone();
        let abuse_fires = abuse_fires.clone();
        let user_quarantine = user_quarantine.clone();
        let user_quota = user_quota.clone();
        let tls_cert_watcher = tls_cert_watcher.clone();
        let live_blocks = live_blocks.clone();
        tokio::spawn(handle_connection_v12(
            stream,
            metrics,
            auth,
            probe_anomaly,
            auto_deny,
            tls_acceptor,
            config_presence,
            process_info,
            per_user,
            per_user_conn_limiter,
            abuse_fires,
            user_quarantine,
            user_quota,
            tls_cert_watcher,
            live_blocks,
        ));
    }
}

/// Same as [`serve`] but the caller supplies an already-bound listener
/// (e.g. so a test can pick `127.0.0.1:0` and read the local addr).
pub async fn serve_on_listener(
    listener: TcpListener,
    metrics: Arc<ServerMetrics>,
) -> std::io::Result<()> {
    serve_on_listener_with_auth(listener, metrics, None).await
}

/// Like [`serve_on_listener`] with an optional bearer-token gate on
/// `/metrics`.
pub async fn serve_on_listener_with_auth(
    listener: TcpListener,
    metrics: Arc<ServerMetrics>,
    auth: Option<MetricsAuth>,
) -> std::io::Result<()> {
    serve_on_listener_full(listener, metrics, auth, None).await
}

/// Full-featured variant: the caller may supply a
/// `ProbeAnomalyDetector` so the `/metrics` exposition includes the
/// detector's gauges + recent-fires diagnostic lines. Back-compat
/// shim — forwards to [`serve_on_listener_full_v2`] with
/// `auto_deny = None`.
pub async fn serve_on_listener_full(
    listener: TcpListener,
    metrics: Arc<ServerMetrics>,
    auth: Option<MetricsAuth>,
    probe_anomaly: Option<Arc<crate::probe_anomaly::ProbeAnomalyDetector>>,
) -> std::io::Result<()> {
    serve_on_listener_full_v2(listener, metrics, auth, probe_anomaly, None).await
}

/// v2 of [`serve_on_listener_full`] — adds an optional `AutoDenyList`
/// for the same `/metrics` exposition extension as
/// [`serve_with_auth_full_v2`]. Back-compat shim — forwards to
/// [`serve_on_listener_full_v3`] with `tls_acceptor = None`.
pub async fn serve_on_listener_full_v2(
    listener: TcpListener,
    metrics: Arc<ServerMetrics>,
    auth: Option<MetricsAuth>,
    probe_anomaly: Option<Arc<crate::probe_anomaly::ProbeAnomalyDetector>>,
    auto_deny: Option<Arc<crate::auto_deny::AutoDenyList>>,
) -> std::io::Result<()> {
    serve_on_listener_full_v3(listener, metrics, auth, probe_anomaly, auto_deny, None).await
}

/// v3 of [`serve_on_listener_full`] — adds an optional
/// `ReloadableAcceptor` for the same TLS cert-expiry + reload-counter
/// extension as [`serve_with_auth_full_v3`].
pub async fn serve_on_listener_full_v3(
    listener: TcpListener,
    metrics: Arc<ServerMetrics>,
    auth: Option<MetricsAuth>,
    probe_anomaly: Option<Arc<crate::probe_anomaly::ProbeAnomalyDetector>>,
    auto_deny: Option<Arc<crate::auto_deny::AutoDenyList>>,
    tls_acceptor: Option<crate::tls::ReloadableAcceptor>,
) -> std::io::Result<()> {
    serve_on_listener_full_v4(
        listener,
        metrics,
        auth,
        probe_anomaly,
        auto_deny,
        tls_acceptor,
        None,
    )
    .await
}

/// v4 of [`serve_on_listener_full`] — adds the config-presence
/// Prometheus block. See [`serve_with_auth_full_v4`] for the
/// rationale.
pub async fn serve_on_listener_full_v4(
    listener: TcpListener,
    metrics: Arc<ServerMetrics>,
    auth: Option<MetricsAuth>,
    probe_anomaly: Option<Arc<crate::probe_anomaly::ProbeAnomalyDetector>>,
    auto_deny: Option<Arc<crate::auto_deny::AutoDenyList>>,
    tls_acceptor: Option<crate::tls::ReloadableAcceptor>,
    config_presence: Option<Arc<String>>,
) -> std::io::Result<()> {
    serve_on_listener_full_v5(
        listener,
        metrics,
        auth,
        probe_anomaly,
        auto_deny,
        tls_acceptor,
        config_presence,
        None,
    )
    .await
}

/// v5 of [`serve_on_listener_full`] — adds the process-lifecycle
/// block. Back-compat shim that forwards to v6 with `per_user = None`.
#[allow(clippy::too_many_arguments)]
pub async fn serve_on_listener_full_v5(
    listener: TcpListener,
    metrics: Arc<ServerMetrics>,
    auth: Option<MetricsAuth>,
    probe_anomaly: Option<Arc<crate::probe_anomaly::ProbeAnomalyDetector>>,
    auto_deny: Option<Arc<crate::auto_deny::AutoDenyList>>,
    tls_acceptor: Option<crate::tls::ReloadableAcceptor>,
    config_presence: Option<Arc<String>>,
    process_info: Option<Arc<crate::process_info::ProcessInfo>>,
) -> std::io::Result<()> {
    serve_on_listener_full_v6(
        listener,
        metrics,
        auth,
        probe_anomaly,
        auto_deny,
        tls_acceptor,
        config_presence,
        process_info,
        None,
    )
    .await
}

/// v6 of [`serve_on_listener_full`] — adds the per-user
/// bandwidth block. See [`serve_with_auth_full_v6`] for rationale.
#[allow(clippy::too_many_arguments)]
pub async fn serve_on_listener_full_v6(
    listener: TcpListener,
    metrics: Arc<ServerMetrics>,
    auth: Option<MetricsAuth>,
    probe_anomaly: Option<Arc<crate::probe_anomaly::ProbeAnomalyDetector>>,
    auto_deny: Option<Arc<crate::auto_deny::AutoDenyList>>,
    tls_acceptor: Option<crate::tls::ReloadableAcceptor>,
    config_presence: Option<Arc<String>>,
    process_info: Option<Arc<crate::process_info::ProcessInfo>>,
    per_user: Option<Arc<crate::per_user_bandwidth::PerUserBandwidth>>,
) -> std::io::Result<()> {
    loop {
        let (stream, _peer) = listener.accept().await?;
        let metrics = Arc::clone(&metrics);
        let auth = auth.clone();
        let probe_anomaly = probe_anomaly.clone();
        let auto_deny = auto_deny.clone();
        let tls_acceptor = tls_acceptor.clone();
        let config_presence = config_presence.clone();
        let process_info = process_info.clone();
        let per_user = per_user.clone();
        tokio::spawn(handle_connection(
            stream,
            metrics,
            auth,
            probe_anomaly,
            auto_deny,
            tls_acceptor,
            config_presence,
            process_info,
            per_user,
        ));
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    stream: tokio::net::TcpStream,
    metrics: Arc<ServerMetrics>,
    auth: Option<MetricsAuth>,
    probe_anomaly: Option<Arc<crate::probe_anomaly::ProbeAnomalyDetector>>,
    auto_deny: Option<Arc<crate::auto_deny::AutoDenyList>>,
    tls_acceptor: Option<crate::tls::ReloadableAcceptor>,
    config_presence: Option<Arc<String>>,
    process_info: Option<Arc<crate::process_info::ProcessInfo>>,
    per_user: Option<Arc<crate::per_user_bandwidth::PerUserBandwidth>>,
) {
    // Back-compat shim: forwards to v7 with no conn-limiter.
    handle_connection_v7(
        stream,
        metrics,
        auth,
        probe_anomaly,
        auto_deny,
        tls_acceptor,
        config_presence,
        process_info,
        per_user,
        None,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn handle_connection_v7(
    stream: tokio::net::TcpStream,
    metrics: Arc<ServerMetrics>,
    auth: Option<MetricsAuth>,
    probe_anomaly: Option<Arc<crate::probe_anomaly::ProbeAnomalyDetector>>,
    auto_deny: Option<Arc<crate::auto_deny::AutoDenyList>>,
    tls_acceptor: Option<crate::tls::ReloadableAcceptor>,
    config_presence: Option<Arc<String>>,
    process_info: Option<Arc<crate::process_info::ProcessInfo>>,
    per_user: Option<Arc<crate::per_user_bandwidth::PerUserBandwidth>>,
    per_user_conn_limiter: Option<Arc<crate::per_user_conn_limit::PerUserConnLimiter>>,
) {
    handle_connection_v8(
        stream,
        metrics,
        auth,
        probe_anomaly,
        auto_deny,
        tls_acceptor,
        config_presence,
        process_info,
        per_user,
        per_user_conn_limiter,
        None,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn handle_connection_v8(
    stream: tokio::net::TcpStream,
    metrics: Arc<ServerMetrics>,
    auth: Option<MetricsAuth>,
    probe_anomaly: Option<Arc<crate::probe_anomaly::ProbeAnomalyDetector>>,
    auto_deny: Option<Arc<crate::auto_deny::AutoDenyList>>,
    tls_acceptor: Option<crate::tls::ReloadableAcceptor>,
    config_presence: Option<Arc<String>>,
    process_info: Option<Arc<crate::process_info::ProcessInfo>>,
    per_user: Option<Arc<crate::per_user_bandwidth::PerUserBandwidth>>,
    per_user_conn_limiter: Option<Arc<crate::per_user_conn_limit::PerUserConnLimiter>>,
    abuse_fires: Option<Arc<crate::abuse_fires::AbuseFireBuffer>>,
) {
    handle_connection_v9(
        stream,
        metrics,
        auth,
        probe_anomaly,
        auto_deny,
        tls_acceptor,
        config_presence,
        process_info,
        per_user,
        per_user_conn_limiter,
        abuse_fires,
        None,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn handle_connection_v9(
    stream: tokio::net::TcpStream,
    metrics: Arc<ServerMetrics>,
    auth: Option<MetricsAuth>,
    probe_anomaly: Option<Arc<crate::probe_anomaly::ProbeAnomalyDetector>>,
    auto_deny: Option<Arc<crate::auto_deny::AutoDenyList>>,
    tls_acceptor: Option<crate::tls::ReloadableAcceptor>,
    config_presence: Option<Arc<String>>,
    process_info: Option<Arc<crate::process_info::ProcessInfo>>,
    per_user: Option<Arc<crate::per_user_bandwidth::PerUserBandwidth>>,
    per_user_conn_limiter: Option<Arc<crate::per_user_conn_limit::PerUserConnLimiter>>,
    abuse_fires: Option<Arc<crate::abuse_fires::AbuseFireBuffer>>,
    user_quarantine: Option<Arc<crate::user_quarantine::UserQuarantineList>>,
) {
    handle_connection_v10(
        stream,
        metrics,
        auth,
        probe_anomaly,
        auto_deny,
        tls_acceptor,
        config_presence,
        process_info,
        per_user,
        per_user_conn_limiter,
        abuse_fires,
        user_quarantine,
        None,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn handle_connection_v10(
    stream: tokio::net::TcpStream,
    metrics: Arc<ServerMetrics>,
    auth: Option<MetricsAuth>,
    probe_anomaly: Option<Arc<crate::probe_anomaly::ProbeAnomalyDetector>>,
    auto_deny: Option<Arc<crate::auto_deny::AutoDenyList>>,
    tls_acceptor: Option<crate::tls::ReloadableAcceptor>,
    config_presence: Option<Arc<String>>,
    process_info: Option<Arc<crate::process_info::ProcessInfo>>,
    per_user: Option<Arc<crate::per_user_bandwidth::PerUserBandwidth>>,
    per_user_conn_limiter: Option<Arc<crate::per_user_conn_limit::PerUserConnLimiter>>,
    abuse_fires: Option<Arc<crate::abuse_fires::AbuseFireBuffer>>,
    user_quarantine: Option<Arc<crate::user_quarantine::UserQuarantineList>>,
    user_quota: Option<Arc<crate::user_quota::PerUserQuotaTracker>>,
) {
    handle_connection_v11(
        stream,
        metrics,
        auth,
        probe_anomaly,
        auto_deny,
        tls_acceptor,
        config_presence,
        process_info,
        per_user,
        per_user_conn_limiter,
        abuse_fires,
        user_quarantine,
        user_quota,
        None,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn handle_connection_v11(
    stream: tokio::net::TcpStream,
    metrics: Arc<ServerMetrics>,
    auth: Option<MetricsAuth>,
    probe_anomaly: Option<Arc<crate::probe_anomaly::ProbeAnomalyDetector>>,
    auto_deny: Option<Arc<crate::auto_deny::AutoDenyList>>,
    tls_acceptor: Option<crate::tls::ReloadableAcceptor>,
    config_presence: Option<Arc<String>>,
    process_info: Option<Arc<crate::process_info::ProcessInfo>>,
    per_user: Option<Arc<crate::per_user_bandwidth::PerUserBandwidth>>,
    per_user_conn_limiter: Option<Arc<crate::per_user_conn_limit::PerUserConnLimiter>>,
    abuse_fires: Option<Arc<crate::abuse_fires::AbuseFireBuffer>>,
    user_quarantine: Option<Arc<crate::user_quarantine::UserQuarantineList>>,
    user_quota: Option<Arc<crate::user_quota::PerUserQuotaTracker>>,
    tls_cert_watcher: Option<Arc<crate::tls_watcher::CertFileWatcher>>,
) {
    handle_connection_v12(
        stream,
        metrics,
        auth,
        probe_anomaly,
        auto_deny,
        tls_acceptor,
        config_presence,
        process_info,
        per_user,
        per_user_conn_limiter,
        abuse_fires,
        user_quarantine,
        user_quota,
        tls_cert_watcher,
        Vec::new(),
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn handle_connection_v12(
    mut stream: tokio::net::TcpStream,
    metrics: Arc<ServerMetrics>,
    auth: Option<MetricsAuth>,
    probe_anomaly: Option<Arc<crate::probe_anomaly::ProbeAnomalyDetector>>,
    auto_deny: Option<Arc<crate::auto_deny::AutoDenyList>>,
    tls_acceptor: Option<crate::tls::ReloadableAcceptor>,
    config_presence: Option<Arc<String>>,
    process_info: Option<Arc<crate::process_info::ProcessInfo>>,
    per_user: Option<Arc<crate::per_user_bandwidth::PerUserBandwidth>>,
    per_user_conn_limiter: Option<Arc<crate::per_user_conn_limit::PerUserConnLimiter>>,
    abuse_fires: Option<Arc<crate::abuse_fires::AbuseFireBuffer>>,
    user_quarantine: Option<Arc<crate::user_quarantine::UserQuarantineList>>,
    user_quota: Option<Arc<crate::user_quota::PerUserQuotaTracker>>,
    tls_cert_watcher: Option<Arc<crate::tls_watcher::CertFileWatcher>>,
    live_blocks: Vec<Arc<LiveMetricsBlock>>,
) {
    let mut req = [0u8; 2048];
    let _ = match stream.read(&mut req).await {
        Ok(n) => n,
        Err(_) => return,
    };
    let head = std::str::from_utf8(&req).unwrap_or("");
    // Render the live blocks once per request and concatenate
    // them into a single string for handoff to the existing
    // render_full_v11. Since the live blocks need to appear
    // BOTH in /metrics and /diagnose, we pass them through the
    // config_presence concat point — but only when actually
    // serving those paths. We can't always append because that
    // would corrupt /healthz / /readyz / /diagnose-summary
    // responses. The cheap path: concatenate live blocks to
    // config_presence ONCE for this request.
    let merged_presence: Option<Arc<String>> = if live_blocks.is_empty() {
        config_presence.clone()
    } else {
        let mut buf = String::with_capacity(2048);
        if let Some(cp) = config_presence.as_deref() {
            buf.push_str(cp);
        }
        for block in &live_blocks {
            buf.push_str(&block());
        }
        Some(Arc::new(buf))
    };
    let (status_line, content_type, body) = render_full_v11(
        head,
        &metrics,
        auth.as_ref(),
        probe_anomaly.as_deref(),
        auto_deny.as_deref(),
        tls_acceptor.as_ref(),
        merged_presence.as_deref().map(String::as_str),
        process_info.as_deref(),
        per_user.as_deref(),
        per_user_conn_limiter.as_deref(),
        abuse_fires.as_deref(),
        user_quarantine.as_deref(),
        user_quota.as_deref(),
        tls_cert_watcher.as_deref(),
    );
    let response = format!(
        "{status_line}\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\r\n\
         {body}",
        body.len()
    );
    if let Err(e) = stream.write_all(response.as_bytes()).await {
        warn!(error = %e, "metrics write failed");
    }
    let _ = stream.shutdown().await;
}

/// Match a request line against an exact path, accounting for both
/// `GET /foo ` (trailing space before HTTP version) and
/// `GET /foo?...` (query string). Rejects substring paths like
/// `/foozleak`.
fn matches_path(request_head: &str, path: &str) -> bool {
    let with_space = format!("GET {path} ");
    let with_query = format!("GET {path}?");
    request_head.starts_with(&with_space) || request_head.starts_with(&with_query)
}

/// Severity classification for a [`DiagnoseFinding`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnoseSeverity {
    /// Sanity check passed; included so operators see the green
    /// signals alongside the warnings.
    Info,
    /// Probably operator-actionable but not currently breaking
    /// traffic (e.g. "cert renews in 8 days — within
    /// auto-renew window").
    Warn,
    /// Currently degrading or about to break traffic. Operator
    /// should act now (e.g. cert expired, SIGHUP partially
    /// failed, system-resolver bootstrap used in a deployment
    /// that should be all-pinned).
    Critical,
}

impl DiagnoseSeverity {
    fn label(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Critical => "CRIT",
        }
    }
}

/// One self-check result emitted by [`render_diagnose`].
/// Operator-readable; the renderer prints them at the top of
/// `/diagnose` output as a quick triage section.
#[derive(Debug, Clone)]
pub struct DiagnoseFinding {
    pub severity: DiagnoseSeverity,
    pub rule: &'static str,
    pub message: String,
}

/// Render the `/diagnose` body. Combines:
///   1. A `FINDINGS` section at the top — rule-based self-check
///      that surfaces the operator-actionable issues (cert near
///      expiry, silent SIGHUP failures, etc.).
///   2. The full `/metrics` body so a single curl-paste-share
///      gives the recipient everything they need without asking
///      the operator to run a second command.
///
/// Operator workflow:
///   curl -s :9090/diagnose > diagnose.txt
///   # check the FINDINGS section, share the file if filing a bug
///
/// `auth` is enforced by the caller (we don't see it here); the
/// caller already gated the request.
#[must_use]
pub fn render_diagnose(
    metrics: &ServerMetrics,
    probe_anomaly: Option<&crate::probe_anomaly::ProbeAnomalyDetector>,
    auto_deny: Option<&crate::auto_deny::AutoDenyList>,
    tls_acceptor: Option<&crate::tls::ReloadableAcceptor>,
    config_presence: Option<&str>,
    process_info: Option<&crate::process_info::ProcessInfo>,
) -> String {
    // Back-compat shim — forwards to v2 with no abuse_fires.
    render_diagnose_v2(
        metrics,
        probe_anomaly,
        auto_deny,
        tls_acceptor,
        config_presence,
        process_info,
        None,
    )
}

/// v2 of [`render_diagnose`] — adds the recent-abuse-fires table.
/// Back-compat shim — forwards to v3 with `user_quarantine = None`.
#[must_use]
pub fn render_diagnose_v2(
    metrics: &ServerMetrics,
    probe_anomaly: Option<&crate::probe_anomaly::ProbeAnomalyDetector>,
    auto_deny: Option<&crate::auto_deny::AutoDenyList>,
    tls_acceptor: Option<&crate::tls::ReloadableAcceptor>,
    config_presence: Option<&str>,
    process_info: Option<&crate::process_info::ProcessInfo>,
    abuse_fires: Option<&crate::abuse_fires::AbuseFireBuffer>,
) -> String {
    render_diagnose_v3(
        metrics,
        probe_anomaly,
        auto_deny,
        tls_acceptor,
        config_presence,
        process_info,
        abuse_fires,
        None,
    )
}

/// v3 of [`render_diagnose`] — adds the USER QUARANTINE table.
/// Back-compat shim — forwards to v4 with `user_quota = None`.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn render_diagnose_v3(
    metrics: &ServerMetrics,
    probe_anomaly: Option<&crate::probe_anomaly::ProbeAnomalyDetector>,
    auto_deny: Option<&crate::auto_deny::AutoDenyList>,
    tls_acceptor: Option<&crate::tls::ReloadableAcceptor>,
    config_presence: Option<&str>,
    process_info: Option<&crate::process_info::ProcessInfo>,
    abuse_fires: Option<&crate::abuse_fires::AbuseFireBuffer>,
    user_quarantine: Option<&crate::user_quarantine::UserQuarantineList>,
) -> String {
    render_diagnose_v4(
        metrics,
        probe_anomaly,
        auto_deny,
        tls_acceptor,
        config_presence,
        process_info,
        abuse_fires,
        user_quarantine,
        None,
    )
}

/// v4 of [`render_diagnose`] — adds the USER QUOTA table when a
/// `PerUserQuotaTracker` is supplied. Renders after the
/// quarantine table; together they show the operator the full
/// per-user enforcement state in the diagnose body.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn render_diagnose_v4(
    metrics: &ServerMetrics,
    probe_anomaly: Option<&crate::probe_anomaly::ProbeAnomalyDetector>,
    auto_deny: Option<&crate::auto_deny::AutoDenyList>,
    tls_acceptor: Option<&crate::tls::ReloadableAcceptor>,
    config_presence: Option<&str>,
    process_info: Option<&crate::process_info::ProcessInfo>,
    abuse_fires: Option<&crate::abuse_fires::AbuseFireBuffer>,
    user_quarantine: Option<&crate::user_quarantine::UserQuarantineList>,
    user_quota: Option<&crate::user_quota::PerUserQuotaTracker>,
) -> String {
    let findings = run_diagnose_rules(metrics, tls_acceptor, process_info);
    let mut s = String::with_capacity(4096);
    s.push_str("Proteus diagnose — operator self-check + metrics dump\n");
    s.push_str("=====================================================\n\n");

    s.push_str("FINDINGS\n");
    s.push_str("--------\n");
    if findings.is_empty() {
        s.push_str("  (no rules tripped)\n");
    } else {
        for f in &findings {
            // Format: `[CRIT] cert_expiry: cert expires in 3 days`
            s.push_str("  [");
            s.push_str(f.severity.label());
            s.push_str("] ");
            s.push_str(f.rule);
            s.push_str(": ");
            s.push_str(&f.message);
            s.push('\n');
        }
    }
    s.push('\n');

    // Recent abuse fires — only when wired. Operators see WHO
    // fired (user_id + kind + seconds_ago + magnitude) without
    // grepping journald, which is the actionable signal the
    // aggregate counters don't give.
    if let Some(af) = abuse_fires {
        let now_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        s.push_str(&af.diagnose_table(now_epoch));
        s.push('\n');
    }
    // User quarantine table — currently-banned user_ids + how
    // long until each entry expires. Operators reading the
    // diagnose body top-down see "abuse fired (recent fires
    // table) → user_id was auto-banned (this table)" as one
    // narrative.
    if let Some(uq) = user_quarantine {
        let now_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        s.push_str(&uq.diagnose_table(now_epoch));
        s.push('\n');
    }
    // User quota table — heaviest bandwidth-burners + their
    // per-period caps. Operators see "alice has consumed 99 GB
    // of her 100 GB monthly cap" + "bob is over 50 GB cap →
    // his admission is being rejected".
    if let Some(qt) = user_quota {
        let now_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        s.push_str(&qt.diagnose_table(now_epoch));
        s.push('\n');
    }

    s.push_str("METRICS (text/plain; version=0.0.4)\n");
    s.push_str("-----------------------------------\n");
    let now = std::time::Instant::now();
    s.push_str(&metrics.prometheus());
    if let Some(det) = probe_anomaly {
        s.push_str(&det.prometheus_extension(now));
    }
    if let Some(ad) = auto_deny {
        s.push_str(&ad.prometheus_extension(now));
    }
    if let Some(ra) = tls_acceptor {
        s.push_str(&ra.prometheus_extension());
    }
    if let Some(cp) = config_presence {
        s.push_str(cp);
    }
    if let Some(pi) = process_info {
        s.push_str(&pi.prometheus());
        let res = crate::process_resources::ProcessResources::capture();
        if !res.is_empty() {
            s.push_str(&res.prometheus_with_prefix("proteus"));
        }
    }
    if let Some(af) = abuse_fires {
        s.push_str(&af.prometheus());
    }
    if let Some(uq) = user_quarantine {
        s.push_str(&uq.prometheus());
    }
    if let Some(qt) = user_quota {
        s.push_str(&qt.prometheus());
    }
    s
}

/// Pure rule evaluator — separated from the renderer so tests
/// can exercise individual rules without parsing rendered text.
///
/// Current rules (severity ordering is reported, not enforced):
///   - Cert TTL: CRIT if < 1d, WARN if < 14d, INFO if > 14d.
///   - TLS reload: CRIT if `attempts > succeeded` (silent SIGHUP
///     failure on the cert path — operator's certbot deploy hook
///     fired but Proteus didn't pick it up).
///   - Process up: INFO when alive=true; CRIT when alive=false.
///   - SOCKS5 readiness: INFO when ready=true; WARN when
///     ready=false (draining or warming up).
///
/// More rules land as production deployments surface specific
/// failure modes — the harness is the pattern, not the rule
/// list.
#[must_use]
pub fn run_diagnose_rules(
    metrics: &ServerMetrics,
    tls_acceptor: Option<&crate::tls::ReloadableAcceptor>,
    _process_info: Option<&crate::process_info::ProcessInfo>,
) -> Vec<DiagnoseFinding> {
    let mut out = Vec::new();

    // Process up / readiness — every diagnose run reports these
    // even when fine, so the operator sees green signals.
    let alive = metrics.alive.load(Ordering::Relaxed);
    out.push(DiagnoseFinding {
        severity: if alive {
            DiagnoseSeverity::Info
        } else {
            DiagnoseSeverity::Critical
        },
        rule: "process_alive",
        message: if alive {
            "process alive".to_string()
        } else {
            "process NOT alive — accept loop has not bound the listener yet".to_string()
        },
    });
    let ready = metrics.ready.load(Ordering::Relaxed);
    out.push(DiagnoseFinding {
        severity: if ready {
            DiagnoseSeverity::Info
        } else {
            DiagnoseSeverity::Warn
        },
        rule: "process_ready",
        message: if ready {
            "process ready — accepting new traffic".to_string()
        } else {
            "process NOT ready — either still warming up OR draining for SIGTERM".to_string()
        },
    });

    // TLS cert TTL + reload silent-failure.
    if let Some(ra) = tls_acceptor {
        if let Some(not_after) = ra.leaf_not_after() {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let secs_until = not_after - now;
            let days = secs_until / 86_400;
            let severity = if days < 1 {
                // `days < 1` covers both `secs_until <= 0`
                // (already expired) AND `0 < secs_until < 24h`
                // (about to expire) — collapsed because they're
                // both Critical with different render strings.
                DiagnoseSeverity::Critical
            } else if days < 14 {
                DiagnoseSeverity::Warn
            } else {
                DiagnoseSeverity::Info
            };
            let msg = if secs_until <= 0 {
                format!("cert EXPIRED {} days ago", -days)
            } else if days < 1 {
                "cert expires in < 24 hours — RENEW NOW".to_string()
            } else {
                format!("cert expires in {days} days")
            };
            out.push(DiagnoseFinding {
                severity,
                rule: "tls_cert_ttl",
                message: msg,
            });
        }
        let attempts = ra.reload_attempts();
        let succeeded = ra.reload_succeeded();
        if attempts > 0 {
            let missing = attempts.saturating_sub(succeeded);
            let severity = if missing == 0 {
                DiagnoseSeverity::Info
            } else {
                DiagnoseSeverity::Critical
            };
            let msg = if missing == 0 {
                format!("TLS reload: {attempts} attempts, all succeeded")
            } else {
                format!(
                    "TLS reload: {attempts} attempts, {succeeded} succeeded, {missing} silent failures — check journalctl"
                )
            };
            out.push(DiagnoseFinding {
                severity,
                rule: "tls_reload_silent_failure",
                message: msg,
            });
        }
    }

    // Reload counters for the 4 non-TLS sections — same
    // silent-failure rule but on the ServerMetrics atomics.
    for (rule_name, att, suc) in [
        (
            "firewall_reload_silent_failure",
            metrics.firewall_reload_attempts.load(Ordering::Relaxed),
            metrics.firewall_reload_succeeded.load(Ordering::Relaxed),
        ),
        (
            "rate_limit_reload_silent_failure",
            metrics.rate_limit_reload_attempts.load(Ordering::Relaxed),
            metrics.rate_limit_reload_succeeded.load(Ordering::Relaxed),
        ),
        (
            "user_rate_limit_reload_silent_failure",
            metrics
                .user_rate_limit_reload_attempts
                .load(Ordering::Relaxed),
            metrics
                .user_rate_limit_reload_succeeded
                .load(Ordering::Relaxed),
        ),
        (
            "handshake_budget_reload_silent_failure",
            metrics
                .handshake_budget_reload_attempts
                .load(Ordering::Relaxed),
            metrics
                .handshake_budget_reload_succeeded
                .load(Ordering::Relaxed),
        ),
    ] {
        if att == 0 {
            continue;
        }
        let missing = att.saturating_sub(suc);
        if missing > 0 {
            out.push(DiagnoseFinding {
                severity: DiagnoseSeverity::Warn,
                rule: rule_name,
                message: format!(
                    "{att} reload attempts, {suc} succeeded, {missing} missing — section may not be installed in config OR no limiter was installed at startup"
                ),
            });
        }
    }

    out
}

/// Extract the value of an `Authorization:` header from a raw HTTP
/// request head. Returns `None` if no such header exists. Case-
/// insensitive on the header name (HTTP/1.1 § 3.2 says field names
/// are case-insensitive).
fn extract_authorization(request_head: &str) -> Option<&str> {
    for line in request_head.split("\r\n") {
        let (name, value) = match line.split_once(':') {
            Some(kv) => kv,
            None => continue,
        };
        if name.eq_ignore_ascii_case("Authorization") {
            return Some(value.trim_start());
        }
    }
    None
}

/// Pure routing: given the request head and the metrics, return
/// `(status_line, content_type, body)`. Public so it can be unit-tested
/// without spinning up a TCP listener.
#[must_use]
pub fn render(
    request_head: &str,
    metrics: &ServerMetrics,
    auth: Option<&MetricsAuth>,
) -> (&'static str, &'static str, String) {
    render_full(request_head, metrics, auth, None)
}

/// Full-featured variant of [`render`] — back-compat shim that
/// forwards to [`render_full_v2`] with `auto_deny = None`.
#[must_use]
pub fn render_full(
    request_head: &str,
    metrics: &ServerMetrics,
    auth: Option<&MetricsAuth>,
    probe_anomaly: Option<&crate::probe_anomaly::ProbeAnomalyDetector>,
) -> (&'static str, &'static str, String) {
    render_full_v2(request_head, metrics, auth, probe_anomaly, None)
}

/// v2 of [`render_full`] — adds an optional `AutoDenyList` reference.
/// When supplied, the `/metrics` body includes the deny list's
/// four diagnostic series (`active_prefixes`, `inserted_total`,
/// `refused_inserts_total`, per-prefix `remaining_secs`). Operators
/// see WHO is currently blocked AND for how much longer, directly
/// in Prometheus / Grafana. Back-compat shim — forwards to
/// [`render_full_v3`] with `tls_acceptor = None`.
#[must_use]
pub fn render_full_v2(
    request_head: &str,
    metrics: &ServerMetrics,
    auth: Option<&MetricsAuth>,
    probe_anomaly: Option<&crate::probe_anomaly::ProbeAnomalyDetector>,
    auto_deny: Option<&crate::auto_deny::AutoDenyList>,
) -> (&'static str, &'static str, String) {
    render_full_v3(request_head, metrics, auth, probe_anomaly, auto_deny, None)
}

/// v3 of [`render_full`] — adds an optional `ReloadableAcceptor` for
/// TLS cert-expiry + SIGHUP reload-counter observability. When
/// supplied, the `/metrics` body includes
/// `proteus_tls_cert_not_after_unix_seconds` (gauge) and
/// `proteus_tls_reload_attempts_total` / `_succeeded_total`
/// (counters).
#[must_use]
pub fn render_full_v3(
    request_head: &str,
    metrics: &ServerMetrics,
    auth: Option<&MetricsAuth>,
    probe_anomaly: Option<&crate::probe_anomaly::ProbeAnomalyDetector>,
    auto_deny: Option<&crate::auto_deny::AutoDenyList>,
    tls_acceptor: Option<&crate::tls::ReloadableAcceptor>,
) -> (&'static str, &'static str, String) {
    render_full_v4(
        request_head,
        metrics,
        auth,
        probe_anomaly,
        auto_deny,
        tls_acceptor,
        None,
    )
}

/// v4 of [`render_full`] — adds an optional `config_presence` block
/// emitted verbatim into the `/metrics` body AFTER the existing
/// extensions. Back-compat shim — forwards to [`render_full_v5`]
/// with `process_info = None`.
#[must_use]
pub fn render_full_v4(
    request_head: &str,
    metrics: &ServerMetrics,
    auth: Option<&MetricsAuth>,
    probe_anomaly: Option<&crate::probe_anomaly::ProbeAnomalyDetector>,
    auto_deny: Option<&crate::auto_deny::AutoDenyList>,
    tls_acceptor: Option<&crate::tls::ReloadableAcceptor>,
    config_presence: Option<&str>,
) -> (&'static str, &'static str, String) {
    render_full_v5(
        request_head,
        metrics,
        auth,
        probe_anomaly,
        auto_deny,
        tls_acceptor,
        config_presence,
        None,
    )
}

/// v5 of [`render_full`] — adds optional process-lifecycle gauges
/// (`proteus_process_start_unix_seconds`, `_uptime_seconds`,
/// `proteus_build_info`). Back-compat shim — forwards to v6 with
/// `per_user = None`.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn render_full_v5(
    request_head: &str,
    metrics: &ServerMetrics,
    auth: Option<&MetricsAuth>,
    probe_anomaly: Option<&crate::probe_anomaly::ProbeAnomalyDetector>,
    auto_deny: Option<&crate::auto_deny::AutoDenyList>,
    tls_acceptor: Option<&crate::tls::ReloadableAcceptor>,
    config_presence: Option<&str>,
    process_info: Option<&crate::process_info::ProcessInfo>,
) -> (&'static str, &'static str, String) {
    render_full_v6(
        request_head,
        metrics,
        auth,
        probe_anomaly,
        auto_deny,
        tls_acceptor,
        config_presence,
        process_info,
        None,
    )
}

/// v6 of [`render_full`] — adds optional per-user bandwidth
/// accumulator. When supplied, the `/metrics` body includes the
/// `proteus_per_user_bytes_{sent,received}_total{user_id="…"}`
/// series. See [`serve_with_auth_full_v6`] for the operator
/// rationale.
///
/// Back-compat shim — forwards to v7 with no conn-limiter.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn render_full_v6(
    request_head: &str,
    metrics: &ServerMetrics,
    auth: Option<&MetricsAuth>,
    probe_anomaly: Option<&crate::probe_anomaly::ProbeAnomalyDetector>,
    auto_deny: Option<&crate::auto_deny::AutoDenyList>,
    tls_acceptor: Option<&crate::tls::ReloadableAcceptor>,
    config_presence: Option<&str>,
    process_info: Option<&crate::process_info::ProcessInfo>,
    per_user: Option<&crate::per_user_bandwidth::PerUserBandwidth>,
) -> (&'static str, &'static str, String) {
    render_full_v7(
        request_head,
        metrics,
        auth,
        probe_anomaly,
        auto_deny,
        tls_acceptor,
        config_presence,
        process_info,
        per_user,
        None,
    )
}

/// v7 of [`render_full`] — adds optional per-user
/// concurrent-session limiter. Back-compat shim — forwards to v8
/// with `abuse_fires = None`.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn render_full_v7(
    request_head: &str,
    metrics: &ServerMetrics,
    auth: Option<&MetricsAuth>,
    probe_anomaly: Option<&crate::probe_anomaly::ProbeAnomalyDetector>,
    auto_deny: Option<&crate::auto_deny::AutoDenyList>,
    tls_acceptor: Option<&crate::tls::ReloadableAcceptor>,
    config_presence: Option<&str>,
    process_info: Option<&crate::process_info::ProcessInfo>,
    per_user: Option<&crate::per_user_bandwidth::PerUserBandwidth>,
    per_user_conn_limiter: Option<&crate::per_user_conn_limit::PerUserConnLimiter>,
) -> (&'static str, &'static str, String) {
    render_full_v8(
        request_head,
        metrics,
        auth,
        probe_anomaly,
        auto_deny,
        tls_acceptor,
        config_presence,
        process_info,
        per_user,
        per_user_conn_limiter,
        None,
    )
}

/// v8 of [`render_full`] — back-compat shim. Forwards to v9 with
/// `user_quarantine = None`.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn render_full_v8(
    request_head: &str,
    metrics: &ServerMetrics,
    auth: Option<&MetricsAuth>,
    probe_anomaly: Option<&crate::probe_anomaly::ProbeAnomalyDetector>,
    auto_deny: Option<&crate::auto_deny::AutoDenyList>,
    tls_acceptor: Option<&crate::tls::ReloadableAcceptor>,
    config_presence: Option<&str>,
    process_info: Option<&crate::process_info::ProcessInfo>,
    per_user: Option<&crate::per_user_bandwidth::PerUserBandwidth>,
    per_user_conn_limiter: Option<&crate::per_user_conn_limit::PerUserConnLimiter>,
    abuse_fires: Option<&crate::abuse_fires::AbuseFireBuffer>,
) -> (&'static str, &'static str, String) {
    render_full_v9(
        request_head,
        metrics,
        auth,
        probe_anomaly,
        auto_deny,
        tls_acceptor,
        config_presence,
        process_info,
        per_user,
        per_user_conn_limiter,
        abuse_fires,
        None,
    )
}

/// v9 of [`render_full`] — back-compat shim to v10 with
/// `user_quota = None`.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn render_full_v9(
    request_head: &str,
    metrics: &ServerMetrics,
    auth: Option<&MetricsAuth>,
    probe_anomaly: Option<&crate::probe_anomaly::ProbeAnomalyDetector>,
    auto_deny: Option<&crate::auto_deny::AutoDenyList>,
    tls_acceptor: Option<&crate::tls::ReloadableAcceptor>,
    config_presence: Option<&str>,
    process_info: Option<&crate::process_info::ProcessInfo>,
    per_user: Option<&crate::per_user_bandwidth::PerUserBandwidth>,
    per_user_conn_limiter: Option<&crate::per_user_conn_limit::PerUserConnLimiter>,
    abuse_fires: Option<&crate::abuse_fires::AbuseFireBuffer>,
    user_quarantine: Option<&crate::user_quarantine::UserQuarantineList>,
) -> (&'static str, &'static str, String) {
    render_full_v10(
        request_head,
        metrics,
        auth,
        probe_anomaly,
        auto_deny,
        tls_acceptor,
        config_presence,
        process_info,
        per_user,
        per_user_conn_limiter,
        abuse_fires,
        user_quarantine,
        None,
    )
}

/// v10 of [`render_full`] — back-compat shim to v11 with
/// `tls_cert_watcher = None`.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn render_full_v10(
    request_head: &str,
    metrics: &ServerMetrics,
    auth: Option<&MetricsAuth>,
    probe_anomaly: Option<&crate::probe_anomaly::ProbeAnomalyDetector>,
    auto_deny: Option<&crate::auto_deny::AutoDenyList>,
    tls_acceptor: Option<&crate::tls::ReloadableAcceptor>,
    config_presence: Option<&str>,
    process_info: Option<&crate::process_info::ProcessInfo>,
    per_user: Option<&crate::per_user_bandwidth::PerUserBandwidth>,
    per_user_conn_limiter: Option<&crate::per_user_conn_limit::PerUserConnLimiter>,
    abuse_fires: Option<&crate::abuse_fires::AbuseFireBuffer>,
    user_quarantine: Option<&crate::user_quarantine::UserQuarantineList>,
    user_quota: Option<&crate::user_quota::PerUserQuotaTracker>,
) -> (&'static str, &'static str, String) {
    render_full_v11(
        request_head,
        metrics,
        auth,
        probe_anomaly,
        auto_deny,
        tls_acceptor,
        config_presence,
        process_info,
        per_user,
        per_user_conn_limiter,
        abuse_fires,
        user_quarantine,
        user_quota,
        None,
    )
}

/// v11 of [`render_full`] — adds optional `CertFileWatcher`.
/// When supplied, `/metrics` includes the four
/// `proteus_tls_cert_watcher_*` counters.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn render_full_v11(
    request_head: &str,
    metrics: &ServerMetrics,
    auth: Option<&MetricsAuth>,
    probe_anomaly: Option<&crate::probe_anomaly::ProbeAnomalyDetector>,
    auto_deny: Option<&crate::auto_deny::AutoDenyList>,
    tls_acceptor: Option<&crate::tls::ReloadableAcceptor>,
    config_presence: Option<&str>,
    process_info: Option<&crate::process_info::ProcessInfo>,
    per_user: Option<&crate::per_user_bandwidth::PerUserBandwidth>,
    per_user_conn_limiter: Option<&crate::per_user_conn_limit::PerUserConnLimiter>,
    abuse_fires: Option<&crate::abuse_fires::AbuseFireBuffer>,
    user_quarantine: Option<&crate::user_quarantine::UserQuarantineList>,
    user_quota: Option<&crate::user_quota::PerUserQuotaTracker>,
    tls_cert_watcher: Option<&crate::tls_watcher::CertFileWatcher>,
) -> (&'static str, &'static str, String) {
    if matches_path(request_head, "/metrics") {
        // Bearer-token gate when configured.
        if let Some(expected) = auth {
            let presented = extract_authorization(request_head);
            let ok = presented.is_some_and(|p| expected.matches(p));
            if !ok {
                return (
                    "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer realm=\"proteus-metrics\"\r\n",
                    "text/plain",
                    "unauthorized\n".to_string(),
                );
            }
        }
        let now = std::time::Instant::now();
        let mut body = metrics.prometheus();
        if let Some(det) = probe_anomaly {
            body.push_str(&det.prometheus_extension(now));
        }
        if let Some(ad) = auto_deny {
            body.push_str(&ad.prometheus_extension(now));
        }
        if let Some(ra) = tls_acceptor {
            body.push_str(&ra.prometheus_extension());
        }
        if let Some(cp) = config_presence {
            body.push_str(cp);
        }
        if let Some(pi) = process_info {
            body.push_str(&pi.prometheus());
            // Process-resource gauges (open FDs + RSS) are coupled
            // to process_info: both convey "this process right now".
            // Captured live per scrape — operators watching a soak
            // run see FD growth in real time, and PromQL alerts on
            // `deriv(proteus_process_open_fds[1h]) > 0` catch leaks
            // in production. Linux-only; empty on macOS / Windows.
            let res = crate::process_resources::ProcessResources::capture();
            if !res.is_empty() {
                body.push_str(&res.prometheus_with_prefix("proteus"));
            }
        }
        if let Some(pu) = per_user {
            body.push_str(&pu.prometheus());
        }
        if let Some(cl) = per_user_conn_limiter {
            body.push_str(&cl.prometheus());
        }
        if let Some(af) = abuse_fires {
            body.push_str(&af.prometheus());
        }
        if let Some(uq) = user_quarantine {
            body.push_str(&uq.prometheus());
        }
        if let Some(qt) = user_quota {
            body.push_str(&qt.prometheus());
        }
        if let Some(w) = tls_cert_watcher {
            body.push_str(&w.prometheus());
        }
        ("HTTP/1.1 200 OK\r\n", "text/plain; version=0.0.4", body)
    } else if matches_path(request_head, "/healthz") {
        // /healthz now consults three gates:
        //   1. `alive` — accept loop bound the listener (set once
        //      at startup, flipped to false during graceful drain).
        //   2. `last_periodic_self_test_passed` — most recent
        //      background self-test outcome (true by default; set
        //      false by the periodic task on a failed cycle).
        //   3. Staleness — if the periodic interval is configured
        //      (>0) AND the last successful test is more than
        //      3× interval ago, treat as failed even if the gauge
        //      still says true. Catches a hung self-test task /
        //      tokio runtime deadlock that prevents the periodic
        //      task from running at all.
        //
        // Operators load-balancing in front of Proteus alert on
        // a healthz=503 to immediately route around a degraded
        // instance instead of waiting for real users to hit the
        // failure.
        let alive = metrics.alive.load(Ordering::Relaxed);
        let periodic_passed = metrics
            .last_periodic_self_test_passed
            .load(Ordering::Relaxed);
        let interval_secs = metrics
            .periodic_self_test_interval_secs
            .load(Ordering::Relaxed);
        let stale = if interval_secs > 0 {
            let last_pass = metrics
                .last_periodic_self_test_unix_seconds
                .load(Ordering::Relaxed);
            if last_pass == 0 {
                // Never ran successfully yet. NOT stale-failed
                // immediately — give the periodic task the first
                // window-length to produce a result. Operators see
                // the gauge at 0 + alive=true and know the
                // periodic task is initializing.
                false
            } else {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                now.saturating_sub(last_pass) > interval_secs.saturating_mul(3)
            }
        } else {
            false
        };
        if alive && periodic_passed && !stale {
            ("HTTP/1.1 200 OK\r\n", "text/plain", "alive\n".to_string())
        } else if !alive {
            (
                "HTTP/1.1 503 Service Unavailable\r\n",
                "text/plain",
                "dead\n".to_string(),
            )
        } else if !periodic_passed {
            (
                "HTTP/1.1 503 Service Unavailable\r\n",
                "text/plain",
                "self_test_failed\n".to_string(),
            )
        } else {
            (
                "HTTP/1.1 503 Service Unavailable\r\n",
                "text/plain",
                "self_test_stale\n".to_string(),
            )
        }
    } else if matches_path(request_head, "/diagnose") {
        // Bearer-token gate (same rule as /metrics — /diagnose
        // exposes operator-sensitive info like prefix lists and
        // cert TTLs).
        if let Some(expected) = auth {
            let presented = extract_authorization(request_head);
            let ok = presented.is_some_and(|p| expected.matches(p));
            if !ok {
                return (
                    "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer realm=\"proteus-metrics\"\r\n",
                    "text/plain",
                    "unauthorized\n".to_string(),
                );
            }
        }
        let mut body = render_diagnose_v4(
            metrics,
            probe_anomaly,
            auto_deny,
            tls_acceptor,
            config_presence,
            process_info,
            abuse_fires,
            user_quarantine,
            user_quota,
        );
        // Append TLS cert watcher counters when wired —
        // operators reading /diagnose see the auto-reload
        // health alongside the SIGHUP-reload counters
        // (`proteus_tls_reload_*`).
        if let Some(w) = tls_cert_watcher {
            body.push_str(&w.prometheus());
        }
        ("HTTP/1.1 200 OK\r\n", "text/plain; charset=utf-8", body)
    } else if matches_path(request_head, "/readyz") {
        if metrics.ready.load(Ordering::Relaxed) {
            ("HTTP/1.1 200 OK\r\n", "text/plain", "ready\n".to_string())
        } else {
            (
                "HTTP/1.1 503 Service Unavailable\r\n",
                "text/plain",
                "draining\n".to_string(),
            )
        }
    } else {
        (
            "HTTP/1.1 404 Not Found\r\n",
            "text/plain",
            "not found\n".to_string(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;
    use tokio::net::TcpStream;
    use tokio::time::{timeout, Duration};

    #[test]
    fn render_200_on_get_metrics_with_trailing_space() {
        let m = ServerMetrics::default();
        m.sessions_accepted.fetch_add(7, Ordering::Relaxed);
        let (status, ctype, body) = render("GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n", &m, None);
        assert!(status.starts_with("HTTP/1.1 200"));
        assert!(ctype.starts_with("text/plain; version=0.0.4"));
        assert!(body.contains("proteus_sessions_accepted_total 7"));
    }

    #[test]
    fn render_200_on_get_metrics_with_query_string() {
        let m = ServerMetrics::default();
        let (status, _ctype, body) = render("GET /metrics?debug=1 HTTP/1.1\r\n\r\n", &m, None);
        assert!(status.starts_with("HTTP/1.1 200"));
        assert!(body.contains("# HELP proteus_sessions_accepted_total"));
    }

    #[test]
    fn render_404_on_root() {
        let m = ServerMetrics::default();
        let (status, _ctype, body) = render("GET / HTTP/1.1\r\n\r\n", &m, None);
        assert_eq!(status, "HTTP/1.1 404 Not Found\r\n");
        assert_eq!(body, "not found\n");
    }

    #[test]
    fn render_404_on_post() {
        let m = ServerMetrics::default();
        let (status, _ctype, _body) = render("POST /metrics HTTP/1.1\r\n\r\n", &m, None);
        assert!(status.starts_with("HTTP/1.1 404"));
    }

    #[test]
    fn render_404_on_metrics_substring_path() {
        let m = ServerMetrics::default();
        // /metricsleak should NOT match /metrics — the trailing space
        // / query-string check is what enforces this.
        let (status, _ctype, _body) = render("GET /metricsleak HTTP/1.1\r\n\r\n", &m, None);
        assert!(status.starts_with("HTTP/1.1 404"));
    }

    #[test]
    fn healthz_503_when_not_alive() {
        let m = ServerMetrics::default();
        // Default: alive=false.
        let (status, ctype, body) = render("GET /healthz HTTP/1.1\r\n\r\n", &m, None);
        assert_eq!(status, "HTTP/1.1 503 Service Unavailable\r\n");
        assert_eq!(ctype, "text/plain");
        assert_eq!(body, "dead\n");
    }

    #[test]
    fn healthz_200_when_alive() {
        let m = ServerMetrics::default();
        m.alive.store(true, Ordering::Relaxed);
        let (status, _ctype, body) = render("GET /healthz HTTP/1.1\r\n\r\n", &m, None);
        assert!(status.starts_with("HTTP/1.1 200"));
        assert_eq!(body, "alive\n");
    }

    #[test]
    fn healthz_503_when_periodic_self_test_failed() {
        // alive=true, but the periodic self-test most recently
        // failed → /healthz 503 with `self_test_failed` body.
        let m = ServerMetrics::default();
        m.alive.store(true, Ordering::Relaxed);
        m.last_periodic_self_test_passed
            .store(false, Ordering::Relaxed);
        let (status, _ctype, body) = render("GET /healthz HTTP/1.1\r\n\r\n", &m, None);
        assert_eq!(status, "HTTP/1.1 503 Service Unavailable\r\n");
        assert_eq!(body, "self_test_failed\n");
    }

    #[test]
    fn healthz_503_when_periodic_self_test_stale() {
        // alive=true, last test passed but it was a LONG time ago
        // (well past 3× interval) → /healthz 503 with
        // `self_test_stale` body.
        let m = ServerMetrics::default();
        m.alive.store(true, Ordering::Relaxed);
        m.last_periodic_self_test_passed
            .store(true, Ordering::Relaxed);
        // Interval = 60s; last success = 2000s ago. 2000 > 180,
        // so the staleness rule should fire.
        m.periodic_self_test_interval_secs
            .store(60, Ordering::Relaxed);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        m.last_periodic_self_test_unix_seconds
            .store(now.saturating_sub(2000), Ordering::Relaxed);
        let (status, _ctype, body) = render("GET /healthz HTTP/1.1\r\n\r\n", &m, None);
        assert_eq!(status, "HTTP/1.1 503 Service Unavailable\r\n");
        assert_eq!(body, "self_test_stale\n");
    }

    #[test]
    fn healthz_200_when_periodic_interval_set_but_no_success_yet() {
        // Interval > 0 but last_periodic_self_test_unix_seconds=0
        // (the periodic task hasn't completed its first cycle).
        // We do NOT immediately 503; give the task the first
        // window-length to produce a result. Operators see the
        // gauge at 0 + alive=true and know the periodic task is
        // initializing.
        let m = ServerMetrics::default();
        m.alive.store(true, Ordering::Relaxed);
        m.periodic_self_test_interval_secs
            .store(60, Ordering::Relaxed);
        // last_periodic_self_test_passed defaults to true; OK.
        let (status, _ctype, body) = render("GET /healthz HTTP/1.1\r\n\r\n", &m, None);
        assert_eq!(status, "HTTP/1.1 200 OK\r\n");
        assert_eq!(body, "alive\n");
    }

    #[test]
    fn healthz_200_when_periodic_test_recent_and_fresh() {
        let m = ServerMetrics::default();
        m.alive.store(true, Ordering::Relaxed);
        m.last_periodic_self_test_passed
            .store(true, Ordering::Relaxed);
        m.periodic_self_test_interval_secs
            .store(60, Ordering::Relaxed);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // 10s ago — well within 3×60=180.
        m.last_periodic_self_test_unix_seconds
            .store(now.saturating_sub(10), Ordering::Relaxed);
        let (status, _ctype, body) = render("GET /healthz HTTP/1.1\r\n\r\n", &m, None);
        assert_eq!(status, "HTTP/1.1 200 OK\r\n");
        assert_eq!(body, "alive\n");
    }

    #[test]
    fn healthz_503_when_not_alive_takes_priority_over_self_test() {
        // alive=false → "dead\n" even if the self-test passed.
        // alive is the strongest signal.
        let m = ServerMetrics::default();
        m.alive.store(false, Ordering::Relaxed);
        m.last_periodic_self_test_passed
            .store(true, Ordering::Relaxed);
        let (status, _ctype, body) = render("GET /healthz HTTP/1.1\r\n\r\n", &m, None);
        assert_eq!(status, "HTTP/1.1 503 Service Unavailable\r\n");
        assert_eq!(body, "dead\n");
    }

    #[test]
    fn readyz_503_when_not_ready() {
        let m = ServerMetrics::default();
        m.alive.store(true, Ordering::Relaxed);
        // Default: ready=false (still warming up or draining).
        let (status, _ctype, body) = render("GET /readyz HTTP/1.1\r\n\r\n", &m, None);
        assert_eq!(status, "HTTP/1.1 503 Service Unavailable\r\n");
        assert_eq!(body, "draining\n");
    }

    #[test]
    fn readyz_200_when_ready() {
        let m = ServerMetrics::default();
        m.ready.store(true, Ordering::Relaxed);
        let (status, _ctype, body) = render("GET /readyz HTTP/1.1\r\n\r\n", &m, None);
        assert!(status.starts_with("HTTP/1.1 200"));
        assert_eq!(body, "ready\n");
    }

    #[test]
    fn readyz_with_query_string_also_matches() {
        let m = ServerMetrics::default();
        m.ready.store(true, Ordering::Relaxed);
        let (status, _ctype, _body) = render("GET /readyz?source=lb HTTP/1.1\r\n\r\n", &m, None);
        assert!(status.starts_with("HTTP/1.1 200"));
    }

    #[test]
    fn healthz_substring_rejected() {
        let m = ServerMetrics::default();
        m.alive.store(true, Ordering::Relaxed);
        // /healthznow shouldn't match /healthz.
        let (status, _ctype, _body) = render("GET /healthznow HTTP/1.1\r\n\r\n", &m, None);
        assert!(status.starts_with("HTTP/1.1 404"));
    }

    /// End-to-end: bind a listener on a free port, spawn the server,
    /// open a TCP client, send `GET /metrics`, verify the response
    /// contains the Prometheus exposition.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn end_to_end_scrape() {
        let metrics = Arc::new(ServerMetrics::default());
        metrics
            .handshakes_succeeded
            .fetch_add(42, Ordering::Relaxed);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_metrics = Arc::clone(&metrics);
        let server_task = tokio::spawn(serve_on_listener(listener, server_metrics));

        // Spin briefly so the accept loop is polled.
        tokio::task::yield_now().await;

        let mut sock = timeout(Duration::from_secs(5), TcpStream::connect(addr))
            .await
            .expect("connect timeout")
            .expect("connect ok");
        sock.write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        sock.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("Content-Type: text/plain"));
        assert!(response.contains("proteus_handshakes_succeeded_total 42"));

        server_task.abort();
    }

    /// End-to-end: a fresh server (alive=false, ready=false) should
    /// return 503 on both /healthz and /readyz; once flipped, 200.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn end_to_end_probes_flip_status() {
        let metrics = Arc::new(ServerMetrics::default());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_metrics = Arc::clone(&metrics);
        let server_task = tokio::spawn(serve_on_listener(listener, server_metrics));
        tokio::task::yield_now().await;

        async fn fetch(addr: std::net::SocketAddr, path: &str) -> String {
            let mut sock = timeout(Duration::from_secs(5), TcpStream::connect(addr))
                .await
                .expect("connect timeout")
                .expect("connect ok");
            sock.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
                .await
                .unwrap();
            let mut buf = Vec::new();
            sock.read_to_end(&mut buf).await.unwrap();
            String::from_utf8_lossy(&buf).to_string()
        }

        let r = fetch(addr, "/healthz").await;
        assert!(r.starts_with("HTTP/1.1 503"), "expected 503, got: {r}");

        metrics.alive.store(true, Ordering::Relaxed);
        let r = fetch(addr, "/healthz").await;
        assert!(r.starts_with("HTTP/1.1 200 OK"), "expected 200, got: {r}");

        let r = fetch(addr, "/readyz").await;
        assert!(r.starts_with("HTTP/1.1 503"), "expected 503, got: {r}");

        metrics.ready.store(true, Ordering::Relaxed);
        let r = fetch(addr, "/readyz").await;
        assert!(r.starts_with("HTTP/1.1 200 OK"), "expected 200, got: {r}");

        server_task.abort();
    }

    // ----- Bearer-token auth tests -----

    fn dummy_auth() -> MetricsAuth {
        MetricsAuth::new("s3cr3t-deadbeef-cafe-1234").unwrap()
    }

    #[test]
    fn metrics_auth_rejects_empty_token() {
        assert!(MetricsAuth::new("").is_none());
    }

    #[test]
    fn metrics_auth_matches_correct_token() {
        let a = dummy_auth();
        assert!(a.matches("Bearer s3cr3t-deadbeef-cafe-1234"));
    }

    #[test]
    fn metrics_auth_rejects_wrong_prefix() {
        let a = dummy_auth();
        assert!(!a.matches("Basic s3cr3t-deadbeef-cafe-1234"));
        assert!(!a.matches("Token s3cr3t-deadbeef-cafe-1234"));
        // Missing prefix.
        assert!(!a.matches("s3cr3t-deadbeef-cafe-1234"));
    }

    #[test]
    fn metrics_auth_rejects_wrong_token() {
        let a = dummy_auth();
        assert!(!a.matches("Bearer wrong-token-of-same-length-aa"));
        assert!(!a.matches("Bearer x"));
        assert!(!a.matches("Bearer "));
    }

    #[test]
    fn metrics_auth_strips_trailing_whitespace_and_crlf() {
        // HTTP header values can have trailing CR/LF when split off
        // mid-buffer. Accept them.
        let a = dummy_auth();
        assert!(a.matches("Bearer s3cr3t-deadbeef-cafe-1234\r\n"));
        assert!(a.matches("Bearer s3cr3t-deadbeef-cafe-1234 "));
    }

    #[test]
    fn extract_authorization_case_insensitive_header_name() {
        let head = "GET /metrics HTTP/1.1\r\nhost: x\r\nauthorization: Bearer foo\r\n\r\n";
        assert_eq!(extract_authorization(head), Some("Bearer foo"));
        let head = "GET /metrics HTTP/1.1\r\nAUTHORIZATION: Bearer foo\r\n\r\n";
        assert_eq!(extract_authorization(head), Some("Bearer foo"));
    }

    #[test]
    fn extract_authorization_missing_returns_none() {
        let head = "GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n";
        assert_eq!(extract_authorization(head), None);
    }

    #[test]
    fn render_401_when_auth_configured_and_no_header() {
        let m = ServerMetrics::default();
        let auth = dummy_auth();
        let (status, _ctype, body) = render("GET /metrics HTTP/1.1\r\n\r\n", &m, Some(&auth));
        assert!(status.starts_with("HTTP/1.1 401"));
        assert!(status.contains("WWW-Authenticate: Bearer"));
        assert_eq!(body, "unauthorized\n");
    }

    #[test]
    fn render_401_when_auth_configured_and_wrong_token() {
        let m = ServerMetrics::default();
        let auth = dummy_auth();
        let (status, _ctype, _body) = render(
            "GET /metrics HTTP/1.1\r\nAuthorization: Bearer nope\r\n\r\n",
            &m,
            Some(&auth),
        );
        assert!(status.starts_with("HTTP/1.1 401"));
    }

    #[test]
    fn render_200_when_auth_configured_and_correct_token() {
        let m = ServerMetrics::default();
        m.sessions_accepted.fetch_add(99, Ordering::Relaxed);
        let auth = dummy_auth();
        let (status, _ctype, body) = render(
            "GET /metrics HTTP/1.1\r\nAuthorization: Bearer s3cr3t-deadbeef-cafe-1234\r\n\r\n",
            &m,
            Some(&auth),
        );
        assert!(status.starts_with("HTTP/1.1 200"));
        assert!(body.contains("proteus_sessions_accepted_total 99"));
    }

    #[test]
    fn render_healthz_and_readyz_never_require_auth() {
        // /healthz + /readyz must respond without auth even when the
        // gate is configured — orchestrator probes don't carry tokens.
        let m = ServerMetrics::default();
        m.alive.store(true, Ordering::Relaxed);
        m.ready.store(true, Ordering::Relaxed);
        let auth = dummy_auth();
        let (s, _, _) = render("GET /healthz HTTP/1.1\r\n\r\n", &m, Some(&auth));
        assert!(s.starts_with("HTTP/1.1 200"));
        let (s, _, _) = render("GET /readyz HTTP/1.1\r\n\r\n", &m, Some(&auth));
        assert!(s.starts_with("HTTP/1.1 200"));
    }

    /// End-to-end: bind a listener, configure auth, verify that a
    /// scrape without `Authorization` gets 401, while one with the
    /// correct bearer gets 200 + exposition.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn end_to_end_auth_gate() {
        let metrics = Arc::new(ServerMetrics::default());
        metrics.handshakes_succeeded.fetch_add(7, Ordering::Relaxed);
        let auth = MetricsAuth::new("integration-test-token-fffffff");

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(serve_on_listener_with_auth(
            listener,
            Arc::clone(&metrics),
            auth,
        ));
        tokio::task::yield_now().await;

        async fn fetch(addr: std::net::SocketAddr, raw: &str) -> String {
            let mut sock = timeout(Duration::from_secs(5), TcpStream::connect(addr))
                .await
                .unwrap()
                .unwrap();
            sock.write_all(raw.as_bytes()).await.unwrap();
            let mut buf = Vec::new();
            sock.read_to_end(&mut buf).await.unwrap();
            String::from_utf8_lossy(&buf).to_string()
        }

        // No auth header → 401.
        let r = fetch(addr, "GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(r.starts_with("HTTP/1.1 401"), "expected 401, got:\n{r}");
        assert!(r.contains("WWW-Authenticate: Bearer"));

        // Wrong token → 401.
        let r = fetch(
            addr,
            "GET /metrics HTTP/1.1\r\nAuthorization: Bearer wrong\r\n\r\n",
        )
        .await;
        assert!(r.starts_with("HTTP/1.1 401"), "expected 401, got:\n{r}");

        // Correct token → 200 + body.
        let r = fetch(
            addr,
            "GET /metrics HTTP/1.1\r\nAuthorization: Bearer integration-test-token-fffffff\r\n\r\n",
        )
        .await;
        assert!(r.starts_with("HTTP/1.1 200 OK"), "expected 200, got:\n{r}");
        assert!(r.contains("proteus_handshakes_succeeded_total 7"));

        // /healthz remains unauthenticated.
        let r = fetch(addr, "GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n").await;
        // (alive defaults to false → 503, but never 401.)
        assert!(!r.starts_with("HTTP/1.1 401"));

        server_task.abort();
    }

    /// Helper: mint a self-signed cert + acceptor + chain for the
    /// TLS-observability test cases.
    #[cfg(test)]
    fn mint_tls_acceptor_with_chain() -> (
        crate::tls::ReloadableAcceptor,
        Vec<rustls::pki_types::CertificateDer<'static>>,
    ) {
        use rcgen::generate_simple_self_signed;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        let ck = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert = CertificateDer::from(ck.cert.der().to_vec());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));
        let chain = vec![cert];
        let acceptor = crate::tls::build_acceptor(chain.clone(), key).unwrap();
        let reloadable = crate::tls::ReloadableAcceptor::new_with_expiry(acceptor, &chain);
        (reloadable, chain)
    }

    #[test]
    fn render_full_v3_includes_tls_cert_expiry_when_acceptor_supplied() {
        let m = ServerMetrics::default();
        let (acceptor, _) = mint_tls_acceptor_with_chain();
        let (status, _ctype, body) = render_full_v3(
            "GET /metrics HTTP/1.1\r\n\r\n",
            &m,
            None,
            None,
            None,
            Some(&acceptor),
        );
        assert!(status.starts_with("HTTP/1.1 200"));
        assert!(
            body.contains("proteus_tls_cert_not_after_unix_seconds"),
            "missing cert-expiry gauge in body: {body}"
        );
        assert!(
            body.contains("proteus_tls_reload_attempts_total 0"),
            "missing/wrong reload-attempts counter in body: {body}"
        );
        assert!(
            body.contains("proteus_tls_reload_succeeded_total 0"),
            "missing/wrong reload-succeeded counter in body: {body}"
        );
    }

    #[test]
    fn render_full_v3_omits_tls_block_when_acceptor_is_none() {
        let m = ServerMetrics::default();
        let (_status, _ctype, body) =
            render_full_v3("GET /metrics HTTP/1.1\r\n\r\n", &m, None, None, None, None);
        assert!(
            !body.contains("proteus_tls_cert_not_after_unix_seconds"),
            "should not emit cert gauge without acceptor: {body}"
        );
        assert!(
            !body.contains("proteus_tls_reload_attempts_total"),
            "should not emit reload counters without acceptor: {body}"
        );
    }

    /// v4 propagates the config-presence block verbatim into the
    /// `/metrics` body when supplied. Tests that the v3-shaped
    /// metric series remain present alongside the v4 extension.
    #[test]
    fn render_full_v4_appends_config_presence_block() {
        let m = ServerMetrics::default();
        let presence = "# HELP proteus_config_section_active sample\n\
                        # TYPE proteus_config_section_active gauge\n\
                        proteus_config_section_active{section=\"firewall\"} 1\n";
        let (_status, _ctype, body) = render_full_v4(
            "GET /metrics HTTP/1.1\r\n\r\n",
            &m,
            None,
            None,
            None,
            None,
            Some(presence),
        );
        assert!(
            body.contains(r#"proteus_config_section_active{section="firewall"} 1"#),
            "missing config-presence line: {body}"
        );
        // v3-shaped series still there.
        assert!(body.contains("proteus_sessions_accepted_total"));
    }

    /// v6 with per_user supplied emits the per-user series in
    /// the `/metrics` body alongside the rest of the dump.
    #[test]
    fn render_full_v6_emits_per_user_bytes_when_accumulator_supplied() {
        use crate::per_user_bandwidth::PerUserBandwidth;
        let m = ServerMetrics::default();
        let pu = PerUserBandwidth::new(4096);
        pu.record(*b"alice001", 1024, 2048);
        pu.record(*b"bob00002", 512, 256);
        let (status, _ctype, body) = render_full_v6(
            "GET /metrics HTTP/1.1\r\n\r\n",
            &m,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&pu),
        );
        assert!(status.starts_with("HTTP/1.1 200"));
        assert!(
            body.contains(r#"proteus_per_user_bytes_sent_total{user_id="alice001"} 1024"#),
            "{body}"
        );
        assert!(
            body.contains(r#"proteus_per_user_bytes_received_total{user_id="alice001"} 2048"#),
            "{body}"
        );
        assert!(
            body.contains(r#"proteus_per_user_bytes_sent_total{user_id="bob00002"} 512"#),
            "{body}"
        );
        assert!(body.contains("proteus_per_user_bandwidth_tracked_users 2"));
    }

    /// v11 with tls_cert_watcher supplied emits the four
    /// `proteus_tls_cert_watcher_*` counters on /metrics AND
    /// appends them to /diagnose. Proves the wire-up reaches the
    /// HTTP layer.
    #[test]
    fn render_full_v11_emits_tls_cert_watcher_counters_when_supplied() {
        use crate::tls_watcher::CertFileWatcher;
        let m = ServerMetrics::default();
        // We don't actually need the files to exist for the
        // /metrics rendering — the counter values are stored
        // on the watcher independently of the filesystem.
        let watcher = CertFileWatcher::new(
            std::path::PathBuf::from("/tmp/nonexistent_cert.pem"),
            std::path::PathBuf::from("/tmp/nonexistent_key.pem"),
        );
        watcher.record_attempt();
        watcher.record_success();
        let (_status, _ctype, body) = render_full_v11(
            "GET /metrics HTTP/1.1\r\n\r\n",
            &m,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&watcher),
        );
        assert!(
            body.contains("proteus_tls_cert_watcher_auto_reload_attempts_total 1"),
            "missing attempts counter: {body}"
        );
        assert!(
            body.contains("proteus_tls_cert_watcher_auto_reload_succeeded_total 1"),
            "missing succeeded counter: {body}"
        );
        assert!(
            body.contains("proteus_tls_cert_watcher_auto_reload_failed_total 0"),
            "missing failed counter: {body}"
        );

        let (_, _, diag_body) = render_full_v11(
            "GET /diagnose HTTP/1.1\r\n\r\n",
            &m,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&watcher),
        );
        assert!(
            diag_body.contains("proteus_tls_cert_watcher_auto_reload_attempts_total"),
            "watcher counters missing from diagnose: {diag_body}"
        );
    }

    /// v11 with no tls_cert_watcher omits the counters.
    #[test]
    fn render_full_v11_omits_tls_cert_watcher_when_none() {
        let m = ServerMetrics::default();
        let (_, _, body) = render_full_v11(
            "GET /metrics HTTP/1.1\r\n\r\n",
            &m,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(!body.contains("proteus_tls_cert_watcher_"));
    }

    /// v10 with user_quota supplied emits the 11-series quota
    /// block on /metrics AND adds the USER QUOTA table to
    /// /diagnose. End-to-end proof the wire-up reaches the HTTP
    /// layer.
    #[test]
    fn render_full_v10_emits_user_quota_block_when_supplied() {
        use crate::user_quota::PerUserQuotaTracker;
        use std::time::Duration;
        let m = ServerMetrics::default();
        let qt = PerUserQuotaTracker::new(Duration::from_secs(3600), 1024, 4096);
        qt.record(*b"alice001", 500);
        qt.record(*b"bob00002", 1100); // over quota
        let (_status, _ctype, body) = render_full_v10(
            "GET /metrics HTTP/1.1\r\n\r\n",
            &m,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&qt),
        );
        assert!(body.contains("proteus_user_quota_period_seconds 3600"));
        assert!(body.contains("proteus_user_quota_default_cap_bytes 1024"));
        assert!(body.contains("proteus_user_quota_tracked_users 2"));
        assert!(body.contains("proteus_user_quota_over_quota_transitions_total 1"));

        let (_, _, diag_body) = render_full_v10(
            "GET /diagnose HTTP/1.1\r\n\r\n",
            &m,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&qt),
        );
        assert!(diag_body.contains("USER QUOTA"), "{diag_body}");
        assert!(diag_body.contains("alice001"));
        assert!(diag_body.contains("bob00002"));
    }

    /// v10 with no user_quota omits the list-emitted block but
    /// the server-level `proteus_user_quota_admission_rejected_total`
    /// counter is still always emitted.
    #[test]
    fn render_full_v10_omits_user_quota_block_when_none() {
        let m = ServerMetrics::default();
        let (_, _, body) = render_full_v10(
            "GET /metrics HTTP/1.1\r\n\r\n",
            &m,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(!body.contains("proteus_user_quota_period_seconds"));
        assert!(!body.contains("proteus_user_quota_tracked_users"));
        // Server-level counter still present.
        assert!(body.contains("proteus_user_quota_admission_rejected_total 0"));
    }

    /// v9 with user_quarantine supplied emits the six
    /// `proteus_user_quarantine_*` series on `/metrics` AND adds
    /// the USER QUARANTINE table to `/diagnose`. End-to-end proof
    /// the wire-up reaches the HTTP layer.
    #[test]
    fn render_full_v9_emits_user_quarantine_block_when_supplied() {
        use crate::user_quarantine::UserQuarantineList;
        use std::time::Duration;
        let m = ServerMetrics::default();
        let q = UserQuarantineList::new(Duration::from_secs(600), 4096);
        q.insert(*b"alice001", "per_user_bandwidth_rate");
        q.insert(*b"bob00002", "rate_limit");
        let (_status, _ctype, metrics_body) = render_full_v9(
            "GET /metrics HTTP/1.1\r\n\r\n",
            &m,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&q),
        );
        assert!(metrics_body.contains("proteus_user_quarantine_ttl_seconds 600"));
        assert!(metrics_body.contains("proteus_user_quarantine_max_entries 4096"));
        assert!(metrics_body.contains("proteus_user_quarantine_active_entries 2"));
        assert!(metrics_body.contains("proteus_user_quarantine_inserted_total 2"));
        let (_status, _ctype, diag_body) = render_full_v9(
            "GET /diagnose HTTP/1.1\r\n\r\n",
            &m,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&q),
        );
        assert!(
            diag_body.contains("USER QUARANTINE"),
            "diagnose missing table: {diag_body}"
        );
        assert!(diag_body.contains("alice001"), "{diag_body}");
        assert!(diag_body.contains("bob00002"), "{diag_body}");
        assert!(diag_body.contains("per_user_bandwidth_rate"), "{diag_body}");
    }

    /// v9 with no quarantine list omits the list-emitted block
    /// (six `*_ttl_seconds`/`*_max_entries`/`*_active_entries`/
    /// `*_inserted_total`/`*_refused_inserts_total`/`*_hits_total`
    /// series). The `proteus_user_quarantine_rejected_total`
    /// counter on ServerMetrics IS still emitted (it's a server-
    /// level counter, always present so operators can write
    /// `rate(...)` against it from t=0).
    #[test]
    fn render_full_v9_omits_user_quarantine_list_block_when_none() {
        let m = ServerMetrics::default();
        let (_s, _c, body) = render_full_v9(
            "GET /metrics HTTP/1.1\r\n\r\n",
            &m,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        // List-emitted series are absent.
        assert!(!body.contains("proteus_user_quarantine_ttl_seconds"));
        assert!(!body.contains("proteus_user_quarantine_max_entries"));
        assert!(!body.contains("proteus_user_quarantine_active_entries"));
        assert!(!body.contains("proteus_user_quarantine_inserted_total"));
        assert!(!body.contains("proteus_user_quarantine_hits_total"));
        // Server-level rejection counter IS emitted (always).
        assert!(body.contains("proteus_user_quarantine_rejected_total 0"));
    }

    /// v8 with abuse_fires supplied emits the buffer's two gauges
    /// AND inserts the recent-fires table into `/diagnose`. Proves
    /// the wire-up is end-to-end through the HTTP layer.
    #[test]
    fn render_full_v8_emits_abuse_fires_metrics_and_diagnose_table() {
        use crate::abuse_fires::{AbuseFireBuffer, AbuseFireKind};
        let m = ServerMetrics::default();
        let fires = AbuseFireBuffer::new(64);
        // Push two fires so the table has content + capacity/count
        // gauges have non-trivial values.
        fires.push(AbuseFireKind::ByteBudget, *b"alice001", 0);
        fires.push(
            AbuseFireKind::PerUserBandwidthRate,
            *b"bob00002",
            104_857_600,
        );

        // /metrics body has the two gauges.
        let (_s1, _c1, metrics_body) = render_full_v8(
            "GET /metrics HTTP/1.1\r\n\r\n",
            &m,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&fires),
        );
        assert!(
            metrics_body.contains("proteus_abuse_recent_fires_capacity 64"),
            "{metrics_body}"
        );
        assert!(
            metrics_body.contains("proteus_abuse_recent_fires_count 2"),
            "{metrics_body}"
        );

        // /diagnose body has the human-readable table.
        let (_s2, _c2, diag_body) = render_full_v8(
            "GET /diagnose HTTP/1.1\r\n\r\n",
            &m,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&fires),
        );
        assert!(
            diag_body.contains("RECENT ABUSE FIRES"),
            "diagnose missing table header: {diag_body}"
        );
        assert!(
            diag_body.contains("alice001"),
            "diagnose missing alice fire: {diag_body}"
        );
        assert!(
            diag_body.contains("per_user_bandwidth_rate"),
            "diagnose missing bandwidth-rate kind: {diag_body}"
        );
        assert!(
            diag_body.contains("104857600"),
            "diagnose missing bandwidth context: {diag_body}"
        );
    }

    /// v8 with no abuse_fires omits the recent-fires block both on
    /// /metrics (no gauges) and /diagnose (no table).
    #[test]
    fn render_full_v8_omits_abuse_fires_when_buffer_none() {
        let m = ServerMetrics::default();
        let (_s, _c, metrics_body) = render_full_v8(
            "GET /metrics HTTP/1.1\r\n\r\n",
            &m,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(!metrics_body.contains("proteus_abuse_recent_fires_capacity"));
        let (_s, _c, diag_body) = render_full_v8(
            "GET /diagnose HTTP/1.1\r\n\r\n",
            &m,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(!diag_body.contains("RECENT ABUSE FIRES"));
    }

    /// v7 with per_user_conn_limiter supplied emits the limiter's
    /// three Prometheus series. Operator-facing test: confirms the
    /// caller can wire the limiter through metrics_http and have it
    /// surface on `/metrics`.
    #[test]
    fn render_full_v7_emits_per_user_conn_limit_block_when_limiter_supplied() {
        use crate::per_user_conn_limit::PerUserConnLimiter;
        let m = ServerMetrics::default();
        let limiter = PerUserConnLimiter::new(6);
        // Hold one slot for alice so active_users=1.
        let _g = limiter.try_acquire(*b"alice001");
        let (status, _ctype, body) = render_full_v7(
            "GET /metrics HTTP/1.1\r\n\r\n",
            &m,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&limiter),
        );
        assert!(status.starts_with("HTTP/1.1 200"));
        assert!(
            body.contains("proteus_per_user_conn_limit_max_per_user 6"),
            "{body}"
        );
        assert!(
            body.contains("proteus_per_user_conn_limit_active_users 1"),
            "{body}"
        );
        assert!(
            body.contains("proteus_per_user_conn_limit_rejected_total 0"),
            "{body}"
        );
    }

    /// v7 with no limiter omits the conn-limit block entirely.
    #[test]
    fn render_full_v7_omits_conn_limit_block_when_limiter_none() {
        let m = ServerMetrics::default();
        let (_s, _c, body) = render_full_v7(
            "GET /metrics HTTP/1.1\r\n\r\n",
            &m,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(
            !body.contains("proteus_per_user_conn_limit_max_per_user"),
            "{body}"
        );
    }

    /// When the per-user accumulator has a rate detector wired,
    /// the `/metrics` body renders the detector's threshold +
    /// window + tracked-users gauges INSIDE the per-user block.
    /// Operators reading `/metrics` see one contiguous "per-user
    /// bandwidth" section instead of needing to know about a
    /// separate detector module.
    #[test]
    fn render_full_v6_emits_rate_detector_gauges_when_detector_wired() {
        use crate::per_user_bandwidth::PerUserBandwidth;
        use crate::per_user_bandwidth_rate_detector::PerUserBandwidthRateDetector;
        use std::sync::Arc;
        use std::time::Duration;
        let m = ServerMetrics::default();
        let pu = PerUserBandwidth::new(4096);
        let det = Arc::new(PerUserBandwidthRateDetector::new(
            Duration::from_secs(45),
            200 * 1024 * 1024, // 200 MB/s threshold
            4096,
        ));
        pu.set_rate_detector(Some(Arc::clone(&det)));
        pu.record(*b"alice001", 1024, 1024);
        let (_s, _c, body) = render_full_v6(
            "GET /metrics HTTP/1.1\r\n\r\n",
            &m,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&pu),
        );
        assert!(
            body.contains("proteus_per_user_bandwidth_rate_threshold_bytes_per_sec 209715200"),
            "rate threshold gauge missing: {body}"
        );
        assert!(
            body.contains("proteus_per_user_bandwidth_rate_window_seconds 45"),
            "rate window gauge missing: {body}"
        );
        assert!(
            body.contains("proteus_per_user_bandwidth_rate_tracked_users 1"),
            "rate tracked-users gauge missing: {body}"
        );
        // Counter present at 0 (always emitted, even pre-fire).
        assert!(
            body.contains("proteus_abuse_alerts_per_user_bandwidth_total 0"),
            "abuse alerts counter missing: {body}"
        );
    }

    /// v6 with `None` per_user omits the per-user block entirely.
    #[test]
    fn render_full_v6_omits_per_user_block_when_accumulator_none() {
        let m = ServerMetrics::default();
        let (_status, _ctype, body) = render_full_v6(
            "GET /metrics HTTP/1.1\r\n\r\n",
            &m,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(
            !body.contains("proteus_per_user_bytes_sent_total"),
            "{body}"
        );
        assert!(
            !body.contains("proteus_per_user_bandwidth_tracked_users"),
            "{body}"
        );
    }

    /// v5 with no per-user accumulator (the back-compat shim path)
    /// should ALSO omit the per-user block — proves the shim is
    /// transparent.
    #[test]
    fn render_full_v5_back_compat_shim_omits_per_user_block() {
        let m = ServerMetrics::default();
        let (_status, _ctype, body) = render_full_v5(
            "GET /metrics HTTP/1.1\r\n\r\n",
            &m,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(
            !body.contains("proteus_per_user_bytes_sent_total"),
            "{body}"
        );
    }

    /// v5 + process_info=Some triggers process_resources capture
    /// in the same render path. On Linux the operator sees
    /// `proteus_process_open_fds` + `proteus_process_resident_memory_bytes`
    /// gauges; on macOS / Windows the gauges are absent because
    /// the capture returned `None`.
    #[test]
    fn render_full_v5_emits_process_resources_when_process_info_supplied() {
        let m = ServerMetrics::default();
        let pi = crate::process_info::ProcessInfo::capture("0.1.0", "1.85.0", "test-target");
        let (_s, _c, body) = render_full_v5(
            "GET /metrics HTTP/1.1\r\n\r\n",
            &m,
            None,
            None,
            None,
            None,
            None,
            Some(&pi),
        );
        // process_info series always present when supplied.
        assert!(
            body.contains("proteus_process_start_unix_seconds"),
            "{body}"
        );
        // process_resources: present on Linux, absent on macOS/Windows.
        if cfg!(target_os = "linux") {
            assert!(
                body.contains("proteus_process_open_fds"),
                "Linux must emit open_fds gauge: {body}"
            );
            assert!(
                body.contains("proteus_process_resident_memory_bytes"),
                "Linux must emit RSS gauge: {body}"
            );
        } else {
            assert!(
                !body.contains("proteus_process_open_fds"),
                "non-Linux must NOT emit open_fds gauge: {body}"
            );
        }
    }

    /// v5 + process_info=None means no process_info block AND no
    /// process_resources block — they're coupled by design.
    #[test]
    fn render_full_v5_omits_process_resources_when_process_info_none() {
        let m = ServerMetrics::default();
        let (_s, _c, body) = render_full_v5(
            "GET /metrics HTTP/1.1\r\n\r\n",
            &m,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(!body.contains("proteus_process_open_fds"), "{body}");
        assert!(
            !body.contains("proteus_process_resident_memory_bytes"),
            "{body}"
        );
        assert!(
            !body.contains("proteus_process_start_unix_seconds"),
            "{body}"
        );
    }

    // ----- /diagnose route + rule tests -----

    #[test]
    fn diagnose_minimal_alive_ready_emits_two_info_findings() {
        let m = ServerMetrics::default();
        m.alive.store(true, Ordering::Relaxed);
        m.ready.store(true, Ordering::Relaxed);
        let findings = run_diagnose_rules(&m, None, None);
        // Exactly two findings (alive + ready), both Info.
        assert_eq!(findings.len(), 2, "{findings:#?}");
        assert_eq!(findings[0].rule, "process_alive");
        assert_eq!(findings[0].severity, DiagnoseSeverity::Info);
        assert_eq!(findings[1].rule, "process_ready");
        assert_eq!(findings[1].severity, DiagnoseSeverity::Info);
    }

    #[test]
    fn diagnose_dead_process_emits_critical() {
        let m = ServerMetrics::default();
        // alive=false (default); ready=false (default).
        let findings = run_diagnose_rules(&m, None, None);
        let alive = &findings[0];
        assert_eq!(alive.rule, "process_alive");
        assert_eq!(alive.severity, DiagnoseSeverity::Critical);
        assert!(
            alive.message.contains("NOT alive"),
            "msg: {}",
            alive.message
        );
    }

    #[test]
    fn diagnose_draining_emits_warn_not_critical() {
        let m = ServerMetrics::default();
        m.alive.store(true, Ordering::Relaxed);
        // ready stays false → "draining or warming"
        let findings = run_diagnose_rules(&m, None, None);
        let ready = findings.iter().find(|f| f.rule == "process_ready").unwrap();
        assert_eq!(
            ready.severity,
            DiagnoseSeverity::Warn,
            "draining should be Warn not Critical: {ready:?}"
        );
    }

    /// Reload-counter rule: when attempts > succeeded (silent
    /// SIGHUP failure) the rule fires with a Critical for TLS and
    /// Warn for the four section reloads.
    #[test]
    fn diagnose_reload_silent_failure_fires_per_section() {
        let m = ServerMetrics::default();
        m.alive.store(true, Ordering::Relaxed);
        m.ready.store(true, Ordering::Relaxed);
        m.firewall_reload_attempts.store(3, Ordering::Relaxed);
        m.firewall_reload_succeeded.store(2, Ordering::Relaxed);
        m.rate_limit_reload_attempts.store(3, Ordering::Relaxed);
        m.rate_limit_reload_succeeded.store(3, Ordering::Relaxed);
        let findings = run_diagnose_rules(&m, None, None);
        // Firewall has a silent failure; rate_limit doesn't.
        let fw = findings
            .iter()
            .find(|f| f.rule == "firewall_reload_silent_failure")
            .expect("expected firewall finding");
        assert_eq!(fw.severity, DiagnoseSeverity::Warn);
        assert!(fw.message.contains("1 missing"), "msg: {}", fw.message);
        assert!(
            !findings
                .iter()
                .any(|f| f.rule == "rate_limit_reload_silent_failure"),
            "rate_limit_reload should NOT fire when all succeeded"
        );
    }

    /// /diagnose route returns 200 + a body that contains both
    /// the FINDINGS section AND the metrics dump.
    #[test]
    fn render_full_v5_diagnose_route_serves_full_body() {
        let m = ServerMetrics::default();
        m.alive.store(true, Ordering::Relaxed);
        m.ready.store(true, Ordering::Relaxed);
        m.sessions_accepted.fetch_add(42, Ordering::Relaxed);
        let (status, ctype, body) = render_full_v5(
            "GET /diagnose HTTP/1.1\r\n\r\n",
            &m,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(status.starts_with("HTTP/1.1 200"));
        assert!(ctype.contains("text/plain"));
        assert!(body.contains("FINDINGS"), "{body}");
        assert!(
            body.contains("[INFO] process_alive: process alive"),
            "{body}"
        );
        assert!(body.contains("METRICS"), "{body}");
        // The full metrics dump goes after FINDINGS.
        assert!(
            body.contains("proteus_sessions_accepted_total 42"),
            "{body}"
        );
    }

    /// /diagnose requires bearer-token auth when configured, same
    /// rule as /metrics.
    #[test]
    fn diagnose_route_requires_bearer_auth_when_configured() {
        let m = ServerMetrics::default();
        let auth = MetricsAuth::new("secret123secret123secret123").unwrap();
        let (status, _ctype, body) = render_full_v5(
            "GET /diagnose HTTP/1.1\r\n\r\n",
            &m,
            Some(&auth),
            None,
            None,
            None,
            None,
            None,
        );
        assert!(status.starts_with("HTTP/1.1 401"));
        assert!(body.contains("unauthorized"));
    }

    #[test]
    fn diagnose_route_accepts_correct_bearer_token() {
        let m = ServerMetrics::default();
        m.alive.store(true, Ordering::Relaxed);
        m.ready.store(true, Ordering::Relaxed);
        let auth = MetricsAuth::new("secret123secret123secret123").unwrap();
        let (status, _ctype, body) = render_full_v5(
            "GET /diagnose HTTP/1.1\r\nAuthorization: Bearer secret123secret123secret123\r\n\r\n",
            &m,
            Some(&auth),
            None,
            None,
            None,
            None,
            None,
        );
        assert!(status.starts_with("HTTP/1.1 200"), "got {status}");
        assert!(body.contains("FINDINGS"));
    }

    /// /diagnose with a wrong bearer token returns 401, NOT 200
    /// with a body that leaks operator-sensitive state.
    #[test]
    fn diagnose_route_rejects_wrong_bearer_token() {
        let m = ServerMetrics::default();
        let auth = MetricsAuth::new("secret123secret123secret123").unwrap();
        let (status, _c, body) = render_full_v5(
            "GET /diagnose HTTP/1.1\r\nAuthorization: Bearer wrong123wrong123wrong123wrong\r\n\r\n",
            &m,
            Some(&auth),
            None,
            None,
            None,
            None,
            None,
        );
        assert!(status.starts_with("HTTP/1.1 401"));
        assert!(
            !body.contains("FINDINGS"),
            "must not leak body on auth fail: {body}"
        );
    }

    /// /diagnose substring rejection (consistent with /metrics).
    #[test]
    fn diagnose_substring_path_returns_404() {
        let m = ServerMetrics::default();
        let (status, _c, _b) = render_full_v5(
            "GET /diagnoseleak HTTP/1.1\r\n\r\n",
            &m,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(status.starts_with("HTTP/1.1 404"));
    }

    /// v4 with `None` config_presence omits the block — back-compat
    /// path that v3 routes hit via shim.
    #[test]
    fn render_full_v4_omits_config_presence_when_none() {
        let m = ServerMetrics::default();
        let (_s, _c, body) = render_full_v4(
            "GET /metrics HTTP/1.1\r\n\r\n",
            &m,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(!body.contains("proteus_config_section_active"), "{body}");
    }

    /// v3 shim into v4 must NOT emit config-presence series (back-compat).
    #[test]
    fn render_full_v3_back_compat_shim_omits_config_presence() {
        let m = ServerMetrics::default();
        let (_s, _c, body) =
            render_full_v3("GET /metrics HTTP/1.1\r\n\r\n", &m, None, None, None, None);
        assert!(!body.contains("proteus_config_section_active"), "{body}");
    }

    #[test]
    fn render_full_v3_reflects_reload_counter_bumps() {
        let m = ServerMetrics::default();
        let (acceptor, _) = mint_tls_acceptor_with_chain();
        // Simulate one successful reload + one failed reload.
        let (_, chain2) = mint_tls_acceptor_with_chain();
        // Build a fresh acceptor from chain2's first cert via the
        // existing mint helper — we just want a new acceptor handle.
        let (_, _) = mint_tls_acceptor_with_chain();
        let (acceptor_to_swap_in, _) = mint_tls_acceptor_with_chain();
        // Successful reload using the matching chain.
        acceptor
            .reload_with_expiry(acceptor_to_swap_in.current(), &chain2)
            .unwrap();
        // Failed reload via garbage chain.
        let bad = vec![rustls::pki_types::CertificateDer::from(vec![0xFFu8; 32])];
        let (acceptor_to_swap_in2, _) = mint_tls_acceptor_with_chain();
        let _ = acceptor.reload_with_expiry(acceptor_to_swap_in2.current(), &bad);

        let (_status, _ctype, body) = render_full_v3(
            "GET /metrics HTTP/1.1\r\n\r\n",
            &m,
            None,
            None,
            None,
            Some(&acceptor),
        );
        assert!(
            body.contains("proteus_tls_reload_attempts_total 2"),
            "wrong attempts in body: {body}"
        );
        assert!(
            body.contains("proteus_tls_reload_succeeded_total 1"),
            "wrong succeeded in body: {body}"
        );
    }
}
