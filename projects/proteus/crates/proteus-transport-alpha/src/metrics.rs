//! Per-session metrics. Cheap atomic counters that the server / client
//! can scrape for Prometheus-style exposition.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

/// Per-session metrics. All counters are monotonically increasing.
#[derive(Default, Debug)]
pub struct SessionMetrics {
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_records: AtomicU64,
    pub rx_records: AtomicU64,
    pub aead_drops: AtomicU64,
    pub ratchets: AtomicU64,
    pub close_sent: AtomicU64,
    pub close_recv: AtomicU64,
    /// Heartbeat / cover-traffic cells sent by us (plaintext-flagged
    /// HEARTBEAT, indistinguishable from a normal cell on the wire).
    pub heartbeats_sent: AtomicU64,
    /// Heartbeat cells received and silently consumed (the receiver
    /// did NOT surface them to the caller of `recv_record`).
    pub heartbeats_recv: AtomicU64,
}

impl SessionMetrics {
    /// Record an outgoing plaintext payload of `n` bytes.
    pub fn record_tx(&self, n: u64) {
        self.tx_bytes.fetch_add(n, Ordering::Relaxed);
        self.tx_records.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an incoming plaintext payload of `n` bytes (after AEAD verify).
    pub fn record_rx(&self, n: u64) {
        self.rx_bytes.fetch_add(n, Ordering::Relaxed);
        self.rx_records.fetch_add(1, Ordering::Relaxed);
    }

    /// An AEAD record failed authentication and was silently dropped.
    pub fn record_aead_drop(&self) {
        self.aead_drops.fetch_add(1, Ordering::Relaxed);
    }

    /// A symmetric ratchet was performed (in either direction).
    pub fn record_ratchet(&self) {
        self.ratchets.fetch_add(1, Ordering::Relaxed);
    }

    /// A CLOSE record was sent.
    pub fn record_close_sent(&self) {
        self.close_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// A CLOSE record was received and authenticated.
    pub fn record_close_recv(&self) {
        self.close_recv.fetch_add(1, Ordering::Relaxed);
    }

    /// A heartbeat cell was emitted on the send side.
    pub fn record_heartbeat_sent(&self) {
        self.heartbeats_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// A heartbeat cell was received and silently consumed.
    pub fn record_heartbeat_recv(&self) {
        self.heartbeats_recv.fetch_add(1, Ordering::Relaxed);
    }

    /// Snapshot all counters into a plain struct.
    #[must_use]
    pub fn snapshot(&self) -> SessionMetricsSnapshot {
        SessionMetricsSnapshot {
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            tx_records: self.tx_records.load(Ordering::Relaxed),
            rx_records: self.rx_records.load(Ordering::Relaxed),
            aead_drops: self.aead_drops.load(Ordering::Relaxed),
            ratchets: self.ratchets.load(Ordering::Relaxed),
            close_sent: self.close_sent.load(Ordering::Relaxed),
            close_recv: self.close_recv.load(Ordering::Relaxed),
            heartbeats_sent: self.heartbeats_sent.load(Ordering::Relaxed),
            heartbeats_recv: self.heartbeats_recv.load(Ordering::Relaxed),
        }
    }
}

/// RAII guard: increment `in_flight_sessions` on construct, decrement
/// on drop. Holds an `Arc<SessionMetrics>` for the live session so the
/// per-session totals are snapshotted AT DROP TIME and merged into the
/// server-level counters — **even if the handler panics**.
///
/// **Why snapshot at drop time, not enter time**: per-session counters
/// (`tx_bytes`, `rx_bytes`, …) start at zero and accumulate as the
/// relay pumps bytes. An enter-time snapshot is always all-zeros, so
/// merging it at drop never bumps `proteus_tx_bytes_total` — and the
/// per-user accumulator records (0, 0) on every session. The previous
/// implementation had exactly this bug; the multi-user soak test
/// caught it because `proteus_per_user_bytes_sent_total` stayed at 0
/// despite ~100 successful sessions. Storing the live Arc and
/// snapshotting at drop makes the merge see the final cumulative
/// totals.
///
/// Previously the binary did this with explicit `fetch_add` /
/// `fetch_sub` pairs around `relay::handle_session(...).await`. That
/// pattern leaks the gauge upward forever if the handler ever panics
/// (the decrement is unreachable). With a guard, the drop runs as
/// part of panic unwinding, so the counter stays honest.
pub struct InFlightGuard {
    server: Arc<ServerMetrics>,
    /// Live session metrics handle. Snapshotted at drop time so the
    /// merge reflects the session's FINAL byte totals, not the (all-
    /// zero) enter-time state. `None` means "do not merge" (used by
    /// tests that only want to validate the in_flight gauge).
    session: Option<Arc<SessionMetrics>>,
    /// Per-user accumulator + the user_id this guard's session
    /// belongs to. When `Some`, the drop also records into the
    /// per-user bandwidth tracker at the same moment as the
    /// global merge. When `None`, behaves identically to the
    /// pre-per-user code path (back-compat for tests + the
    /// legacy `enter` constructor).
    per_user: Option<(Arc<crate::per_user_bandwidth::PerUserBandwidth>, [u8; 8])>,
}

impl InFlightGuard {
    /// Construct the guard. Increments `in_flight_sessions` immediately.
    /// Holds the session's live metrics so the merge at drop time sees
    /// the final byte totals. Back-compat entry point — no per-user
    /// accounting.
    pub fn enter(server: Arc<ServerMetrics>, session: Arc<SessionMetrics>) -> Self {
        server.in_flight_sessions.fetch_add(1, Ordering::Relaxed);
        Self {
            server,
            session: Some(session),
            per_user: None,
        }
    }

    /// Like [`Self::enter`] but ALSO records this session's
    /// `(tx_bytes, rx_bytes)` against the supplied `user_id` in
    /// the per-user bandwidth accumulator on drop. Operators
    /// reading `/metrics` then see
    /// `proteus_per_user_bytes_{sent,received}_total{user_id="…"}`
    /// climb in real time.
    pub fn enter_with_per_user(
        server: Arc<ServerMetrics>,
        session: Arc<SessionMetrics>,
        per_user: Arc<crate::per_user_bandwidth::PerUserBandwidth>,
        user_id: [u8; 8],
    ) -> Self {
        server.in_flight_sessions.fetch_add(1, Ordering::Relaxed);
        Self {
            server,
            session: Some(session),
            per_user: Some((per_user, user_id)),
        }
    }

    /// Test-only constructor that takes a synthetic snapshot directly.
    /// Used by unit tests in this file to validate the merge + per-user
    /// record paths without spinning up a real session. NOT for use
    /// by the binary — production must use [`Self::enter`] /
    /// [`Self::enter_with_per_user`] so the merge sees the LIVE
    /// `Arc<SessionMetrics>` at drop time.
    #[cfg(test)]
    fn enter_with_snapshot(
        server: Arc<ServerMetrics>,
        snapshot: SessionMetricsSnapshot,
        per_user: Option<(Arc<crate::per_user_bandwidth::PerUserBandwidth>, [u8; 8])>,
    ) -> Self {
        // Materialize the synthetic snapshot into a fake SessionMetrics
        // so the drop path is identical to production.
        let session = Arc::new(SessionMetrics::default());
        session.tx_bytes.store(snapshot.tx_bytes, Ordering::Relaxed);
        session.rx_bytes.store(snapshot.rx_bytes, Ordering::Relaxed);
        session
            .tx_records
            .store(snapshot.tx_records, Ordering::Relaxed);
        session
            .rx_records
            .store(snapshot.rx_records, Ordering::Relaxed);
        session
            .aead_drops
            .store(snapshot.aead_drops, Ordering::Relaxed);
        session.ratchets.store(snapshot.ratchets, Ordering::Relaxed);
        server.in_flight_sessions.fetch_add(1, Ordering::Relaxed);
        Self {
            server,
            session: Some(session),
            per_user,
        }
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        if let Some(session) = self.session.take() {
            // Snapshot AT DROP TIME so the merge sees the final
            // cumulative totals (tx_bytes / rx_bytes / etc.), not the
            // all-zero state captured at enter.
            let snap = session.snapshot();
            self.server.merge_session(&snap);
            if let Some((pu, uid)) = self.per_user.take() {
                // Per-user record happens AT THE SAME MOMENT as
                // the global merge, so operators never see drift
                // between `proteus_tx_bytes_total` and the
                // sum of `proteus_per_user_bytes_sent_total{...}`.
                // Use the rate-checking variant so a sustained-
                // bandwidth abuse alert can fire from inside the
                // hot-path drop without the binary having to wire
                // a separate hook for each carrier.
                if let crate::per_user_bandwidth_rate_detector::RateAlertOutcome::Fired {
                    bytes_per_sec,
                } = pu.record_with_rate_check(uid, snap.tx_bytes, snap.rx_bytes)
                {
                    self.server
                        .abuse_alerts_per_user_bandwidth
                        .fetch_add(1, Ordering::Relaxed);
                    // Render user_id for the WARN line using the
                    // same printable-vs-hex strategy the per-user
                    // exposition uses, so the log entry matches
                    // the `/metrics` label.
                    let uid_render = crate::per_user_bandwidth::render_user_id_pub(&uid);
                    tracing::warn!(
                        user_id = %uid_render,
                        bytes_per_sec,
                        "abuse: per-user sustained bandwidth above threshold — \
                         possible stolen credential or exfiltration tool. \
                         Fire-once-per-burst; resets after rate drops to half threshold."
                    );
                }
            }
        }
        self.server
            .in_flight_sessions
            .fetch_sub(1, Ordering::Relaxed);
    }
}

/// Immutable snapshot for export.
#[derive(Debug, Clone, Copy, Default)]
pub struct SessionMetricsSnapshot {
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_records: u64,
    pub rx_records: u64,
    pub aead_drops: u64,
    pub ratchets: u64,
    pub close_sent: u64,
    pub close_recv: u64,
    pub heartbeats_sent: u64,
    pub heartbeats_recv: u64,
}

/// Aggregate metrics across multiple sessions, e.g. on the server.
///
/// Also carries the **liveness/readiness flags** consumed by the
/// `/healthz` and `/readyz` HTTP probes. Liveness flips to `true` once
/// the accept loop has bound; readiness flips to `true` once the
/// server is willing to accept new traffic, and flips back to `false`
/// during graceful drain so load balancers stop sending it work.
#[derive(Debug)]
pub struct ServerMetrics {
    pub sessions_accepted: AtomicU64,
    pub handshakes_succeeded: AtomicU64,
    pub handshakes_failed: AtomicU64,
    pub handshake_timeouts: AtomicU64,
    pub rate_limited: AtomicU64,
    pub conn_limit_rejected: AtomicU64,
    pub firewall_denied: AtomicU64,
    pub handshake_budget_rejected: AtomicU64,
    pub user_rate_rejected: AtomicU64,
    pub cover_forwards: AtomicU64,
    /// Probe-anomaly detector alerts (sliding-window, fire-once-per-
    /// burst semantics). Bumped when any source-IP /24 (v4) /
    /// /48 (v6) prefix crosses the configured cover-forward
    /// threshold within the window. A rising counter here indicates
    /// sustained active probing from a coordinated origin — the
    /// kind of signal a Tiangou-class adversary's IP-sweep mapping
    /// would produce. See `crate::probe_anomaly::ProbeAnomalyDetector`.
    pub probe_anomalies_fired: AtomicU64,
    pub total_tx_bytes: AtomicU64,
    pub total_rx_bytes: AtomicU64,
    pub total_aead_drops: AtomicU64,
    pub total_ratchets: AtomicU64,
    /// Sessions torn down by the relay's per-direction idle timeout.
    /// Distinct from `handshake_timeouts` (which fires during setup).
    pub session_idle_reaped: AtomicU64,
    /// Sessions torn down because their cumulative tx+rx plaintext
    /// byte count hit the configured `max_session_bytes` cap. Distinct
    /// from `session_idle_reaped`. A high rate here means either a
    /// legitimate streaming workload is hitting the cap (raise it) or
    /// a single user is dominating egress (the cap is doing its job).
    pub session_byte_budget_exhausted: AtomicU64,
    /// Abuse-detector alerts. Bumped once per burst (sliding-window,
    /// fire-once semantics) when a user hits the byte-budget cap
    /// repeatedly. Operator sees this counter rise = likely a
    /// stolen credential being used to exfiltrate.
    pub abuse_alerts_byte_budget: AtomicU64,
    /// Abuse-detector alerts for the per-user rate limiter. Bumped
    /// once per burst when a user trips `user_rate_rejected`
    /// repeatedly. Operator sees this counter rise = likely a
    /// misconfigured / bot-controlled client.
    pub abuse_alerts_rate_limit: AtomicU64,
    /// **Per-user sustained bandwidth alerts.** Bumped once per burst
    /// (sliding-window, hysteresis-driven) when a user's
    /// `(tx + rx)` byte rate stays above the operator-configured
    /// `per_user_bandwidth_rate_threshold` for the window length.
    /// Distinct from `abuse_alerts_byte_budget` (which fires on
    /// discrete cap hits): this fires on **sustained throughput**,
    /// catching exfil patterns that stay under the per-session cap.
    /// Operator workflow: alert on `rate(...) > 0` in any log/metrics
    /// pipeline — even a single uptick is operator-actionable.
    pub abuse_alerts_per_user_bandwidth: AtomicU64,
    /// **Post-handshake admission gate rejections** for a quarantined
    /// `user_id`. Bumped once per attempted handshake that lands on
    /// an active quarantine entry — the "auto-quarantine actually
    /// blocked an attacker mid-burst" counter. Distinct from
    /// `user_rate_rejected` (which is a transient rate-limit
    /// rejection): a hit here means the user_id was explicitly
    /// banned for a TTL.
    pub user_quarantine_rejected: AtomicU64,
    /// Upstream dial requests blocked by the outbound destination
    /// filter. Includes SSRF-style attempts (`169.254.169.254`,
    /// RFC 1918, loopback, IPv6 ULA / mapped-v4 bypass) and
    /// disallowed-port attempts. A rising counter here is a strong
    /// signal that a credential has been stolen and is being used
    /// for lateral movement / metadata-endpoint scraping.
    pub outbound_blocked: AtomicU64,
    /// In-flight session count (incremented on accept, decremented on
    /// session completion). Exported as a Prometheus gauge.
    pub in_flight_sessions: AtomicU64,
    /// **SIGHUP firewall reload counters.** The server's SIGHUP
    /// handler re-reads the YAML, rebuilds the CIDR firewall, and
    /// hot-swaps it. Operators have always seen the TLS-reload
    /// success counter on `/metrics` but NOT the firewall reload
    /// counter — meaning they couldn't tell whether SIGHUP actually
    /// applied their `firewall:` block edit. A non-zero
    /// `firewall_reload_attempts - firewall_reload_succeeded`
    /// surfaces YAML-parse errors in the new firewall block.
    pub firewall_reload_attempts: AtomicU64,
    pub firewall_reload_succeeded: AtomicU64,
    /// **SIGHUP per-IP rate-limit reload counters.** Same shape +
    /// same operator value as firewall. `reload_attempts` bumps on
    /// every SIGHUP that has a `rate_limit:` block in the new YAML;
    /// `reload_succeeded` bumps only when the existing per-IP
    /// limiter was installed at startup (operator must restart to
    /// install a NEW limiter — config docstring covers this).
    pub rate_limit_reload_attempts: AtomicU64,
    pub rate_limit_reload_succeeded: AtomicU64,
    /// **SIGHUP per-user rate-limit reload counters.** Same pattern
    /// as per-IP rate limit.
    pub user_rate_limit_reload_attempts: AtomicU64,
    pub user_rate_limit_reload_succeeded: AtomicU64,
    /// **SIGHUP global handshake-budget reload counters.** Same
    /// pattern.
    pub handshake_budget_reload_attempts: AtomicU64,
    pub handshake_budget_reload_succeeded: AtomicU64,
    /// `/healthz` flag — process is alive and event loop running.
    /// Set to `true` once the listener is bound; never flipped back.
    pub alive: AtomicBool,
    /// `/readyz` flag — server is willing to accept new traffic.
    /// Flipped to `false` on graceful shutdown so load balancers
    /// stop steering traffic before in-flight sessions complete.
    pub ready: AtomicBool,
}

impl Default for ServerMetrics {
    fn default() -> Self {
        Self {
            sessions_accepted: AtomicU64::new(0),
            handshakes_succeeded: AtomicU64::new(0),
            handshakes_failed: AtomicU64::new(0),
            handshake_timeouts: AtomicU64::new(0),
            rate_limited: AtomicU64::new(0),
            conn_limit_rejected: AtomicU64::new(0),
            firewall_denied: AtomicU64::new(0),
            handshake_budget_rejected: AtomicU64::new(0),
            user_rate_rejected: AtomicU64::new(0),
            cover_forwards: AtomicU64::new(0),
            probe_anomalies_fired: AtomicU64::new(0),
            total_tx_bytes: AtomicU64::new(0),
            total_rx_bytes: AtomicU64::new(0),
            total_aead_drops: AtomicU64::new(0),
            total_ratchets: AtomicU64::new(0),
            session_idle_reaped: AtomicU64::new(0),
            session_byte_budget_exhausted: AtomicU64::new(0),
            abuse_alerts_byte_budget: AtomicU64::new(0),
            abuse_alerts_rate_limit: AtomicU64::new(0),
            abuse_alerts_per_user_bandwidth: AtomicU64::new(0),
            user_quarantine_rejected: AtomicU64::new(0),
            outbound_blocked: AtomicU64::new(0),
            in_flight_sessions: AtomicU64::new(0),
            firewall_reload_attempts: AtomicU64::new(0),
            firewall_reload_succeeded: AtomicU64::new(0),
            rate_limit_reload_attempts: AtomicU64::new(0),
            rate_limit_reload_succeeded: AtomicU64::new(0),
            user_rate_limit_reload_attempts: AtomicU64::new(0),
            user_rate_limit_reload_succeeded: AtomicU64::new(0),
            handshake_budget_reload_attempts: AtomicU64::new(0),
            handshake_budget_reload_succeeded: AtomicU64::new(0),
            // Default to "not alive, not ready". The accept loop flips
            // alive→true once it binds; the operator flips ready→true
            // once they're satisfied the process has warmed up.
            alive: AtomicBool::new(false),
            ready: AtomicBool::new(false),
        }
    }
}

impl ServerMetrics {
    /// Merge a per-session snapshot into the server-level totals.
    pub fn merge_session(&self, snap: &SessionMetricsSnapshot) {
        self.total_tx_bytes
            .fetch_add(snap.tx_bytes, Ordering::Relaxed);
        self.total_rx_bytes
            .fetch_add(snap.rx_bytes, Ordering::Relaxed);
        self.total_aead_drops
            .fetch_add(snap.aead_drops, Ordering::Relaxed);
        self.total_ratchets
            .fetch_add(snap.ratchets, Ordering::Relaxed);
    }

    /// Emit Prometheus exposition format.
    #[must_use]
    pub fn prometheus(&self) -> String {
        let s = |c: &AtomicU64| c.load(Ordering::Relaxed);
        format!(
            "# HELP proteus_sessions_accepted_total Number of TCP connections accepted.\n\
             # TYPE proteus_sessions_accepted_total counter\n\
             proteus_sessions_accepted_total {}\n\
             # HELP proteus_handshakes_succeeded_total Successful Proteus handshakes.\n\
             # TYPE proteus_handshakes_succeeded_total counter\n\
             proteus_handshakes_succeeded_total {}\n\
             # HELP proteus_handshakes_failed_total Failed Proteus handshakes (forwarded to cover).\n\
             # TYPE proteus_handshakes_failed_total counter\n\
             proteus_handshakes_failed_total {}\n\
             # HELP proteus_handshake_timeouts_total Handshakes that exceeded the deadline (slowloris).\n\
             # TYPE proteus_handshake_timeouts_total counter\n\
             proteus_handshake_timeouts_total {}\n\
             # HELP proteus_rate_limited_total Connections rejected by per-IP rate limiter.\n\
             # TYPE proteus_rate_limited_total counter\n\
             proteus_rate_limited_total {}\n\
             # HELP proteus_conn_limit_rejected_total Connections rejected because max_connections was reached.\n\
             # TYPE proteus_conn_limit_rejected_total counter\n\
             proteus_conn_limit_rejected_total {}\n\
             # HELP proteus_firewall_denied_total Connections denied by CIDR firewall (allow/deny rules).\n\
             # TYPE proteus_firewall_denied_total counter\n\
             proteus_firewall_denied_total {}\n\
             # HELP proteus_handshake_budget_rejected_total Connections denied by the global handshake budget.\n\
             # TYPE proteus_handshake_budget_rejected_total counter\n\
             proteus_handshake_budget_rejected_total {}\n\
             # HELP proteus_user_rate_rejected_total Connections denied by the per-user rate limit (post-handshake).\n\
             # TYPE proteus_user_rate_rejected_total counter\n\
             proteus_user_rate_rejected_total {}\n\
             # HELP proteus_cover_forwards_total Connections forwarded to the cover endpoint.\n\
             # TYPE proteus_cover_forwards_total counter\n\
             proteus_cover_forwards_total {}\n\
             # HELP proteus_probe_anomalies_fired_total Per-/24 cover-forward anomaly alerts (sliding window, fire-once-per-burst).\n\
             # TYPE proteus_probe_anomalies_fired_total counter\n\
             proteus_probe_anomalies_fired_total {}\n\
             # HELP proteus_tx_bytes_total Plaintext bytes sent (server→client).\n\
             # TYPE proteus_tx_bytes_total counter\n\
             proteus_tx_bytes_total {}\n\
             # HELP proteus_rx_bytes_total Plaintext bytes received (client→server).\n\
             # TYPE proteus_rx_bytes_total counter\n\
             proteus_rx_bytes_total {}\n\
             # HELP proteus_aead_drops_total AEAD-failed records silently dropped.\n\
             # TYPE proteus_aead_drops_total counter\n\
             proteus_aead_drops_total {}\n\
             # HELP proteus_ratchets_total Key ratchets performed.\n\
             # TYPE proteus_ratchets_total counter\n\
             proteus_ratchets_total {}\n\
             # HELP proteus_session_idle_reaped_total Sessions torn down by the per-direction idle timeout.\n\
             # TYPE proteus_session_idle_reaped_total counter\n\
             proteus_session_idle_reaped_total {}\n\
             # HELP proteus_session_byte_budget_exhausted_total Sessions torn down by the per-session byte cap.\n\
             # TYPE proteus_session_byte_budget_exhausted_total counter\n\
             proteus_session_byte_budget_exhausted_total {}\n\
             # HELP proteus_abuse_alerts_byte_budget_total Per-user byte-budget abuse alert fires (sliding window).\n\
             # TYPE proteus_abuse_alerts_byte_budget_total counter\n\
             proteus_abuse_alerts_byte_budget_total {}\n\
             # HELP proteus_abuse_alerts_rate_limit_total Per-user rate-limit abuse alert fires (sliding window).\n\
             # TYPE proteus_abuse_alerts_rate_limit_total counter\n\
             proteus_abuse_alerts_rate_limit_total {}\n\
             # HELP proteus_abuse_alerts_per_user_bandwidth_total Per-user sustained-bandwidth abuse alert fires (sliding window + hysteresis).\n\
             # TYPE proteus_abuse_alerts_per_user_bandwidth_total counter\n\
             proteus_abuse_alerts_per_user_bandwidth_total {}\n\
             # HELP proteus_user_quarantine_rejected_total Handshakes rejected because the user_id was in the auto-quarantine list.\n\
             # TYPE proteus_user_quarantine_rejected_total counter\n\
             proteus_user_quarantine_rejected_total {}\n\
             # HELP proteus_outbound_blocked_total Upstream dials blocked by the outbound destination filter.\n\
             # TYPE proteus_outbound_blocked_total counter\n\
             proteus_outbound_blocked_total {}\n\
             # HELP proteus_in_flight_sessions In-flight sessions (gauge).\n\
             # TYPE proteus_in_flight_sessions gauge\n\
             proteus_in_flight_sessions {}\n\
             # HELP proteus_up 1 if the server is alive, 0 otherwise.\n\
             # TYPE proteus_up gauge\n\
             proteus_up {}\n\
             # HELP proteus_ready 1 if the server is accepting new traffic, 0 otherwise.\n\
             # TYPE proteus_ready gauge\n\
             proteus_ready {}\n\
             # HELP proteus_firewall_reload_attempts_total SIGHUP-driven firewall reload attempts.\n\
             # TYPE proteus_firewall_reload_attempts_total counter\n\
             proteus_firewall_reload_attempts_total {}\n\
             # HELP proteus_firewall_reload_succeeded_total Firewall reloads that successfully parsed + swapped.\n\
             # TYPE proteus_firewall_reload_succeeded_total counter\n\
             proteus_firewall_reload_succeeded_total {}\n\
             # HELP proteus_rate_limit_reload_attempts_total SIGHUP-driven per-IP rate-limit reload attempts.\n\
             # TYPE proteus_rate_limit_reload_attempts_total counter\n\
             proteus_rate_limit_reload_attempts_total {}\n\
             # HELP proteus_rate_limit_reload_succeeded_total Per-IP rate-limit reloads that hot-swapped (requires the limiter to have been installed at startup).\n\
             # TYPE proteus_rate_limit_reload_succeeded_total counter\n\
             proteus_rate_limit_reload_succeeded_total {}\n\
             # HELP proteus_user_rate_limit_reload_attempts_total SIGHUP-driven per-user rate-limit reload attempts.\n\
             # TYPE proteus_user_rate_limit_reload_attempts_total counter\n\
             proteus_user_rate_limit_reload_attempts_total {}\n\
             # HELP proteus_user_rate_limit_reload_succeeded_total Per-user rate-limit reloads that hot-swapped.\n\
             # TYPE proteus_user_rate_limit_reload_succeeded_total counter\n\
             proteus_user_rate_limit_reload_succeeded_total {}\n\
             # HELP proteus_handshake_budget_reload_attempts_total SIGHUP-driven global handshake-budget reload attempts.\n\
             # TYPE proteus_handshake_budget_reload_attempts_total counter\n\
             proteus_handshake_budget_reload_attempts_total {}\n\
             # HELP proteus_handshake_budget_reload_succeeded_total Global handshake-budget reloads that hot-swapped.\n\
             # TYPE proteus_handshake_budget_reload_succeeded_total counter\n\
             proteus_handshake_budget_reload_succeeded_total {}\n",
            s(&self.sessions_accepted),
            s(&self.handshakes_succeeded),
            s(&self.handshakes_failed),
            s(&self.handshake_timeouts),
            s(&self.rate_limited),
            s(&self.conn_limit_rejected),
            s(&self.firewall_denied),
            s(&self.handshake_budget_rejected),
            s(&self.user_rate_rejected),
            s(&self.cover_forwards),
            s(&self.probe_anomalies_fired),
            s(&self.total_tx_bytes),
            s(&self.total_rx_bytes),
            s(&self.total_aead_drops),
            s(&self.total_ratchets),
            s(&self.session_idle_reaped),
            s(&self.session_byte_budget_exhausted),
            s(&self.abuse_alerts_byte_budget),
            s(&self.abuse_alerts_rate_limit),
            s(&self.abuse_alerts_per_user_bandwidth),
            s(&self.user_quarantine_rejected),
            s(&self.outbound_blocked),
            s(&self.in_flight_sessions),
            u64::from(self.alive.load(Ordering::Relaxed)),
            u64::from(self.ready.load(Ordering::Relaxed)),
            s(&self.firewall_reload_attempts),
            s(&self.firewall_reload_succeeded),
            s(&self.rate_limit_reload_attempts),
            s(&self.rate_limit_reload_succeeded),
            s(&self.user_rate_limit_reload_attempts),
            s(&self.user_rate_limit_reload_succeeded),
            s(&self.handshake_budget_reload_attempts),
            s(&self.handshake_budget_reload_succeeded),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_counters_increment() {
        let m = SessionMetrics::default();
        m.record_tx(100);
        m.record_tx(50);
        m.record_rx(200);
        m.record_aead_drop();
        m.record_ratchet();
        let snap = m.snapshot();
        assert_eq!(snap.tx_bytes, 150);
        assert_eq!(snap.tx_records, 2);
        assert_eq!(snap.rx_bytes, 200);
        assert_eq!(snap.rx_records, 1);
        assert_eq!(snap.aead_drops, 1);
        assert_eq!(snap.ratchets, 1);
    }

    #[test]
    fn server_prometheus_has_expected_lines() {
        let m = ServerMetrics::default();
        m.sessions_accepted.fetch_add(7, Ordering::Relaxed);
        m.handshakes_succeeded.fetch_add(5, Ordering::Relaxed);
        let text = m.prometheus();
        assert!(text.contains("proteus_sessions_accepted_total 7"));
        assert!(text.contains("proteus_handshakes_succeeded_total 5"));
        assert!(text.contains("# TYPE proteus_handshakes_failed_total counter"));
    }

    /// SIGHUP reload counters are always emitted at zero on a fresh
    /// ServerMetrics — operators script `rate(...)` and need the
    /// series to exist from t=0 (no absent-counter gaps).
    #[test]
    fn server_prometheus_always_emits_sighup_reload_counters() {
        let m = ServerMetrics::default();
        let text = m.prometheus();
        for name in [
            "proteus_firewall_reload_attempts_total",
            "proteus_firewall_reload_succeeded_total",
            "proteus_rate_limit_reload_attempts_total",
            "proteus_rate_limit_reload_succeeded_total",
            "proteus_user_rate_limit_reload_attempts_total",
            "proteus_user_rate_limit_reload_succeeded_total",
            "proteus_handshake_budget_reload_attempts_total",
            "proteus_handshake_budget_reload_succeeded_total",
        ] {
            assert!(
                text.contains(&format!("{name} 0\n")),
                "missing zero-valued counter {name} in:\n{text}"
            );
            assert!(
                text.contains(&format!("# TYPE {name} counter")),
                "missing TYPE row for {name} in:\n{text}"
            );
        }
    }

    /// Bumping the reload counters reflects in the Prometheus output.
    #[test]
    fn server_prometheus_reflects_sighup_reload_counter_bumps() {
        let m = ServerMetrics::default();
        m.firewall_reload_attempts.fetch_add(3, Ordering::Relaxed);
        m.firewall_reload_succeeded.fetch_add(3, Ordering::Relaxed);
        m.rate_limit_reload_attempts.fetch_add(3, Ordering::Relaxed);
        m.rate_limit_reload_succeeded
            .fetch_add(2, Ordering::Relaxed);
        let text = m.prometheus();
        assert!(text.contains("proteus_firewall_reload_attempts_total 3\n"));
        assert!(text.contains("proteus_firewall_reload_succeeded_total 3\n"));
        assert!(text.contains("proteus_rate_limit_reload_attempts_total 3\n"));
        assert!(text.contains("proteus_rate_limit_reload_succeeded_total 2\n"));
    }

    #[test]
    fn merge_session_aggregates() {
        let server = ServerMetrics::default();
        let session = SessionMetricsSnapshot {
            tx_bytes: 10,
            rx_bytes: 20,
            tx_records: 1,
            rx_records: 1,
            aead_drops: 0,
            ratchets: 0,
            close_sent: 0,
            close_recv: 0,
            heartbeats_sent: 0,
            heartbeats_recv: 0,
        };
        server.merge_session(&session);
        server.merge_session(&session);
        assert_eq!(server.total_tx_bytes.load(Ordering::Relaxed), 20);
        assert_eq!(server.total_rx_bytes.load(Ordering::Relaxed), 40);
    }

    #[test]
    fn in_flight_guard_with_per_user_records_at_drop() {
        use crate::per_user_bandwidth::PerUserBandwidth;
        let server = Arc::new(ServerMetrics::default());
        let pu = Arc::new(PerUserBandwidth::new(4096));
        let snap = SessionMetricsSnapshot {
            tx_bytes: 1024,
            rx_bytes: 2048,
            ..SessionMetricsSnapshot::default()
        };
        {
            let _g = InFlightGuard::enter_with_snapshot(
                Arc::clone(&server),
                snap,
                Some((Arc::clone(&pu), *b"alice001")),
            );
        }
        // Per-user counters bumped at drop.
        let pu_snap = pu.snapshot();
        assert_eq!(pu_snap.len(), 1);
        assert_eq!(pu_snap[0].0, *b"alice001");
        assert_eq!(pu_snap[0].1.tx, 1024);
        assert_eq!(pu_snap[0].1.rx, 2048);
        // Global server counters bumped at the same moment.
        assert_eq!(server.total_tx_bytes.load(Ordering::Relaxed), 1024);
        assert_eq!(server.total_rx_bytes.load(Ordering::Relaxed), 2048);
    }

    #[test]
    fn in_flight_guard_snapshots_at_drop_not_enter() {
        // Regression: the guard must capture bytes AT DROP TIME, not
        // at enter. Simulates a real session: the relay mutates
        // session_metrics while the guard is alive; the drop merge
        // must reflect those late-arriving bytes, not the all-zero
        // enter-time state.
        let server = Arc::new(ServerMetrics::default());
        let session = Arc::new(SessionMetrics::default());
        {
            let _g = InFlightGuard::enter(Arc::clone(&server), Arc::clone(&session));
            // Bytes accumulate AFTER the guard was constructed —
            // exactly how relay::handle_session_inner pumps the data
            // pipe. An enter-time snapshot would miss every byte
            // here.
            session.record_tx(500);
            session.record_rx(700);
            session.record_tx(100);
        }
        assert_eq!(
            server.total_tx_bytes.load(Ordering::Relaxed),
            600,
            "guard must snapshot at drop — late TX should be merged"
        );
        assert_eq!(
            server.total_rx_bytes.load(Ordering::Relaxed),
            700,
            "guard must snapshot at drop — late RX should be merged"
        );
    }

    #[test]
    fn in_flight_guard_per_user_records_drop_time_totals() {
        // Same regression as above, but for the per-user accumulator.
        // This is the production code path the multi-user soak
        // exercises.
        use crate::per_user_bandwidth::PerUserBandwidth;
        let server = Arc::new(ServerMetrics::default());
        let pu = Arc::new(PerUserBandwidth::new(4096));
        let session = Arc::new(SessionMetrics::default());
        {
            let _g = InFlightGuard::enter_with_per_user(
                Arc::clone(&server),
                Arc::clone(&session),
                Arc::clone(&pu),
                *b"bob00002",
            );
            session.record_tx(4096);
            session.record_rx(8192);
        }
        let pu_snap = pu.snapshot();
        assert_eq!(pu_snap.len(), 1);
        assert_eq!(pu_snap[0].0, *b"bob00002");
        assert_eq!(
            pu_snap[0].1.tx, 4096,
            "per-user tx must reflect drop-time total"
        );
        assert_eq!(
            pu_snap[0].1.rx, 8192,
            "per-user rx must reflect drop-time total"
        );
    }

    #[test]
    fn in_flight_guard_normal_drop_decrements_and_merges() {
        let server = Arc::new(ServerMetrics::default());
        let snap = SessionMetricsSnapshot {
            tx_bytes: 7,
            rx_bytes: 11,
            ..SessionMetricsSnapshot::default()
        };
        {
            let _guard = InFlightGuard::enter_with_snapshot(Arc::clone(&server), snap, None);
            assert_eq!(server.in_flight_sessions.load(Ordering::Relaxed), 1);
        }
        assert_eq!(server.in_flight_sessions.load(Ordering::Relaxed), 0);
        assert_eq!(server.total_tx_bytes.load(Ordering::Relaxed), 7);
        assert_eq!(server.total_rx_bytes.load(Ordering::Relaxed), 11);
    }

    #[test]
    fn in_flight_guard_decrements_on_panic_unwind() {
        // Spawn a closure that panics while holding the guard. Drop
        // runs as part of unwinding → the counter must end at 0.
        let server = Arc::new(ServerMetrics::default());
        let server_clone = Arc::clone(&server);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _guard = InFlightGuard::enter(
                Arc::clone(&server_clone),
                Arc::new(SessionMetrics::default()),
            );
            assert_eq!(server_clone.in_flight_sessions.load(Ordering::Relaxed), 1);
            panic!("simulated handler panic");
        }));
        assert!(r.is_err(), "panic should have propagated");
        assert_eq!(
            server.in_flight_sessions.load(Ordering::Relaxed),
            0,
            "InFlightGuard MUST decrement even when the handler panics"
        );
    }

    #[test]
    fn in_flight_guard_concurrent_enter_and_drop() {
        // Stress: spawn 64 threads that each construct + drop a guard;
        // the gauge must wind back to 0.
        let server = Arc::new(ServerMetrics::default());
        let mut handles = Vec::new();
        for _ in 0..64 {
            let s = Arc::clone(&server);
            handles.push(std::thread::spawn(move || {
                let _g = InFlightGuard::enter(s, Arc::new(SessionMetrics::default()));
                std::thread::yield_now();
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(server.in_flight_sessions.load(Ordering::Relaxed), 0);
    }
}
