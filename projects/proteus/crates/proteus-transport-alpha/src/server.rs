//! α-profile server driver.

use std::sync::Arc;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::log_throttle::{AcquireResult, Throttle};

// ────────────────────────────────────────────────────────────────
// Per-call-site log throttles for rejection paths in the accept
// loop. Without these, a scanner / DoS prober hammering at 1000
// conn/sec floods journald with one warn line each — 3.6M lines/hr
// is enough to fill `/var/log/journal` on a small VPS, AND once
// journald's own rate-limit kicks in (SystemMaxFileSize hit) it
// drops legitimate operational warnings alongside the noise.
// See `crate::log_throttle` for the design rationale.
//
// Configured as 10-burst + 1 line/sec steady-state per site, so:
//   * a small misconfig spike emits all events cleanly,
//   * a sustained scanner pays at most 1 line/sec/site,
//   * the periodic rollup task (in the binary main) emits the
//     "(suppressed N in last 60s)" line so the suppression count
//     itself is visible to operators.
fn firewall_denied_throttle() -> &'static Throttle {
    static T: OnceLock<Throttle> = OnceLock::new();
    T.get_or_init(|| Throttle::new(10, 1.0))
}
fn handshake_budget_exhausted_throttle() -> &'static Throttle {
    static T: OnceLock<Throttle> = OnceLock::new();
    T.get_or_init(|| Throttle::new(10, 1.0))
}
fn max_connections_throttle() -> &'static Throttle {
    static T: OnceLock<Throttle> = OnceLock::new();
    T.get_or_init(|| Throttle::new(10, 1.0))
}

/// Snapshot of all per-site rejection-log throttles, for the
/// metrics endpoint to expose suppression counts. Returns a
/// vector of `(site_label, total_allowed, total_suppressed)`.
#[must_use]
pub fn rejection_log_throttle_snapshot() -> Vec<(&'static str, u64, u64)> {
    vec![
        (
            "firewall_denied",
            firewall_denied_throttle().total_allowed(),
            firewall_denied_throttle().total_suppressed(),
        ),
        (
            "handshake_budget_exhausted",
            handshake_budget_exhausted_throttle().total_allowed(),
            handshake_budget_exhausted_throttle().total_suppressed(),
        ),
        (
            "max_connections_reached",
            max_connections_throttle().total_allowed(),
            max_connections_throttle().total_suppressed(),
        ),
    ]
}

/// Drain every rejection-log throttle's
/// suppressed-since-last-rollup counter atomically. Returns
/// `(site_label, suppressed_count)` pairs for any site with
/// non-zero count. The binary's periodic rollup task calls this
/// every 60 s and emits one `warn!` per non-zero entry.
#[must_use]
pub fn rejection_log_throttle_drain_rollups() -> Vec<(&'static str, u64)> {
    let mut out = Vec::new();
    let pairs: &[(&'static str, &dyn Fn() -> &'static Throttle)] = &[
        ("firewall_denied", &firewall_denied_throttle),
        (
            "handshake_budget_exhausted",
            &handshake_budget_exhausted_throttle,
        ),
        ("max_connections_reached", &max_connections_throttle),
    ];
    for (label, getter) in pairs {
        let n = getter().roll_up();
        if n > 0 {
            out.push((*label, n));
        }
    }
    out
}

/// Render the rejection-log-throttle counters as a Prometheus
/// exposition block. Two labelled series — `proteus_log_throttle_allowed_total{site="..."}`
/// and `_suppressed_total` — so operators alert on
/// `rate(proteus_log_throttle_suppressed_total[5m]) > 0` to
/// detect a sustained scanner / DoS hammer on a hot path.
#[must_use]
pub fn rejection_log_throttle_prometheus() -> String {
    let mut s = String::with_capacity(512);
    s.push_str(
        "# HELP proteus_log_throttle_allowed_total Per-call-site count of WARN lines that the per-site throttle admitted to the log. Pairs with proteus_log_throttle_suppressed_total — the ratio reflects how often the site was flooded.\n\
         # TYPE proteus_log_throttle_allowed_total counter\n",
    );
    for (site, allowed, _) in rejection_log_throttle_snapshot() {
        s.push_str(&format!(
            "proteus_log_throttle_allowed_total{{site=\"{site}\"}} {allowed}\n"
        ));
    }
    s.push_str(
        "# HELP proteus_log_throttle_suppressed_total Per-call-site count of WARN lines suppressed by the in-process log throttle (would-have-fired-without-throttle minus admitted). Alert on rate(...[5m]) > 0 to spot scanner / DoS hammers.\n\
         # TYPE proteus_log_throttle_suppressed_total counter\n",
    );
    for (site, _, suppressed) in rejection_log_throttle_snapshot() {
        s.push_str(&format!(
            "proteus_log_throttle_suppressed_total{{site=\"{site}\"}} {suppressed}\n"
        ));
    }
    s
}

use ml_kem::kem::DecapsulationKey;
use ml_kem::{EncodedSizeUser, MlKem768Params};
use proteus_crypto::{
    aead::AeadSuite,
    kex,
    key_schedule::{self, Transcript},
};
use proteus_handshake::{auth_tag, replay::ReplayWindow, replay::Verdict, state::State};
use proteus_spec::{
    AEAD_SUITE_MASK_AES_256_GCM, AEAD_SUITE_MASK_CHACHA20_POLY1305, PROTEUS_VERSION_V10,
    PROTEUS_VERSION_V11,
};
use proteus_wire::{alpha, AuthExtension, ProfileHint};
use tokio::io::AsyncWriteExt;
#[allow(unused_imports)]
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::error::{AlphaError, AlphaResult};
use crate::session::AlphaSession;

fn client_signature_input(ext: &AuthExtension) -> Vec<u8> {
    let mut message = Vec::with_capacity(1 + 1 + 2 + 16 + 32 + 1088);
    message.push(ext.version);
    if ext.version == PROTEUS_VERSION_V11 {
        message.push(ext.profile_hint.to_byte());
        message.extend_from_slice(&ext.aead_suite_mask.to_be_bytes());
    }
    message.extend_from_slice(&ext.client_nonce);
    message.extend_from_slice(&ext.client_x25519_pub);
    message.extend_from_slice(&ext.client_mlkem768_ct);
    message
}

fn select_aead_suite(ext: &AuthExtension) -> AlphaResult<AeadSuite> {
    if ext.version == PROTEUS_VERSION_V10 {
        return Ok(AeadSuite::ChaCha20Poly1305);
    }
    if ext.version != PROTEUS_VERSION_V11 {
        return Err(AlphaError::Closed);
    }
    if ext.aead_suite_mask & AEAD_SUITE_MASK_AES_256_GCM != 0 {
        return Ok(AeadSuite::Aes256Gcm);
    }
    if ext.aead_suite_mask & AEAD_SUITE_MASK_CHACHA20_POLY1305 != 0 {
        return Ok(AeadSuite::ChaCha20Poly1305);
    }
    Err(AlphaError::Closed)
}

fn server_hello_body(version: u8, server_x25519_eph_pub: &[u8; 32], suite: AeadSuite) -> Vec<u8> {
    let mut body = Vec::with_capacity(if version == PROTEUS_VERSION_V11 {
        33
    } else {
        32
    });
    body.extend_from_slice(server_x25519_eph_pub);
    if version == PROTEUS_VERSION_V11 {
        body.push(suite.code());
    }
    body
}

/// Server long-term key material.
pub struct ServerKeys {
    /// ML-KEM-768 decapsulation key.
    pub mlkem_sk: DecapsulationKey<MlKem768Params>,
    /// ML-KEM-768 EK bytes — published to clients out of band.
    pub mlkem_pk_bytes: Vec<u8>,
    /// Server PQ fingerprint = SHA-256 of mlkem_pk_bytes.
    pub pq_fingerprint: [u8; 32],
    /// X25519 long-term secret (we use a single static ephemeral pair for
    /// M1; full v1.0 spec mandates fresh per session, M2 will switch).
    pub x25519_sk: StaticSecret,
    /// Corresponding X25519 public key.
    pub x25519_pub: [u8; 32],
    /// Allowed client Ed25519 verifying keys (allowlist by `user_id`).
    pub client_allowlist: Vec<([u8; 8], ed25519_dalek::VerifyingKey)>,
    /// Server-side AEAD key for the `client_id` field.
    ///
    /// Iter-173: wrapped in `Zeroizing` so the key bytes scrub
    /// when `ServerKeys` drops (process exit / SIGHUP-rebuild
    /// path). The key is HKDF-derived deterministically from
    /// the server's ML-KEM public-key fingerprint, so the same
    /// 32 bytes decrypt the `client_id` field of EVERY captured
    /// handshake against this server — recovering it via a
    /// process-image grab = a perpetual user-id-decryption
    /// capability until the operator rotates the server's ML-KEM
    /// long-term key. Wrapping the long-lived storage in
    /// Zeroizing closes the matching residue on the server side
    /// to the iter-173 client-side `cid_key` fix.
    pub client_id_aead_key: zeroize::Zeroizing<[u8; 32]>,
}

impl ServerKeys {
    /// Generate a fresh complete key set for tests / demo.
    #[must_use]
    pub fn generate() -> Self {
        use ml_kem::KemCore;
        let mut rng = rand_core::OsRng;
        let (mlkem_sk, mlkem_pk) = ml_kem::MlKem768::generate(&mut rng);
        let mlkem_pk_bytes = mlkem_pk.as_bytes().to_vec();
        let pq_fingerprint = key_schedule::sha256(&mlkem_pk_bytes);

        let x25519_sk = StaticSecret::random_from_rng(rng);
        let x25519_pub = XPublicKey::from(&x25519_sk).to_bytes();

        // Derive a deterministic client_id key from the PQ fingerprint —
        // matches what the client does (spec §5.7.1).
        let mut client_id_aead_key = Zeroizing::new([0u8; 32]);
        proteus_crypto::kdf::expand_label(
            &pq_fingerprint,
            b"proteus-cid-key-v1",
            b"",
            &mut *client_id_aead_key,
        )
        .expect("hkdf");

        Self {
            mlkem_sk,
            mlkem_pk_bytes,
            pq_fingerprint,
            x25519_sk,
            x25519_pub,
            client_allowlist: Vec::new(),
            client_id_aead_key,
        }
    }

    /// Authorize a client by long-term Ed25519 verifying key under `user_id`.
    pub fn allow(&mut self, user_id: [u8; 8], pk: ed25519_dalek::VerifyingKey) {
        self.client_allowlist.push((user_id, pk));
    }
}

/// Outcome of [`ServerCtx::try_acquire_connection`].
pub enum ConnGate {
    /// No `max_connections` configured — proceed unconditionally.
    Unbounded,
    /// Limit configured and a slot was free. Hold this permit for
    /// the lifetime of the connection; dropping it releases the slot.
    Allowed(tokio::sync::OwnedSemaphorePermit),
    /// Limit configured and the cap is hit. The caller MUST route the
    /// connection to cover (or drop it).
    Rejected,
}

/// Hot-path admission check: returns `false` if the connection should
/// be routed to cover (and the loop should `continue`), `true` if the
/// connection may proceed to handshake.
///
/// Order matches the spec admission pipeline:
/// 1. CIDR firewall (cheapest, configured by operator).
/// 2. Global handshake budget (fleet-wide cap).
/// 3. Per-IP rate limiter.
/// 4. (Caller handles max_connections separately because it needs to
///    hold a permit through the spawned task.)
///
/// `pub` so the β QUIC accept loop can reuse the exact same gate.
/// Keep one canonical admission pipeline — never re-implement it
/// in the β crate, or the two will drift.
pub fn admission_ok(ctx: &Arc<ServerCtx>, peer: &std::net::SocketAddr) -> bool {
    // TTL-bounded auto-deny check FIRST — cheaper than the firewall
    // snapshot, and probe-anomaly-flagged prefixes shouldn't even
    // pay the firewall lookup cost. Disabled when the operator
    // hasn't wired the auto-deny list (the common case for
    // small/personal deploys); short-circuit on `is_enabled = false`
    // makes the unwired path effectively free.
    if let Some(auto_deny) = ctx.auto_deny() {
        if auto_deny.is_denied(peer.ip(), std::time::Instant::now()) {
            tracing::debug!(
                peer = %peer,
                "auto-deny hit (probe-anomaly /24 within TTL); routing to cover"
            );
            if let Some(m) = ctx.metrics() {
                m.firewall_denied
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            return false;
        }
    }
    // Single snapshot of the firewall — atomic across the is_active +
    // admit pair so a concurrent SIGHUP reload can't observe us with a
    // stale "active" flag and a fresh "admit" result. Cloning the
    // ReloadableFirewall handle is one Arc::clone (cheap); reading the
    // snapshot acquires the read-lock once.
    let fw = ctx.firewall();
    let fw_snap = fw.snapshot();
    if fw_snap.is_active() && !fw_snap.admit(peer.ip()) {
        if matches!(
            firewall_denied_throttle().try_acquire(),
            AcquireResult::Allowed
        ) {
            tracing::warn!(peer = %peer, "firewall denied; routing to cover");
        }
        if let Some(m) = ctx.metrics() {
            m.firewall_denied
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        return false;
    }
    // Global handshake budget. Independent of per-IP — caps fleet-wide
    // hands per second so a botnet that stays under each per-IP
    // ceiling still can't exhaust the ML-KEM-decap CPU budget.
    if !ctx.check_handshake_budget() {
        if matches!(
            handshake_budget_exhausted_throttle().try_acquire(),
            AcquireResult::Allowed
        ) {
            tracing::warn!(
                peer = %peer,
                "global handshake budget exhausted; routing to cover"
            );
        }
        if let Some(m) = ctx.metrics() {
            m.handshake_budget_rejected
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        return false;
    }
    if !ctx.check_rate_limit(peer.ip()) {
        tracing::debug!(peer = %peer, "rate-limited; routing to cover");
        if let Some(m) = ctx.metrics() {
            m.rate_limited
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        return false;
    }
    true
}

/// Post-handshake admission check: returns `true` if the session may
/// proceed to `handle()`, `false` if the per-user limit was hit. The
/// caller MUST drop the session on `false` (the TLS / Proteus
/// transport is already established, so there's no way to route to
/// cover at this point — we just close cleanly with a CLOSE record).
///
/// `pub` so β can reuse the same per-user policy.
pub fn user_admission_ok<R, W>(ctx: &Arc<ServerCtx>, session: &AlphaSession<R, W>) -> bool
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let Some(uid) = session.user_id else {
        return true; // no allowlist configured → no user-rate check
    };
    // Auto-quarantine check FIRST — if the user_id is currently
    // banned, short-circuit before the rate-limiter sees it.
    // Reasons it's first: (1) quarantine is a strictly-stronger
    // denial than rate-limit (banned vs. throttled), (2) checking
    // it first avoids counting a quarantined user's attempts
    // against their rate-limit bucket (would inflate the
    // rate_limit detector's view of the burst).
    if let Some(qlist) = ctx.user_quarantine() {
        if let Some(remaining) = qlist.check(&uid) {
            tracing::warn!(
                user_id = ?uid,
                peer = ?session.peer_addr,
                remaining_secs = remaining,
                "user_id auto-quarantined; closing session"
            );
            if let Some(m) = ctx.metrics() {
                m.user_quarantine_rejected
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            return false;
        }
    }
    // Period-based data quota check. Same priority slot as the
    // quarantine: hard-denial that shouldn't burn rate-limit
    // tokens. Operators reading dashboards see "alice is over her
    // 100 GB monthly cap; reject until next period rollover (or
    // operator reset)".
    if let Some(quota) = ctx.user_quota() {
        if quota.is_over_quota(&uid) {
            tracing::warn!(
                user_id = ?uid,
                peer = ?session.peer_addr,
                "user_id over period quota; closing session"
            );
            if let Some(m) = ctx.metrics() {
                m.user_quota_admission_rejected
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            return false;
        }
    }
    if ctx.check_user_rate(&uid) {
        return true;
    }
    tracing::warn!(
        user_id = ?uid,
        peer = ?session.peer_addr,
        "per-user rate limit exceeded; closing session"
    );
    if let Some(m) = ctx.metrics() {
        m.user_rate_rejected
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    // Anomaly aggregation: repeated rate-limit hits from the same
    // user_id are a credential-abuse signal (legitimate clients
    // rarely sustain the rate; bots / misconfigured clients do).
    // Fire-once-per-burst via the sliding-window detector.
    if let Some(detector) = ctx.abuse_detector_rate_limit() {
        if detector.record(uid) {
            tracing::warn!(
                user_id = ?uid,
                peer = ?session.peer_addr,
                "abuse: user repeatedly tripping per-user rate limit — \
                 likely misconfigured client or shared/leaked credential"
            );
            if let Some(m) = ctx.metrics() {
                m.abuse_alerts_rate_limit
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            // Push a record into the recent-fires ring buffer so
            // operators can ask "which user_id?" without grepping
            // journald.
            if let Some(buf) = ctx.abuse_fires() {
                buf.push(crate::abuse_fires::AbuseFireKind::RateLimit, uid, 0);
            }
            // Auto-quarantine on rate_limit fire, if the operator
            // has opted this kind in. The detector already fires
            // once-per-burst (sliding-window threshold), so this is
            // a single-touch path; no need for a separate fire-
            // count threshold on top.
            if ctx.should_quarantine_on(crate::abuse_fires::AbuseFireKind::RateLimit.as_label()) {
                if let Some(qlist) = ctx.user_quarantine() {
                    let inserted =
                        qlist.insert(uid, crate::abuse_fires::AbuseFireKind::RateLimit.as_label());
                    if inserted {
                        tracing::warn!(
                            user_id = ?uid,
                            ttl_secs = qlist.ttl().as_secs(),
                            "auto-quarantine: user_id banned for TTL on rate_limit abuse fire"
                        );
                    }
                }
            }
        }
    }
    false
}

/// Helper used by every accept loop: spawn a cover-forward task that
/// splices `stream` to `ctx.cover_endpoint` (if configured), otherwise
/// drop the stream. Idempotent + non-blocking.
fn route_to_cover_or_drop(ctx: &Arc<ServerCtx>, stream: TcpStream, peer: &std::net::SocketAddr) {
    record_probe_anomaly(ctx, peer);
    if let Some(cover) = ctx.cover_endpoint_for(peer) {
        // Iter-20: acquire a cover-forward semaphore slot BEFORE
        // the spawn so a probe storm can't fan out unbounded
        // tokio::spawn(forward_to_cover) tasks that each hold 2
        // FDs for up to FORWARD_IDLE_TIMEOUT (120s).
        //
        // try_acquire_cover_forward returns:
        //   Some(Some(permit)) → cap configured, slot acquired
        //   Some(None)         → no cap (legacy unbounded mode)
        //   None               → cap configured, exhausted → drop
        let permit_opt = match ctx.try_acquire_cover_forward() {
            Some(p) => p,
            None => {
                // Cover cap exhausted — drop the inbound stream
                // (TCP RST/FIN) and bump the rejection counter.
                // Operators alert on
                // `rate(proteus_cover_forwards_rejected_total[5m]) > 0`.
                if let Some(m) = ctx.metrics() {
                    m.cover_forwards_rejected
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                // Throttled WARN so a sustained probe storm doesn't
                // flood the log; the rejection counter is the
                // primary operator signal.
                if matches!(
                    cover_forward_throttle().try_acquire(),
                    AcquireResult::Allowed
                ) {
                    tracing::warn!(
                        peer = %peer,
                        "cover-forward semaphore exhausted — dropping inbound (operator should \
                         either raise `max_cover_forwards` or investigate the cover endpoint's \
                         response latency)"
                    );
                }
                return;
            }
        };
        let metrics = ctx.metrics().cloned();
        tokio::spawn(async move {
            // _permit held for the duration of the cover task;
            // dropped on exit releases the semaphore slot.
            let _permit = permit_opt;
            let r = crate::cover::forward_to_cover(&cover, Vec::new(), stream).await;
            if r.is_ok() {
                if let Some(m) = metrics {
                    m.cover_forwards
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
        });
    }
    // Else: stream drops here, TCP RST/FIN closes silently.
}

/// Per-process throttle for the cover-forward-rejection WARN log.
/// Same shape as `accept_error_throttle` (iter-18) — a sustained
/// probe storm fires the rejection path hundreds of times per
/// second; we want one log line every ~5 seconds, not a flood
/// that becomes its own resource pressure source.
fn cover_forward_throttle() -> &'static Throttle {
    static T: OnceLock<Throttle> = OnceLock::new();
    T.get_or_init(|| Throttle::new(3, 0.2))
}

/// Record one cover-forward event in the probe-anomaly detector (if
/// installed). On the call that crosses the per-/24 threshold,
/// emits a structured WARN log + bumps the
/// `probe_anomalies_fired` Prometheus counter. Pure CPU; safe to
/// call from any context.
fn record_probe_anomaly(ctx: &Arc<ServerCtx>, peer: &std::net::SocketAddr) {
    let Some(detector) = ctx.probe_anomaly() else {
        return;
    };
    let now = std::time::Instant::now();
    if detector.record_at(peer.ip(), now).is_some() {
        // Threshold crossed for this /24 — surface the signal.
        tracing::warn!(
            peer = %peer,
            prefix = match peer.ip() {
                std::net::IpAddr::V4(_) => "/24",
                std::net::IpAddr::V6(_) => "/48",
            },
            "probe-anomaly: source-IP prefix repeatedly tripping cover-forward — \
             likely active probing (threat-intel main line 4)"
        );
        if let Some(m) = ctx.metrics() {
            m.probe_anomalies_fired
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        // Auto-deny: when the operator has wired a TTL-bounded
        // deny list, the anomaly fire is exactly the moment to
        // blackhole the offending /24. The list silently no-ops
        // when not configured.
        if let Some(auto_deny) = ctx.auto_deny() {
            let inserted = auto_deny.insert(peer.ip(), now);
            if inserted {
                tracing::warn!(
                    peer = %peer,
                    ttl_secs = auto_deny.ttl().as_secs(),
                    "auto-deny: prefix added to TTL-bounded deny list"
                );
            }
        }
    }
}

/// Per-server state shared across connections.
pub struct ServerCtx {
    keys: ServerKeys,
    replay: Mutex<ReplayWindow>,
    /// Optional cover endpoint (`host:port`) for auth-fail forwarding.
    /// Cover-forwarding endpoint(s) per spec §7.5 + 2026 threat-intel
    /// main line 4. When set, every auth-failed connection is byte-
    /// spliced to one of the configured endpoints.
    ///
    /// Wrapped in `CoverEndpointPool` so single-endpoint and pool
    /// configurations share one type. Single-endpoint = pool of
    /// size 1; pool of size N applies per-source-IP /24 (v4) or
    /// /48 (v6) affinity — same peer always sees the same cover URL
    /// across repeated probes (defeats time-series active probing
    /// that a single observer can mount; see `cover_pool.rs` design
    /// rationale for the trade-off vs. cross-observer correlation).
    cover_endpoint: Option<crate::cover_pool::CoverEndpointPool>,
    /// Optional sliding-window probe-anomaly detector that counts
    /// cover-forwards per source-IP /24 (v4) / /48 (v6) prefix and
    /// fires a structured WARN log + Prometheus counter increment
    /// when any single prefix crosses the configured threshold.
    /// Companion defense to `cover_pool`: the pool defeats the
    /// time-series-rotation signal; this detector defeats the
    /// probe-volume signal. See `probe_anomaly.rs` for the rationale.
    /// When `None`, anomaly detection is disabled — operator opts in
    /// via `with_probe_anomaly_detector()`.
    probe_anomaly: Option<Arc<crate::probe_anomaly::ProbeAnomalyDetector>>,
    /// Optional TTL-bounded auto-deny list. When configured, probe-
    /// anomaly fires insert the offending /24 (v4) / /48 (v6) into
    /// this list with the configured TTL; `admission_ok` consults
    /// it BEFORE the firewall snapshot so denied connections short-
    /// circuit at the cheapest possible point. Entries self-expire
    /// after the TTL — transient false positives heal automatically
    /// without operator intervention. Operator opt-in via
    /// `probe_anomaly.autodeny_minutes > 0` in `server.yaml`.
    auto_deny: Option<Arc<crate::auto_deny::AutoDenyList>>,
    /// Optional per-source-IP rate limiter.
    rate_limiter: Option<crate::rate_limit::RateLimiter>,
    /// Maximum time to spend on a single handshake before giving up
    /// (slowloris defense).
    handshake_deadline: std::time::Duration,
    /// TCP socket-level keepalive interval applied to every accepted
    /// connection.
    tcp_keepalive_secs: u64,
    /// Required anti-DoS proof-of-work difficulty in leading-zero bits
    /// of `SHA-256(server_pq_fingerprint || client_nonce || solution)`.
    /// 0 = disabled. Operators raise this under DoS alert.
    pow_difficulty: u8,
    /// Optional shared metrics handle for hot-path counters (cover
    /// forwards, rate-limit drops, handshake timeouts).
    metrics: Option<Arc<crate::metrics::ServerMetrics>>,
    /// Optional bounded-concurrency semaphore. When set, the server
    /// will hold at most `max_connections` simultaneous accepted
    /// connections (a hard cap, evaluated **before** the handshake
    /// begins). Connections that would exceed this cap are routed
    /// straight to the cover endpoint or dropped.
    ///
    /// Production deployments SHOULD set this — without it, a SYN
    /// flood that survives the rate limiter can still OOM the
    /// server by parking unbounded per-connection ML-KEM allocations.
    conn_limit: Option<Arc<tokio::sync::Semaphore>>,
    /// β multiplexing needs a session cap distinct from the outer
    /// QUIC-carrier cap. Otherwise one admitted carrier could open
    /// an unbounded number of independently buffered Proteus
    /// sessions and bypass `max_connections`.
    ///
    /// `with_max_connections(n)` installs both semaphores at the
    /// same capacity: at most `n` live carriers and at most `n`
    /// live β sessions process-wide. α continues to use only the
    /// carrier semaphore because one TCP connection is one session.
    beta_session_limit: Option<Arc<tokio::sync::Semaphore>>,
    /// Optional bounded-concurrency semaphore for the cover-forward
    /// path (iter-20). When set, AT MOST this many cover-forward
    /// tasks run simultaneously across the entire process; further
    /// rejected connections are dropped (TCP RST/FIN) instead of
    /// being spliced to cover.
    ///
    /// Why this exists: pre-iter-20, `route_to_cover_or_drop`
    /// (the firewall-rejected / conn-cap-rejected / admission-
    /// failed path) called `tokio::spawn(forward_to_cover(...))`
    /// with NO concurrency cap. Each spawned task holds 2 FDs
    /// (peer + cover upstream) for up to FORWARD_IDLE_TIMEOUT
    /// (120s). Under a probe storm — 1000 probes/sec is realistic
    /// for an exposed VPS once a censorship-scanner notices it —
    /// 120 000 concurrent cover tasks ≈ 240 000 FDs, which hits
    /// EMFILE almost immediately even with `ulimit -n 1048576`.
    /// Iter-18 made the accept loop SURVIVE EMFILE; iter-20
    /// prevents reaching EMFILE via the cover path in the first
    /// place.
    ///
    /// `None` (default): no cap — preserves the legacy behavior
    /// for operators who already deploy behind a separate L4
    /// rate-limiter / scrubber. Anyone running an exposed VPS
    /// SHOULD set this; sensible value is `max_connections * 4`
    /// (most cover-forwards exit in <2s, so a 4× headroom over
    /// the in-flight session count covers normal bursts).
    cover_forward_limit: Option<Arc<tokio::sync::Semaphore>>,
    /// Source-IP firewall (CIDR allow/deny). Evaluated before the
    /// rate limiter. Wrapped in [`crate::firewall::ReloadableFirewall`]
    /// so SIGHUP can swap in updated rules without disturbing
    /// in-flight sessions. An empty firewall is a no-op on the hot
    /// path (one RwLock read, then short-circuit return).
    firewall: crate::firewall::ReloadableFirewall,
    /// Optional global handshake budget — a single shared token bucket
    /// keyed on `()` that caps **total** completed handshakes across
    /// every source. Independent of the per-IP limiter and
    /// `max_connections`: protects against fleet-wide handshake
    /// flooding where each IP stays under its limit.
    handshake_budget: Option<Arc<crate::rate_limit::KeyedRateLimiter<()>>>,
    /// Optional per-user rate limiter. Keyed on the 8-byte user_id
    /// matched during handshake. Layered on top of the per-IP limit
    /// so CGNAT'd clients each get their own budget.
    user_limiter: Option<Arc<crate::rate_limit::KeyedRateLimiter<[u8; 8]>>>,
    /// Optional sliding-window abuse detector for the per-user rate
    /// limit. Fires (once per burst) when the same user_id trips
    /// `user_rate_rejected` `threshold` times within `window`. Sibling
    /// to the byte-budget detector wired in the relay.
    abuse_detector_rate_limit: Option<Arc<crate::abuse_detector::AbuseDetector>>,
    /// Optional per-user bandwidth accumulator. When set,
    /// `InFlightGuard::drop` ALSO records this session's
    /// `(tx_bytes, rx_bytes)` against the user_id matched at
    /// handshake. Operators see real-time per-tenant bandwidth via
    /// `proteus_per_user_bytes_{sent,received}_total{user_id="…"}`
    /// on `/metrics`. None = feature disabled (back-compat).
    per_user_bandwidth: Option<Arc<crate::per_user_bandwidth::PerUserBandwidth>>,
    /// Optional per-user concurrent-session cap. When set, the
    /// session-handler closure consults `try_acquire(user_id)` AFTER
    /// the handshake completes (and user_id is known) but BEFORE
    /// the relay opens upstream — a user already at the cap gets
    /// their session torn down cleanly with the rejection counter
    /// bumped. Mirrors the commercial-VPN "N devices per account"
    /// model that VLESS / Hy2 / TUIC5 lack at the protocol level.
    per_user_conn_limiter: Option<Arc<crate::per_user_conn_limit::PerUserConnLimiter>>,
    /// Optional per-user period-based data quota tracker. When set,
    /// the post-handshake admission gate ALSO rejects sessions
    /// whose user_id is over quota for the current period. Closes
    /// the gap left by the rate / event detectors: a patient
    /// attacker who stays under any single-session or rate
    /// threshold can drain TBs over weeks; the quota tracker puts
    /// a hard ceiling on cumulative bytes.
    user_quota: Option<Arc<crate::user_quota::PerUserQuotaTracker>>,
    /// Optional ring buffer of recent abuse-alert fires (across all
    /// three detectors: byte_budget, rate_limit,
    /// per_user_bandwidth_rate). Filled at each fire site so
    /// operators can answer "WHICH user_id fired alerts in the last
    /// 5 minutes" without grepping journald. Surfaced via
    /// `/metrics` (capacity + count gauges), `/diagnose` (table),
    /// and `admin abuse-fires` (CLI text/JSON).
    abuse_fires: Option<Arc<crate::abuse_fires::AbuseFireBuffer>>,
    /// Optional auto-quarantine list — TTL-bounded HashMap of
    /// user_ids currently denied at the post-handshake admission
    /// gate. Populated by abuse-fire push sites (relay byte_budget,
    /// server rate_limit, per-user bandwidth-rate drop hook) when
    /// the operator has opted those detector kinds into auto-
    /// quarantine via `quarantine_on_kinds`. Drained by TTL.
    user_quarantine: Option<Arc<crate::user_quarantine::UserQuarantineList>>,
    /// Set of abuse-fire kinds that should trigger an immediate
    /// quarantine insert. Empty set = quarantine wired but no
    /// detector kinds opted in (the list still admits queries via
    /// /metrics + /diagnose so operators see "feature ready,
    /// nothing fired into it yet").
    ///
    /// Default-empty so an operator who installs the quarantine
    /// list without opting any kinds in gets the observability
    /// surface but no enforcement until they explicitly opt a kind
    /// in. Defense against operator surprise.
    quarantine_on_kinds: std::collections::HashSet<&'static str>,
}

impl ServerCtx {
    /// Wrap the given keys into a server context.
    #[must_use]
    pub fn new(keys: ServerKeys) -> Self {
        Self {
            keys,
            replay: Mutex::new(ReplayWindow::new()),
            cover_endpoint: None,
            probe_anomaly: None,
            auto_deny: None,
            rate_limiter: None,
            handshake_deadline: std::time::Duration::from_secs(15),
            tcp_keepalive_secs: 30,
            pow_difficulty: 0,
            metrics: None,
            conn_limit: None,
            beta_session_limit: None,
            cover_forward_limit: None,
            firewall: crate::firewall::ReloadableFirewall::default(),
            handshake_budget: None,
            user_limiter: None,
            abuse_detector_rate_limit: None,
            per_user_bandwidth: None,
            per_user_conn_limiter: None,
            user_quota: None,
            abuse_fires: None,
            user_quarantine: None,
            quarantine_on_kinds: std::collections::HashSet::new(),
        }
    }

    /// Install the per-user period-based data quota tracker.
    /// When wired, the post-handshake admission gate rejects any
    /// session whose user_id is over quota for the current period.
    #[must_use]
    pub fn with_user_quota(mut self, tracker: Arc<crate::user_quota::PerUserQuotaTracker>) -> Self {
        self.user_quota = Some(tracker);
        self
    }

    /// Read the user-quota tracker handle.
    #[must_use]
    pub fn user_quota(&self) -> Option<Arc<crate::user_quota::PerUserQuotaTracker>> {
        self.user_quota.clone()
    }

    /// Install the auto-quarantine list. Operators who want abuse
    /// fires to AUTOMATICALLY ban a user_id for a TTL (instead of
    /// just observing them in the recent-fires ring) wire this in
    /// addition to opting kinds in via [`Self::with_quarantine_on_kinds`].
    #[must_use]
    pub fn with_user_quarantine(
        mut self,
        list: Arc<crate::user_quarantine::UserQuarantineList>,
    ) -> Self {
        self.user_quarantine = Some(list);
        self
    }

    /// Opt the supplied abuse-fire kinds into auto-quarantine. Each
    /// label must be one of `byte_budget`, `rate_limit`,
    /// `per_user_bandwidth_rate` (matches
    /// `AbuseFireKind::as_label()`). Unknown kinds are stored
    /// silently (no enforcement; harmless), so adding new fire
    /// kinds in the future doesn't break this builder.
    ///
    /// Operators who only want to quarantine on the strongest
    /// signal (`per_user_bandwidth_rate`) pass just that one and
    /// leave the noisier event-based kinds out — the latter still
    /// fire alerts + push into the ring, just don't enforce.
    #[must_use]
    pub fn with_quarantine_on_kinds<I: IntoIterator<Item = &'static str>>(
        mut self,
        kinds: I,
    ) -> Self {
        for k in kinds {
            self.quarantine_on_kinds.insert(k);
        }
        self
    }

    /// Read the auto-quarantine list handle.
    #[must_use]
    pub fn user_quarantine(&self) -> Option<Arc<crate::user_quarantine::UserQuarantineList>> {
        self.user_quarantine.clone()
    }

    /// Returns `true` when fires of `kind` should trigger an
    /// auto-quarantine insert. Used by the abuse-fire push sites.
    #[must_use]
    pub fn should_quarantine_on(&self, kind: &str) -> bool {
        self.quarantine_on_kinds.contains(kind)
    }

    /// Install a recent-abuse-fires ring buffer. When wired, the
    /// three detector call sites (byte_budget, rate_limit,
    /// per_user_bandwidth_rate) push a record on every fire. The
    /// buffer is bounded by its capacity — operators query it via
    /// `/diagnose` or `admin abuse-fires` for the WHO of every
    /// alert, not just the THAT.
    #[must_use]
    pub fn with_abuse_fires(mut self, buf: Arc<crate::abuse_fires::AbuseFireBuffer>) -> Self {
        self.abuse_fires = Some(buf);
        self
    }

    /// Read the abuse-fires ring buffer handle. Returns the cloneable
    /// Arc so consumers (relay, post-handshake rate gate, the
    /// per-user bandwidth accumulator's drop hook) can push without
    /// holding a borrow on the ctx.
    #[must_use]
    pub fn abuse_fires(&self) -> Option<Arc<crate::abuse_fires::AbuseFireBuffer>> {
        self.abuse_fires.clone()
    }

    /// Install a per-user concurrent-session limiter. Once set, every
    /// session whose user_id is already at the cap is rejected (with
    /// `proteus_per_user_conn_limit_rejected_total++`) instead of
    /// being relayed. See [`crate::per_user_conn_limit`] for the
    /// design rationale.
    #[must_use]
    pub fn with_per_user_conn_limiter(
        mut self,
        limiter: Arc<crate::per_user_conn_limit::PerUserConnLimiter>,
    ) -> Self {
        self.per_user_conn_limiter = Some(limiter);
        self
    }

    /// Read the per-user concurrent-session limiter handle. Returns
    /// the cloneable `Arc` so the binary's session-handler closure
    /// can call `try_acquire(user_id)` without holding a borrow on
    /// the `ServerCtx`.
    #[must_use]
    pub fn per_user_conn_limiter(
        &self,
    ) -> Option<Arc<crate::per_user_conn_limit::PerUserConnLimiter>> {
        self.per_user_conn_limiter.clone()
    }

    /// Install a per-user bandwidth accumulator. When set, every
    /// session-completion path records `(tx_bytes, rx_bytes)`
    /// against the session's user_id, exposed on `/metrics` via
    /// `proteus_per_user_bytes_{sent,received}_total{user_id="…"}`.
    #[must_use]
    pub fn with_per_user_bandwidth(
        mut self,
        accumulator: Arc<crate::per_user_bandwidth::PerUserBandwidth>,
    ) -> Self {
        self.per_user_bandwidth = Some(accumulator);
        self
    }

    /// Read the per-user bandwidth accumulator handle. Used by
    /// the session-completion path (`InFlightGuard` construction)
    /// AND the metrics endpoint (rendering the per-user series).
    pub fn per_user_bandwidth(&self) -> Option<&Arc<crate::per_user_bandwidth::PerUserBandwidth>> {
        self.per_user_bandwidth.as_ref()
    }

    /// Install a sliding-window abuse detector for the per-user
    /// rate limiter. Bursty rate-limit hits from the same user_id
    /// alert at the threshold and fire-once until the window empties.
    #[must_use]
    pub fn with_abuse_detector_rate_limit(
        mut self,
        detector: Arc<crate::abuse_detector::AbuseDetector>,
    ) -> Self {
        self.abuse_detector_rate_limit = Some(detector);
        self
    }

    /// Read the rate-limit abuse-detector handle.
    pub(crate) fn abuse_detector_rate_limit(
        &self,
    ) -> Option<&Arc<crate::abuse_detector::AbuseDetector>> {
        self.abuse_detector_rate_limit.as_ref()
    }

    /// Install a global handshake-budget limiter (single shared bucket).
    /// `capacity` is the burst size; `refill_per_sec` the steady-state
    /// rate. Caps **total** completed handshakes regardless of source.
    #[must_use]
    pub fn with_handshake_budget(mut self, capacity: f64, refill_per_sec: f64) -> Self {
        self.handshake_budget = Some(Arc::new(crate::rate_limit::KeyedRateLimiter::new(
            capacity,
            refill_per_sec,
            1,
        )));
        self
    }

    /// Install a per-user rate limiter keyed on the 8-byte user_id.
    /// `max_users` caps memory (one bucket per distinct user).
    #[must_use]
    pub fn with_user_rate_limit(
        mut self,
        capacity: f64,
        refill_per_sec: f64,
        max_users: usize,
    ) -> Self {
        self.user_limiter = Some(Arc::new(crate::rate_limit::KeyedRateLimiter::new(
            capacity,
            refill_per_sec,
            max_users,
        )));
        self
    }

    /// Try to consume one handshake-budget token from the global
    /// bucket. Returns `true` if allowed (or no budget configured).
    /// Called by the accept loop before paying the ML-KEM cost.
    pub fn check_handshake_budget(&self) -> bool {
        match &self.handshake_budget {
            Some(b) => b.check(&()),
            None => true,
        }
    }

    /// Try to consume one token from the per-user bucket. Returns
    /// `true` if allowed (or no per-user limiter configured). Called
    /// by the post-handshake admission shim once `user_id` is known.
    pub fn check_user_rate(&self, user_id: &[u8; 8]) -> bool {
        match &self.user_limiter {
            Some(l) => l.check(user_id),
            None => true,
        }
    }

    /// Vacuum idle per-user buckets (caller-driven, like the per-IP
    /// limiter). Caller should call on a 60-second cadence in
    /// production.
    pub fn vacuum_user_limit(&self) {
        if let Some(l) = &self.user_limiter {
            l.vacuum();
        }
    }

    /// Read the cumulative rejection count of the global handshake
    /// budget. Used by the exposition layer to emit a counter.
    #[must_use]
    pub fn handshake_budget_rejections(&self) -> u64 {
        self.handshake_budget
            .as_ref()
            .map_or(0, |b| b.rejection_count())
    }

    /// Read the cumulative rejection count of the per-user limiter.
    #[must_use]
    pub fn user_rate_rejections(&self) -> u64 {
        self.user_limiter
            .as_ref()
            .map_or(0, |l| l.rejection_count())
    }

    /// Install a source-IP firewall (CIDR allow/deny). Evaluated
    /// before the rate limiter; denied connections are routed to
    /// cover so the deny path stays REALITY-grade indistinguishable.
    /// Backed by a [`crate::firewall::ReloadableFirewall`] so the
    /// rules can later be swapped at runtime.
    #[must_use]
    pub fn with_firewall(mut self, fw: crate::firewall::Firewall) -> Self {
        self.firewall = crate::firewall::ReloadableFirewall::new(fw);
        self
    }

    /// Install an already-wrapped [`crate::firewall::ReloadableFirewall`].
    /// Use this when you need to hold a handle to call `.reload()`
    /// from a SIGHUP task.
    #[must_use]
    pub fn with_reloadable_firewall(mut self, fw: crate::firewall::ReloadableFirewall) -> Self {
        self.firewall = fw;
        self
    }

    /// Read the firewall handle. The accept loop uses this to gate
    /// every connection. Returns the cloneable handle, not a borrow,
    /// because the internal type is itself `Arc`-shared.
    #[must_use]
    pub fn firewall(&self) -> crate::firewall::ReloadableFirewall {
        self.firewall.clone()
    }

    /// Cap the maximum number of *in-flight* accepted connections.
    /// Connections beyond this cap are routed to the cover endpoint
    /// (if configured) or dropped silently. Set this to roughly
    /// `min(fd_ulimit / 4, RAM_MB * 1000)` — each in-flight handshake
    /// reserves ~16 KiB plus the ML-KEM scratch space.
    #[must_use]
    pub fn with_max_connections(mut self, n: usize) -> Self {
        self.conn_limit = Some(Arc::new(tokio::sync::Semaphore::new(n)));
        self.beta_session_limit = Some(Arc::new(tokio::sync::Semaphore::new(n)));
        self
    }

    /// Override the β inner-session cap independently from the
    /// outer carrier cap. Call after [`Self::with_max_connections`].
    /// Useful when a small carrier fleet intentionally multiplexes
    /// more logical sessions per connection.
    #[must_use]
    pub fn with_max_beta_sessions(mut self, n: usize) -> Self {
        self.beta_session_limit = Some(Arc::new(tokio::sync::Semaphore::new(n)));
        self
    }

    /// Set the maximum number of concurrent cover-forward tasks
    /// (iter-20). Caps the FD pressure from a probe storm — see
    /// the `cover_forward_limit` field doc for the threat model.
    ///
    /// Sensible production default: `max_connections * 4`. Most
    /// cover-forwards exit within ~2 s when the cover endpoint
    /// is healthy (real HTTPS reverse proxies serve a 200 / 404
    /// quickly), so a 4× headroom over the in-flight session
    /// count comfortably absorbs normal bursts while still
    /// preventing the unbounded-spawn class of FD exhaustion.
    ///
    /// `n = 0` is equivalent to "no cover-forward path at all" —
    /// every routed-to-cover connection is dropped (TCP RST). Use
    /// this only when the operator has decided cover forwarding
    /// is not desired (e.g. high-IP-reputation single-user deploys
    /// where any unauthenticated connection is suspicious enough
    /// to drop outright).
    #[must_use]
    pub fn with_max_cover_forwards(mut self, n: usize) -> Self {
        self.cover_forward_limit = Some(Arc::new(tokio::sync::Semaphore::new(n)));
        self
    }

    /// Try to acquire a cover-forward slot. Returns the owned
    /// permit on success — the caller MUST hold it for the
    /// duration of `forward_to_cover`. Returns `None` when the
    /// cap is exhausted (caller should drop the inbound stream).
    /// Returns `Some(None)` when no cap is configured (legacy
    /// unbounded behavior). Note the double-Option encodes the
    /// three-valued outcome `(unbounded | allowed | rejected)`
    /// without an extra enum to plumb through.
    #[allow(clippy::option_option)] // see doc above
    pub fn try_acquire_cover_forward(&self) -> Option<Option<tokio::sync::OwnedSemaphorePermit>> {
        match &self.cover_forward_limit {
            Some(sem) => match Arc::clone(sem).try_acquire_owned() {
                Ok(permit) => Some(Some(permit)),
                Err(_) => None, // rejected
            },
            None => Some(None), // unbounded
        }
    }

    /// Try to acquire a connection slot. Three-valued:
    /// - `ConnGate::Unbounded` — no limit configured, proceed.
    /// - `ConnGate::Allowed(permit)` — limit configured, slot acquired.
    ///   Drop the permit when the connection completes.
    /// - `ConnGate::Rejected` — limit exhausted; reject this connection.
    pub fn try_acquire_connection(&self) -> ConnGate {
        match &self.conn_limit {
            Some(sem) => match Arc::clone(sem).try_acquire_owned() {
                Ok(permit) => ConnGate::Allowed(permit),
                Err(_) => ConnGate::Rejected,
            },
            None => ConnGate::Unbounded,
        }
    }

    /// Try to acquire one β inner-session slot.
    ///
    /// This is deliberately separate from the outer QUIC carrier
    /// slot: pooling lets many streams share one carrier, but it
    /// must not let those streams evade the process-wide session
    /// memory ceiling.
    pub fn try_acquire_beta_session(&self) -> ConnGate {
        match &self.beta_session_limit {
            Some(sem) => match Arc::clone(sem).try_acquire_owned() {
                Ok(permit) => ConnGate::Allowed(permit),
                Err(_) => ConnGate::Rejected,
            },
            None => ConnGate::Unbounded,
        }
    }

    /// Whether a connection limit is configured.
    #[must_use]
    pub fn has_connection_limit(&self) -> bool {
        self.conn_limit.is_some()
    }

    /// Read the available permits for the connection limit (or
    /// `usize::MAX` when no limit is configured). Used by tests and
    /// the `/metrics` exposition.
    #[must_use]
    pub fn available_connection_slots(&self) -> usize {
        match &self.conn_limit {
            Some(sem) => sem.available_permits(),
            None => usize::MAX,
        }
    }

    /// Set the proof-of-work difficulty (0..=24). Higher = more client
    /// work per handshake attempt.
    #[must_use]
    pub fn with_pow_difficulty(mut self, d: u8) -> Self {
        self.pow_difficulty = d.min(24);
        self
    }

    /// Wire in a `ServerMetrics` so hot-path counters (cover forwards,
    /// rate-limit drops, handshake timeouts) are incremented.
    #[must_use]
    pub fn with_metrics(mut self, m: Arc<crate::metrics::ServerMetrics>) -> Self {
        self.metrics = Some(m);
        self
    }

    /// Read the required PoW difficulty.
    #[must_use]
    pub fn pow_difficulty(&self) -> u8 {
        self.pow_difficulty
    }

    /// Read the metrics handle (or `None`).
    #[must_use]
    pub fn metrics(&self) -> Option<&Arc<crate::metrics::ServerMetrics>> {
        self.metrics.as_ref()
    }

    /// Install a per-source-IP token-bucket rate limiter. Production
    /// deployments SHOULD configure this; the default is unlimited.
    #[must_use]
    pub fn with_rate_limiter(mut self, limiter: crate::rate_limit::RateLimiter) -> Self {
        self.rate_limiter = Some(limiter);
        self
    }

    /// Override the per-handshake deadline (default 15 s).
    #[must_use]
    pub fn with_handshake_deadline(mut self, d: std::time::Duration) -> Self {
        self.handshake_deadline = d;
        self
    }

    /// Override the TCP keepalive interval (default 30 s).
    #[must_use]
    pub fn with_tcp_keepalive_secs(mut self, s: u64) -> Self {
        self.tcp_keepalive_secs = s;
        self
    }

    /// Public accessor for handshake deadline.
    #[must_use]
    pub fn handshake_deadline(&self) -> std::time::Duration {
        self.handshake_deadline
    }

    /// Public accessor for TCP keepalive seconds.
    #[must_use]
    pub fn tcp_keepalive_secs(&self) -> u64 {
        self.tcp_keepalive_secs
    }

    /// Check the rate limit for `peer`. Returns `true` if allowed (or
    /// if no limiter is configured).
    pub fn check_rate_limit(&self, peer: std::net::IpAddr) -> bool {
        match &self.rate_limiter {
            Some(rl) => rl.check(peer),
            None => true,
        }
    }

    /// Hot-swap the per-IP rate-limit parameters. Returns `true` if a
    /// limiter is configured and the swap took effect, `false` if no
    /// limiter is installed (in which case the caller must rebuild the
    /// ServerCtx — which costs a binary restart). Called from the
    /// SIGHUP handler when the operator edits `rate_limit` in
    /// `server.yaml`. Bucket state is preserved across the swap, so
    /// in-flight clients are not penalized.
    pub fn reload_rate_limit(&self, capacity: f64, refill_per_sec: f64) -> bool {
        match &self.rate_limiter {
            Some(rl) => {
                rl.set_params(capacity, refill_per_sec);
                true
            }
            None => false,
        }
    }

    /// Hot-swap the per-user rate-limit parameters. Same semantics as
    /// `reload_rate_limit` for the user-id-keyed limiter.
    pub fn reload_user_rate_limit(&self, capacity: f64, refill_per_sec: f64) -> bool {
        match &self.user_limiter {
            Some(l) => {
                l.set_params(capacity, refill_per_sec);
                true
            }
            None => false,
        }
    }

    /// Hot-swap the global handshake-budget parameters. Same semantics
    /// as the other reload helpers.
    pub fn reload_handshake_budget(&self, capacity: f64, refill_per_sec: f64) -> bool {
        match &self.handshake_budget {
            Some(b) => {
                b.set_params(capacity, refill_per_sec);
                true
            }
            None => false,
        }
    }

    /// Vacuum idle entries from the rate limiter (caller-driven; the
    /// limiter itself doesn't spawn background tasks).
    pub fn vacuum_rate_limit(&self) {
        if let Some(rl) = &self.rate_limiter {
            rl.vacuum();
        }
    }

    /// Configure cover-forwarding to a SINGLE endpoint per spec §7.5.
    /// Backward-compatible single-endpoint setter — wraps into a
    /// `CoverEndpointPool` of size 1, so every source IP routes to
    /// the same URL (pre-pool behavior).
    pub fn with_cover(mut self, endpoint: impl Into<String>) -> Self {
        self.cover_endpoint = Some(crate::cover_pool::CoverEndpointPool::single(
            endpoint.into(),
        ));
        self
    }

    /// Configure cover-forwarding to a POOL of N endpoints.
    /// Per-source-IP /24 (v4) / /48 (v6) affinity — same peer always
    /// receives the same cover URL across repeated probes, defeating
    /// time-series active probing while preserving the consistency
    /// property a single observer would expect from a real cover
    /// server. See `cover_pool.rs` module docs for the trade-off.
    ///
    /// Returns `self` unchanged when `endpoints` is empty (caller
    /// almost certainly wanted a non-empty pool; an empty pool
    /// would silently disable cover-forwarding and tend to surprise
    /// the operator).
    pub fn with_cover_pool(mut self, endpoints: Vec<String>) -> Self {
        if let Some(pool) = crate::cover_pool::CoverEndpointPool::new(endpoints) {
            self.cover_endpoint = Some(pool);
        }
        self
    }

    /// Backward-compatible accessor. Returns the canonical (index-0)
    /// cover endpoint string from the pool — sufficient for callers
    /// that lost the peer address before reaching cover-forward.
    /// New code should prefer `cover_endpoint_for(&peer)` so the
    /// affinity policy applies.
    #[must_use]
    pub fn cover_endpoint(&self) -> Option<String> {
        self.cover_endpoint.as_ref().map(|p| p.select_canonical())
    }

    /// Select a cover endpoint with per-source-IP affinity. This is
    /// the path call sites with a `peer: &SocketAddr` in scope
    /// should use; the affinity discipline only fires when the peer
    /// address is supplied.
    #[must_use]
    pub fn cover_endpoint_for(&self, peer: &std::net::SocketAddr) -> Option<String> {
        self.cover_endpoint.as_ref().map(|p| p.select_for(peer))
    }

    /// Diagnostic accessor — returns the configured pool, if any.
    /// Used by metrics + admin surfaces to report pool size /
    /// endpoint list without invoking the affinity selector.
    #[must_use]
    pub fn cover_pool(&self) -> Option<&crate::cover_pool::CoverEndpointPool> {
        self.cover_endpoint.as_ref()
    }

    /// Install a probe-anomaly detector. The detector counts
    /// cover-forwards per source-IP /24 prefix and signals "this
    /// /24 is repeatedly tripping cover-forward" — the operator
    /// surfaces that signal via the `proteus_probe_anomalies_fired_total`
    /// Prometheus counter and a structured WARN log line per burst.
    ///
    /// See `crate::probe_anomaly::ProbeAnomalyDetector::with_defaults`
    /// for the recommended thresholds; operators tune via
    /// `probe_anomaly:` in `server.yaml`.
    #[must_use]
    pub fn with_probe_anomaly_detector(
        mut self,
        detector: Arc<crate::probe_anomaly::ProbeAnomalyDetector>,
    ) -> Self {
        self.probe_anomaly = Some(detector);
        self
    }

    /// Diagnostic accessor for the installed detector, if any.
    #[must_use]
    pub fn probe_anomaly(&self) -> Option<&Arc<crate::probe_anomaly::ProbeAnomalyDetector>> {
        self.probe_anomaly.as_ref()
    }

    /// Install a TTL-bounded auto-deny list. When configured, the
    /// probe-anomaly fire helper (`record_probe_anomaly` in this
    /// crate's server code and its β-side mirror) inserts the
    /// offending prefix into the list with the list's configured
    /// TTL. `admission_ok` consults this list BEFORE the firewall
    /// snapshot so denied prefixes short-circuit at the cheapest
    /// admission point.
    ///
    /// Pair with `with_probe_anomaly_detector` — the detector's
    /// fires are what populate the deny list. Installing one
    /// without the other gives you cheap admission lookups against
    /// an always-empty map (correct but useless).
    #[must_use]
    pub fn with_auto_deny_list(mut self, list: Arc<crate::auto_deny::AutoDenyList>) -> Self {
        self.auto_deny = Some(list);
        self
    }

    /// Diagnostic accessor for the installed auto-deny list.
    #[must_use]
    pub fn auto_deny(&self) -> Option<&Arc<crate::auto_deny::AutoDenyList>> {
        self.auto_deny.as_ref()
    }

    /// Public accessor for the ML-KEM EK bytes (for client config).
    #[must_use]
    pub fn mlkem_pk_bytes(&self) -> &[u8] {
        &self.keys.mlkem_pk_bytes
    }

    /// Public accessor for the X25519 server pub.
    #[must_use]
    pub fn x25519_pub(&self) -> &[u8; 32] {
        &self.keys.x25519_pub
    }

    /// Public accessor for the PQ fingerprint.
    #[must_use]
    pub fn pq_fingerprint(&self) -> &[u8; 32] {
        &self.keys.pq_fingerprint
    }
}

/// TLS-wrapped variant of [`serve`]. Identical handling but every
/// accepted connection is run through a TLS 1.3 handshake before the
/// Proteus handshake. The cover-forward path still operates on the raw
/// TCP stream when TLS itself fails (e.g. client doesn't speak TLS),
/// so probes that don't even reach the TLS handshake still see the
/// configured cover server's response.
///
/// Use [`serve_tls_reloadable`] instead if you want SIGHUP-driven
/// certificate hot-reload — this variant pins one fixed
/// [`TlsAcceptor`] for the lifetime of the process.
pub async fn serve_tls<F, Fut>(
    listener: TcpListener,
    ctx: Arc<ServerCtx>,
    acceptor: tokio_rustls::TlsAcceptor,
    handle: F,
) -> std::io::Result<()>
where
    F: Fn(
            AlphaSession<
                tokio::io::ReadHalf<crate::tls::ServerStream>,
                tokio::io::WriteHalf<crate::tls::ServerStream>,
            >,
        ) -> Fut
        + Send
        + Sync
        + Clone
        + 'static,
    Fut: std::future::Future<Output = ()> + Send,
{
    loop {
        let (stream, peer) = match accept_with_backoff(&listener, accept_error_throttle()).await? {
            AcceptOutcome::Got(p) => p,
            AcceptOutcome::Transient => continue,
        };
        let ctx = Arc::clone(&ctx);
        let acceptor = acceptor.clone();
        let handle = handle.clone();

        if !admission_ok(&ctx, &peer) {
            route_to_cover_or_drop(&ctx, stream, &peer);
            continue;
        }

        let permit = match ctx.try_acquire_connection() {
            ConnGate::Unbounded => None,
            ConnGate::Allowed(p) => Some(p),
            ConnGate::Rejected => {
                if matches!(
                    max_connections_throttle().try_acquire(),
                    AcquireResult::Allowed
                ) {
                    tracing::warn!(peer = %peer, "max_connections reached; routing to cover (TLS)");
                }
                if let Some(m) = ctx.metrics() {
                    m.conn_limit_rejected
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                route_to_cover_or_drop(&ctx, stream, &peer);
                continue;
            }
        };

        let _ = apply_tcp_keepalive(&stream, ctx.tcp_keepalive_secs());

        tokio::spawn(async move {
            let _permit_held = permit; // drop releases the slot on task exit.
            let deadline = ctx.handshake_deadline();
            let outcome =
                tokio::time::timeout(deadline, handshake_over_tls(stream, &acceptor, &ctx)).await;
            match outcome {
                Ok(Ok(session)) => {
                    let session = session.with_peer_addr(peer);
                    if user_admission_ok(&ctx, &session) {
                        handle(session).await;
                    }
                }
                Ok(Err(e)) => {
                    tracing::debug!(peer = %peer, error = %e, "TLS/Proteus handshake failed");
                    if let Some(m) = ctx.metrics() {
                        m.handshakes_failed
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                Err(_) => {
                    tracing::warn!(
                        peer = %peer,
                        timeout_secs = deadline.as_secs(),
                        "TLS handshake deadline elapsed"
                    );
                    if let Some(m) = ctx.metrics() {
                        m.handshake_timeouts
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }
        });
    }
}

/// Like [`serve_tls`] but takes a [`crate::tls::ReloadableAcceptor`].
/// The current `TlsAcceptor` is cloned cheaply on every accept, so a
/// SIGHUP-triggered [`crate::tls::ReloadableAcceptor::reload`] takes
/// effect on the very next connection without disturbing any
/// in-flight session.
pub async fn serve_tls_reloadable<F, Fut>(
    listener: TcpListener,
    ctx: Arc<ServerCtx>,
    acceptor: crate::tls::ReloadableAcceptor,
    handle: F,
) -> std::io::Result<()>
where
    F: Fn(
            AlphaSession<
                tokio::io::ReadHalf<crate::tls::ServerStream>,
                tokio::io::WriteHalf<crate::tls::ServerStream>,
            >,
        ) -> Fut
        + Send
        + Sync
        + Clone
        + 'static,
    Fut: std::future::Future<Output = ()> + Send,
{
    loop {
        let (stream, peer) = match accept_with_backoff(&listener, accept_error_throttle()).await? {
            AcceptOutcome::Got(p) => p,
            AcceptOutcome::Transient => continue,
        };
        let ctx = Arc::clone(&ctx);
        // Read-lock the current acceptor. After this clone the
        // operator is free to swap in a new cert; we keep ours for
        // the duration of this connection.
        let current_acceptor = acceptor.current();
        let handle = handle.clone();

        if !admission_ok(&ctx, &peer) {
            route_to_cover_or_drop(&ctx, stream, &peer);
            continue;
        }

        let permit = match ctx.try_acquire_connection() {
            ConnGate::Unbounded => None,
            ConnGate::Allowed(p) => Some(p),
            ConnGate::Rejected => {
                if matches!(
                    max_connections_throttle().try_acquire(),
                    AcquireResult::Allowed
                ) {
                    tracing::warn!(peer = %peer, "max_connections reached; routing to cover (TLS-reloadable)");
                }
                if let Some(m) = ctx.metrics() {
                    m.conn_limit_rejected
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                route_to_cover_or_drop(&ctx, stream, &peer);
                continue;
            }
        };

        let _ = apply_tcp_keepalive(&stream, ctx.tcp_keepalive_secs());

        tokio::spawn(async move {
            let _permit_held = permit;
            let deadline = ctx.handshake_deadline();
            // Measure handshake wall-clock time so the
            // on_session handler can feed it into the latency
            // histogram. Same shape as the plain-TCP path above.
            let hs_start = std::time::Instant::now();
            let outcome = tokio::time::timeout(
                deadline,
                handshake_over_tls(stream, &current_acceptor, &ctx),
            )
            .await;
            match outcome {
                Ok(Ok(session)) => {
                    let elapsed = hs_start.elapsed();
                    let session = session
                        .with_peer_addr(peer)
                        .with_handshake_duration(elapsed);
                    if user_admission_ok(&ctx, &session) {
                        handle(session).await;
                    }
                }
                Ok(Err(e)) => {
                    tracing::debug!(peer = %peer, error = %e, "TLS/Proteus handshake failed");
                    if let Some(m) = ctx.metrics() {
                        m.handshakes_failed
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                Err(_) => {
                    tracing::warn!(
                        peer = %peer,
                        timeout_secs = deadline.as_secs(),
                        "TLS handshake deadline elapsed"
                    );
                    if let Some(m) = ctx.metrics() {
                        m.handshake_timeouts
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }
        });
    }
}

/// Path-A variant of [`serve_tls_reloadable`] that runs the
/// `knock_dispatch` gate BEFORE TLS termination.
///
/// Three-way routing per connection:
/// - Gate `Pass` → wrap the TcpStream in a `PrependedStream`
///   (re-yields the peeked ClientHello bytes) and run
///   `handshake_over_tls_io` → existing per-session `handle`
///   callback.
/// - Gate `RouteToCover` → already handled by the dispatcher
///   (cover splice). Nothing more to do.
/// - Gate `Drop` → close silently.
///
/// When `dispatch_cfg.psk` is `None`, the gate short-circuits
/// to `Pass` without sniffing — operators who haven't opted
/// into Path A see the same byte-for-byte accept-loop behavior
/// as `serve_tls_reloadable`.
pub async fn serve_tls_reloadable_with_gate<F, Fut>(
    listener: TcpListener,
    ctx: Arc<ServerCtx>,
    acceptor: crate::tls::ReloadableAcceptor,
    dispatch_cfg: Arc<crate::knock_dispatch::DispatchConfig>,
    handle: F,
) -> std::io::Result<()>
where
    F: Fn(
            AlphaSession<
                tokio::io::ReadHalf<
                    tokio_rustls::server::TlsStream<crate::knock_dispatch::PrependedStream>,
                >,
                tokio::io::WriteHalf<
                    tokio_rustls::server::TlsStream<crate::knock_dispatch::PrependedStream>,
                >,
            >,
        ) -> Fut
        + Send
        + Sync
        + Clone
        + 'static,
    Fut: std::future::Future<Output = ()> + Send,
{
    loop {
        let (stream, peer) = match accept_with_backoff(&listener, accept_error_throttle()).await? {
            AcceptOutcome::Got(p) => p,
            AcceptOutcome::Transient => continue,
        };
        let ctx = Arc::clone(&ctx);
        let current_acceptor = acceptor.current();
        let handle = handle.clone();
        let dispatch_cfg = Arc::clone(&dispatch_cfg);

        if !admission_ok(&ctx, &peer) {
            route_to_cover_or_drop(&ctx, stream, &peer);
            continue;
        }

        let permit = match ctx.try_acquire_connection() {
            ConnGate::Unbounded => None,
            ConnGate::Allowed(p) => Some(p),
            ConnGate::Rejected => {
                if matches!(
                    max_connections_throttle().try_acquire(),
                    AcquireResult::Allowed
                ) {
                    tracing::warn!(peer = %peer, "max_connections reached; routing to cover (Path-A TLS)");
                }
                if let Some(m) = ctx.metrics() {
                    m.conn_limit_rejected
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                route_to_cover_or_drop(&ctx, stream, &peer);
                continue;
            }
        };

        let _ = apply_tcp_keepalive(&stream, ctx.tcp_keepalive_secs());
        let _ = stream.set_nodelay(true);

        tokio::spawn(async move {
            let _permit_held = permit;
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let routing =
                crate::knock_dispatch::dispatch_or_local_terminate(stream, &dispatch_cfg, now_secs)
                    .await;

            let prepended = match routing {
                crate::knock_dispatch::PathARouting::TerminateLocally(s) => s,
                crate::knock_dispatch::PathARouting::RoutedToCover {
                    reason,
                    splice_outcome,
                } => {
                    tracing::debug!(
                        peer = %peer,
                        ?reason,
                        cover_ok = splice_outcome.is_ok(),
                        "Path-A: connection routed to cover"
                    );
                    return;
                }
                crate::knock_dispatch::PathARouting::Dropped { reason } => {
                    tracing::debug!(peer = %peer, ?reason, "Path-A: connection dropped");
                    return;
                }
            };

            let deadline = ctx.handshake_deadline();
            let hs_start = std::time::Instant::now();
            let outcome = tokio::time::timeout(
                deadline,
                handshake_over_tls_io(prepended, &current_acceptor, &ctx),
            )
            .await;
            match outcome {
                Ok(Ok(session)) => {
                    let elapsed = hs_start.elapsed();
                    let session = session
                        .with_peer_addr(peer)
                        .with_handshake_duration(elapsed);
                    if user_admission_ok(&ctx, &session) {
                        handle(session).await;
                    }
                }
                Ok(Err(e)) => {
                    tracing::debug!(peer = %peer, error = %e, "Path-A TLS/Proteus handshake failed");
                    if let Some(m) = ctx.metrics() {
                        m.handshakes_failed
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                Err(_) => {
                    tracing::warn!(
                        peer = %peer,
                        timeout_secs = deadline.as_secs(),
                        "Path-A TLS handshake deadline elapsed"
                    );
                    if let Some(m) = ctx.metrics() {
                        m.handshake_timeouts
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }
        });
    }
}

/// Listen on `addr` and serve α-profile handshakes. `handle` is invoked
/// per established session.
///
/// **Auth-fail handling** (spec §7.5):
/// - If `ctx.cover_endpoint` is set, the raw bytes consumed during the
///   failed handshake attempt are replayed to that endpoint and the
///   live stream is byte-verbatim spliced for the rest of the connection.
/// - Otherwise, the connection is silently closed.
pub async fn serve<F, Fut>(
    listener: TcpListener,
    ctx: Arc<ServerCtx>,
    handle: F,
) -> std::io::Result<()>
where
    F: Fn(AlphaSession) -> Fut + Send + Sync + Clone + 'static,
    Fut: std::future::Future<Output = ()> + Send,
{
    loop {
        let (stream, peer) = match accept_with_backoff(&listener, accept_error_throttle()).await? {
            AcceptOutcome::Got(p) => p,
            AcceptOutcome::Transient => continue,
        };
        let ctx = Arc::clone(&ctx);
        let handle = handle.clone();

        // ---- Source-IP firewall + per-IP rate limit (DoS defense) ----
        if !admission_ok(&ctx, &peer) {
            route_to_cover_or_drop(&ctx, stream, &peer);
            continue;
        }

        // ---- Global concurrency cap (OOM defense) ----
        let permit = match ctx.try_acquire_connection() {
            ConnGate::Unbounded => None,
            ConnGate::Allowed(p) => Some(p),
            ConnGate::Rejected => {
                if matches!(
                    max_connections_throttle().try_acquire(),
                    AcquireResult::Allowed
                ) {
                    tracing::warn!(peer = %peer, "max_connections reached; routing to cover");
                }
                if let Some(m) = ctx.metrics() {
                    m.conn_limit_rejected
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                route_to_cover_or_drop(&ctx, stream, &peer);
                continue;
            }
        };

        // ---- Apply TCP keepalive (idle session reaper) ----
        let _ = apply_tcp_keepalive(&stream, ctx.tcp_keepalive_secs());

        tokio::spawn(async move {
            let _permit_held = permit;
            // Per-source-IP affinity selection — same peer always
            // sees the same cover URL across repeated probes
            // (defeats time-series active probing). Wins when
            // `cover_pool` is configured; collapses to the canonical
            // single-cover behavior when only `cover_endpoint` is set.
            let cover_target = ctx.cover_endpoint_for(&peer);
            let deadline = ctx.handshake_deadline();
            // Measure handshake wall-clock time so the on_session
            // handler can feed it into the latency histogram.
            // Operators dashboard `histogram_quantile(0.99, ...)`
            // to catch p99 regressions BEFORE users complain.
            let hs_start = std::time::Instant::now();
            let result = tokio::time::timeout(deadline, handshake_buffered(stream, &ctx)).await;
            let (replay_buf, raw_stream, timed_out) = match result {
                Ok(Ok((session, _))) => {
                    let elapsed = hs_start.elapsed();
                    let session = session
                        .with_peer_addr(peer)
                        .with_handshake_duration(elapsed);
                    if user_admission_ok(&ctx, &session) {
                        handle(session).await;
                    }
                    return;
                }
                Ok(Err(HandshakeFailure { buffer, stream, .. })) => {
                    tracing::debug!(peer = %peer, "handshake failed, attempting cover forward");
                    if let Some(m) = ctx.metrics() {
                        m.handshakes_failed
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    (buffer, stream, false)
                }
                Err(_elapsed) => {
                    tracing::warn!(
                        peer = %peer,
                        timeout_secs = deadline.as_secs(),
                        "handshake deadline elapsed (slowloris?)"
                    );
                    if let Some(m) = ctx.metrics() {
                        m.handshake_timeouts
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    (Vec::new(), None, true)
                }
            };
            let _ = timed_out;
            if let (Some(cover), Some(stream)) = (cover_target, raw_stream) {
                // Record before forwarding so the anomaly counter
                // increments even if the forward itself fails to
                // dial the cover server — the probe still happened
                // from the operator's POV.
                record_probe_anomaly(&ctx, &peer);
                match crate::cover::forward_to_cover(&cover, replay_buf, stream).await {
                    Ok(()) => {
                        tracing::debug!(peer = %peer, "cover forward complete");
                        if let Some(m) = ctx.metrics() {
                            m.cover_forwards
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                    Err(e) => tracing::warn!(peer = %peer, error = %e, "cover forward failed"),
                }
            }
            // else: silently drop.
        });
    }
}

/// Buffer-aware handshake: same protocol as [`handshake_over_tcp`] but
/// retains the consumed bytes + the live stream on failure so callers
/// can forward to cover (spec §7.5).
async fn handshake_buffered(
    stream: TcpStream,
    ctx: &Arc<ServerCtx>,
) -> Result<(AlphaSession, Vec<u8>), HandshakeFailure> {
    // We need the raw stream back on failure. We use a tee-style buffer:
    // every read fills both the wire-buffer (handshake parser) and a
    // failure-replay buffer. On success we discard the replay buffer;
    // on failure the caller gets the replay buffer + the still-open
    // TcpStream (NOT `into_split`-ed).
    //
    // Implementation note: to keep this simple and correct, we manually
    // read into a Vec<u8> buffer and try to decode after each chunk.
    // Once enough bytes for a full ClientHello frame are present, we
    // hand off to the existing handshake logic — but only after
    // re-attaching a `OwnedReadHalf` whose internal pre-buffered bytes
    // are the bytes we already drained. To avoid OS-level complications,
    // M1 keeps the cover-forward path simpler: on ANY decode/auth
    // failure we close. The full buffered replay is a v1.1 add — the
    // production wire is unchanged.
    use tokio::io::AsyncReadExt;
    let mut buf = Vec::with_capacity(2048);
    let mut tmp = [0u8; 4096];
    let mut stream = stream;
    loop {
        match proteus_wire::alpha::decode_frame(&buf) {
            Ok((frame, _consumed)) => {
                if frame.kind != proteus_wire::alpha::FRAME_CLIENT_HELLO {
                    return Err(HandshakeFailure::new(buf, Some(stream)));
                }
                break;
            }
            Err(proteus_wire::WireError::Short { .. }) => {}
            Err(_e) => {
                return Err(HandshakeFailure::new(buf, Some(stream)));
            }
        }
        // Cap handshake-time buffer growth. A malicious client could
        // otherwise send a varint-encoded frame body length of 2^30
        // bytes and then stream garbage forever — the
        // `WireError::Short` branch loops happily forever waiting
        // for the declared body. See crate::client::HANDSHAKE_RX_HARD_CAP.
        if buf.len() >= crate::client::HANDSHAKE_RX_HARD_CAP {
            return Err(HandshakeFailure::new(buf, Some(stream)));
        }
        let n = match stream.read(&mut tmp).await {
            Ok(0) => return Err(HandshakeFailure::new(buf, None)),
            Ok(n) => n,
            Err(_) => return Err(HandshakeFailure::new(buf, None)),
        };
        buf.extend_from_slice(&tmp[..n]);
    }

    // We now have at least one full ClientHello frame in `buf`. Hand it
    // to a synchronous parse + verify pipeline. On success we continue
    // the rest of the handshake on the same socket.
    match handshake_with_prefix(stream, ctx, std::mem::take(&mut buf)).await {
        Ok(s) => Ok((s, Vec::new())),
        Err(HandshakeFailure { buffer, stream, .. }) => Err(HandshakeFailure::new(buffer, stream)),
    }
}

/// Apply OS-level TCP keepalive to an accepted stream. Failure is
/// non-fatal.
///
/// Implementation note: tokio's `TcpStream` does not expose
/// `set_keepalive` directly. We borrow the underlying fd via `dup(2)`,
/// wrap into `socket2::Socket`, apply the option, and drop our copy.
/// The dup'd fd is closed when `sock` is dropped; tokio's original fd
/// is untouched.
/// Build a `TcpListener` with `SO_REUSEADDR` enabled so the service can
/// restart immediately after a SIGTERM without waiting for the kernel's
/// TIME_WAIT window. (Linux/macOS: 60 s default.)
pub async fn bind_listener_with_reuseaddr(addr: &str) -> std::io::Result<TcpListener> {
    let std_addr: std::net::SocketAddr = addr.parse().map_err(std::io::Error::other)?;
    let socket = match std_addr {
        std::net::SocketAddr::V4(_) => socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?,
        std::net::SocketAddr::V6(_) => socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?,
    };
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&std_addr.into())?;
    socket.listen(1024)?;
    let std_listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(std_listener)
}

// `apply_tcp_keepalive` moved to `crate::socket_opts` in iter-14
// so both the server accept-loop AND outbound dialers (client
// SOCKS5, server upstream) share one implementation. Local
// re-export keeps the existing call sites unchanged.
use crate::socket_opts::apply_tcp_keepalive;

/// Outcome of a single `listener.accept().await` attempt,
/// post-iter-18 with transient-error backoff.
enum AcceptOutcome {
    /// Got a usable stream + peer. Caller proceeds normally.
    Got((TcpStream, std::net::SocketAddr)),
    /// Transient kernel error — we logged + backed off; caller
    /// should `continue` to the next loop iteration.
    Transient,
}

/// Classify a raw OS error from `accept()` into "transient
/// (back off)" vs "fatal (propagate up)".
///
/// Iter-19: moved to `crate::socket_opts` so the proteus-client
/// SOCKS5 accept loop can reuse the same classifier. Local
/// re-export keeps server.rs call sites unchanged.
use crate::socket_opts::is_transient_accept_error;

/// Backoff applied after EMFILE / ENFILE / ENOMEM on accept.
/// 100 ms is long enough that one already-spawned per-conn
/// task can plausibly complete + release an FD before we
/// re-try, but short enough that legitimate inbound traffic
/// doesn't see a multi-second stall under a probe flood.
const ACCEPT_TRANSIENT_BACKOFF: std::time::Duration = std::time::Duration::from_millis(100);

/// Robust `listener.accept()` wrapper for the server's
/// accept loops (iter-18).
///
/// Pre-iter-18 every `pub async fn serve*` had the shape
/// `let (stream, peer) = listener.accept().await?;` — the `?`
/// propagated ANY io::Error and KILLED the accept loop. The
/// fatal class here is **EMFILE / ENFILE / ENOMEM**: under a
/// real probe storm the kernel runs out of file descriptors
/// faster than the cover-forward tasks can release them, the
/// next `accept()` returns EMFILE, the loop dies, the server
/// stops accepting new connections — but is still alive enough
/// that systemd doesn't restart it, AND its `/healthz` endpoint
/// (a Tokio task that already has its own listener FD) keeps
/// returning 200. From the operator's POV: the server is
/// "healthy" but silently refusing all new traffic. The worst
/// kind of production failure mode.
///
/// Real-world production servers (nginx, HAProxy, envoy) all
/// handle EMFILE the same way: log at WARN-throttled, briefly
/// sleep (100 ms is the de-facto industry value), continue.
/// The TCP backlog buffers incoming SYNs for ~tens of seconds
/// of EMFILE-induced pause, so a transient FD shortage is
/// invisible to clients.
///
/// Non-transient errors (the listener socket itself is gone:
/// EBADF, ECONNABORTED on the listener fd, ENETDOWN) are
/// propagated up — the operator's systemd unit should restart
/// the binary in those cases.
async fn accept_with_backoff(
    listener: &TcpListener,
    throttle: &Throttle,
) -> std::io::Result<AcceptOutcome> {
    match listener.accept().await {
        Ok(pair) => Ok(AcceptOutcome::Got(pair)),
        Err(e) => {
            let raw = e.raw_os_error();
            if is_transient_accept_error(raw) {
                if matches!(throttle.try_acquire(), AcquireResult::Allowed) {
                    tracing::warn!(
                        error = %e,
                        raw_os_error = ?raw,
                        backoff_ms = ACCEPT_TRANSIENT_BACKOFF.as_millis() as u64,
                        "accept() hit FD exhaustion — backing off briefly; \
                         in-flight cover-forward / handshake tasks should release \
                         FDs and the next accept will succeed"
                    );
                }
                tokio::time::sleep(ACCEPT_TRANSIENT_BACKOFF).await;
                Ok(AcceptOutcome::Transient)
            } else {
                // Non-transient: kill the loop (operator's systemd
                // restart catches this).
                Err(e)
            }
        }
    }
}

/// Per-server-instance log throttle for accept-error WARN spam.
/// EMFILE under a probe storm fires hundreds of times per
/// second; we want exactly one log line every few seconds, not
/// a flood that itself becomes the FD pressure source.
fn accept_error_throttle() -> &'static Throttle {
    static T: OnceLock<Throttle> = OnceLock::new();
    // burst=3 (cluster of three fires after a long pause, then
    // throttle kicks in); 0.2 tokens/sec = one log line every
    // 5 seconds of sustained EMFILE.
    T.get_or_init(|| Throttle::new(3, 0.2))
}

struct HandshakeFailure {
    buffer: Vec<u8>,
    stream: Option<TcpStream>,
}

impl HandshakeFailure {
    fn new(buffer: Vec<u8>, stream: Option<TcpStream>) -> Self {
        Self { buffer, stream }
    }
}

/// Handshake where the first chunk of bytes is supplied externally
/// (already-read from the wire). Used by [`handshake_buffered`] so we
/// don't re-read what we already peeked.
async fn handshake_with_prefix(
    stream: TcpStream,
    ctx: &Arc<ServerCtx>,
    prefix: Vec<u8>,
) -> Result<AlphaSession, HandshakeFailure> {
    stream.set_nodelay(true).ok();
    let (read, mut write) = stream.into_split();
    let mut read = read;

    // Decode the ClientHello frame from `prefix`. Any tail bytes (rare)
    // are stashed for the next `read_frame_with_buf` call.
    let (ch_frame_body, tail) = match proteus_wire::alpha::decode_frame(&prefix) {
        Ok((frame, consumed)) => (frame.body.to_vec(), prefix[consumed..].to_vec()),
        Err(_) => {
            return Err(HandshakeFailure::new(prefix, None));
        }
    };

    // From here, we replicate the original `handshake_over_tcp` body but
    // start from the parsed CH body and use `tail` as the pre-buffered
    // bytes for the rest of the handshake.

    let ext = match AuthExtension::decode_payload(&ch_frame_body) {
        Ok(e) => e,
        Err(_) => {
            // Reconstruct the full original bytes for cover forward.
            let mut original = proteus_wire::alpha::encode_handshake(
                proteus_wire::alpha::FRAME_CLIENT_HELLO,
                &ch_frame_body,
            );
            original.extend_from_slice(&tail);
            return Err(HandshakeFailure::new(original, None));
        }
    };

    // Carrier-hint check: this handshake function is shared between
    // α (TCP) and β (QUIC) — both deliver the same inner protocol.
    // Reject the γ hint (MASQUE-only) here, but allow α + β so the
    // proteus-transport-beta crate can reuse the exact code path.
    if matches!(ext.profile_hint, ProfileHint::Gamma) {
        let mut original = proteus_wire::alpha::encode_handshake(
            proteus_wire::alpha::FRAME_CLIENT_HELLO,
            &ch_frame_body,
        );
        original.extend_from_slice(&tail);
        return Err(HandshakeFailure::new(original, None));
    }
    let selected_suite = match select_aead_suite(&ext) {
        Ok(suite) => suite,
        Err(_) => {
            let mut original = proteus_wire::alpha::encode_handshake(
                proteus_wire::alpha::FRAME_CLIENT_HELLO,
                &ch_frame_body,
            );
            original.extend_from_slice(&tail);
            return Err(HandshakeFailure::new(original, None));
        }
    };

    let auth_key = auth_tag::derive_auth_key(
        ctx.pq_fingerprint(),
        &ext.client_x25519_pub,
        &ext.client_nonce,
    );
    let mac_input = ext.auth_mac_input();
    if !auth_tag::verify(&auth_key, &mac_input, &ext.auth_tag) {
        let mut original = proteus_wire::alpha::encode_handshake(
            proteus_wire::alpha::FRAME_CLIENT_HELLO,
            &ch_frame_body,
        );
        original.extend_from_slice(&tail);
        return Err(HandshakeFailure::new(original, None));
    }

    // Proof-of-work anti-DDoS (spec §8.3). Before paying ML-KEM Decap
    // CPU, require the client to demonstrate work. The check is one
    // SHA-256 (≈50 ns). Failure routes to cover so an attacker can't
    // tell "PoW reject" from "this is a generic HTTPS server".
    let required = ctx.pow_difficulty();
    if required > 0
        && !crate::pow::verify(
            ctx.pq_fingerprint(),
            &ext.client_nonce,
            required,
            &ext.anti_dos_solution,
        )
    {
        let mut original = proteus_wire::alpha::encode_handshake(
            proteus_wire::alpha::FRAME_CLIENT_HELLO,
            &ch_frame_body,
        );
        original.extend_from_slice(&tail);
        return Err(HandshakeFailure::new(original, None));
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let verdict = ctx
        .replay
        .lock()
        .await
        .check(now, &ext.client_nonce, ext.timestamp_unix_seconds);
    if !matches!(verdict, Verdict::Accept) {
        return Err(HandshakeFailure::new(Vec::new(), None));
    }

    // ----- Per-session ephemeral X25519 (Perfect Forward Secrecy) -----
    //
    // ARCHITECTURAL HARDENING vs REALITY + earlier Proteus drafts:
    //
    // REALITY uses a *long-term* X25519 keypair on the server (the
    // operator generates it once, distributes the public-half to
    // clients, and the secret-half sits in /etc/<reality>/server.key
    // for months). A compromise of that single file retroactively
    // decrypts every past session that ever DH'd against it. This is
    // the "harvest-now-decrypt-later" attack with a classical lever.
    //
    // Pre-this-commit Proteus inherited the same flaw: `ctx.keys.
    // x25519_sk` was a `StaticSecret` generated once at boot. Even
    // though the ML-KEM half was per-session-ephemeral on the client
    // side (PQ-FS by construction), the X25519 half was static on
    // the server side. An adversary who later seized the server's
    // x25519_sk could go back to a packet capture, replay
    // `server_combine`, and recover the classical 32 bytes of every
    // captured session's hybrid_shared. ML-KEM-only forward secrecy
    // is still strong, but a defense-in-depth crypto design must
    // not rely on a single primitive being unbroken.
    //
    // FIX: generate a fresh X25519 keypair on EVERY incoming session.
    // The secret half lives in this stack frame and is dropped
    // (zeroized via Zeroizing/StaticSecret's Drop) as soon as
    // `combined` is consumed. The public half is shipped in the
    // SH frame, transcript-hashed, and the client uses it for its
    // own `client_combine` — same as before, but the server's
    // identity to the wire never reuses an X25519 key.
    //
    // Server IDENTITY is unaffected: it still rests on the
    // long-term ML-KEM-768 keypair (the client encapsulates to a
    // pinned `server_pq_fingerprint`, only the rightful server can
    // decap). Stealing the server's ML-KEM secret would still hurt,
    // but ML-KEM keys are large + don't sit in process memory
    // outside of an active session's stack — much harder to exfil
    // than a 32-byte X25519 file.
    let server_x25519_eph_sk = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
    let server_x25519_eph_pub = x25519_dalek::PublicKey::from(&server_x25519_eph_sk).to_bytes();

    let combined = match kex::server_combine(
        &server_x25519_eph_sk,
        &ctx.keys.mlkem_sk,
        &ext.client_x25519_pub,
        &ext.client_mlkem768_ct,
    ) {
        Ok(c) => c,
        Err(_) => return Err(HandshakeFailure::new(Vec::new(), None)),
    };
    // Iter-171: `combined` is already a Zeroizing<[u8;64]> from
    // `server_combine`. Pre-iter-171 we copied its bytes into a
    // bare `let mut hybrid_shared = [0u8; 64]` stack array, which
    // never gets scrubbed. The Deref<Target = [u8;64]> on
    // Zeroizing lets us pass `&combined` directly to
    // `key_schedule::derive` (which takes `&[u8; 64]`), eliminating
    // the residue entirely. Pre-iter-171 a coredump or process-image
    // grab against the handshake-dispatch stack frame could recover
    // the full hybrid_shared (K_classic || K_pq) — sufficient to
    // re-derive every key for that session via the standard
    // Proteus key schedule.

    let sig_msg = client_signature_input(&ext);
    // ----- Decrypt client_id → look up exactly one allowlist entry → 1 verify -----
    //
    // The pre-fix code did `for (uid, vk) in allowlist { sig::verify(...) }`
    // until the first match, which is two CVEs in one:
    //
    //   1. Timing channel: position of the matching key in the allowlist
    //      is observable through total-Ed25519-verify latency. An attacker
    //      who can present a known (uid, sig) pair learns the index.
    //   2. CPU DoS amplification: an unauthenticated peer with no
    //      matching key forces N Ed25519 verifies (~100 µs each on
    //      Apple Silicon, ~250 µs on a typical VPS). N = 1000 users
    //      ⇒ 250 ms of server CPU per junk handshake.
    //
    // After this fix:
    //   - We AEAD-decrypt `client_id` to recover the claimed user_id (8
    //     bytes). This is a single ChaCha20-Poly1305 open (~1 µs).
    //   - We look up the user in the allowlist (linear scan over the
    //     8-byte uid is O(n) but the per-element cost is memcmp; an
    //     attacker who succeeds in this lookup has already authenticated
    //     the user_id via the AEAD tag, so this scan is not a timing
    //     channel on identity).
    //   - We do EXACTLY ONE Ed25519 verify against the matched key.
    //
    // The AEAD auth tag on `client_id` (16 bytes of Poly1305) is the
    // first auth gate — forgery resistance is 2^-128. The Ed25519 over
    // `(version || nonce || x25519_pub || mlkem_ct)` remains the
    // primary identity proof. Both must succeed.
    let cid_key = &ctx.keys.client_id_aead_key;
    let mut cid_n = [0u8; 12];
    cid_n.copy_from_slice(&ext.client_nonce[..12]);
    let claimed_uid: [u8; 8] =
        match proteus_crypto::aead::open(cid_key, &cid_n, 0, b"proteus-cid-v1", &ext.client_id) {
            Ok(pt) => {
                let s = pt.as_slice();
                if s.len() != 8 {
                    let mut original = proteus_wire::alpha::encode_handshake(
                        proteus_wire::alpha::FRAME_CLIENT_HELLO,
                        &ch_frame_body,
                    );
                    original.extend_from_slice(&tail);
                    return Err(HandshakeFailure::new(original, None));
                }
                let mut uid = [0u8; 8];
                uid.copy_from_slice(s);
                uid
            }
            Err(_) => {
                // client_id AEAD failed: this is the "no such user" path AND
                // the "garbage handshake" path collapsed into one indistinguishable
                // response. Cover-forward.
                let mut original = proteus_wire::alpha::encode_handshake(
                    proteus_wire::alpha::FRAME_CLIENT_HELLO,
                    &ch_frame_body,
                );
                original.extend_from_slice(&tail);
                return Err(HandshakeFailure::new(original, None));
            }
        };

    let mut matched_user_id: Option<[u8; 8]> = None;
    if !ctx.keys.client_allowlist.is_empty() {
        // Direct lookup by uid. O(n) for now (allowlist is a Vec); a
        // future HashMap conversion brings this to O(1) but doesn't
        // change the security story — uid is already authenticated by
        // the AEAD tag above.
        if let Some((uid, vk)) = ctx
            .keys
            .client_allowlist
            .iter()
            .find(|(uid, _)| uid == &claimed_uid)
        {
            if proteus_crypto::sig::verify(vk, &sig_msg, &ext.client_kex_sig).is_ok() {
                matched_user_id = Some(*uid);
            }
        }
        if matched_user_id.is_none() {
            return Err(HandshakeFailure::new(Vec::new(), None));
        }
    } else {
        // No allowlist configured (test mode): trust the AEAD-attested uid.
        matched_user_id = Some(claimed_uid);
    }

    let mut transcript = Transcript::new();
    transcript.update(&ch_frame_body);
    // SH carries the SERVER'S EPHEMERAL X25519 pub, not the long-term
    // one. Transcript-hashing it binds the ephemeral into the Finished
    // MAC chain so a MITM cannot swap the pub for a key it controls
    // without invalidating the MAC.
    let sh_body = server_hello_body(ext.version, &server_x25519_eph_pub, selected_suite);
    let sh_frame =
        proteus_wire::alpha::encode_handshake(proteus_wire::alpha::FRAME_SERVER_HELLO, &sh_body);
    transcript.update(&sh_body);
    let th_ch_sh = transcript.snapshot();
    if write.write_all(&sh_frame).await.is_err() {
        return Err(HandshakeFailure::new(Vec::new(), None));
    }

    let provisional = match key_schedule::derive(
        &ext.client_nonce,
        &combined,
        &th_ch_sh,
        &th_ch_sh,
        &th_ch_sh,
    ) {
        Ok(s) => s,
        Err(_) => return Err(HandshakeFailure::new(Vec::new(), None)),
    };
    // Iter-172: wrap the HKDF-derived finished MAC keys in
    // `Zeroizing` so the 32-byte secret arrays scrub on drop.
    // See the matching iter-172 fix in client.rs for the threat
    // analysis. Server-side has the larger blast radius — this
    // function is called for every accepted handshake, so leaving
    // residue accumulates one stack-image of every session's
    // finished MAC keys.
    let mut server_finished_key = Zeroizing::new([0u8; 32]);
    if proteus_crypto::kdf::expand_label(
        &provisional.s_ap_secret,
        b"finished",
        b"",
        &mut *server_finished_key,
    )
    .is_err()
    {
        return Err(HandshakeFailure::new(Vec::new(), None));
    }
    let sf_mac = hmac_sha256(&server_finished_key, &th_ch_sh);
    let sf_frame =
        proteus_wire::alpha::encode_handshake(proteus_wire::alpha::FRAME_SERVER_FINISHED, &sf_mac);
    if write.write_all(&sf_frame).await.is_err() {
        return Err(HandshakeFailure::new(Vec::new(), None));
    }

    // Read ClientFinished using the prefilled `tail` first. Use a
    // persistent buffer so any tail bytes past CF are retained for the
    // post-handshake DATA receiver.
    let mut rx_buf = tail;
    let cf = match read_frame_drain(&mut read, &mut rx_buf).await {
        Ok(f) => f,
        Err(_) => return Err(HandshakeFailure::new(Vec::new(), None)),
    };
    if cf.kind != proteus_wire::alpha::FRAME_CLIENT_FINISHED || cf.body.len() != 32 {
        return Err(HandshakeFailure::new(Vec::new(), None));
    }

    let th_ch_sf = key_schedule::sha256(&{
        let mut h = Vec::new();
        h.extend_from_slice(&ch_frame_body);
        h.extend_from_slice(&sh_body);
        h.extend_from_slice(&sf_mac);
        h
    });
    let mut client_finished_key = Zeroizing::new([0u8; 32]);
    if proteus_crypto::kdf::expand_label(
        &provisional.c_ap_secret,
        b"finished",
        b"",
        &mut *client_finished_key,
    )
    .is_err()
    {
        return Err(HandshakeFailure::new(Vec::new(), None));
    }
    let expected_cf = hmac_sha256(&client_finished_key, &th_ch_sf);
    let received_cf: [u8; 32] = match cf.body.as_slice().try_into() {
        Ok(v) => v,
        Err(_) => return Err(HandshakeFailure::new(Vec::new(), None)),
    };
    if !ct_eq(&expected_cf, &received_cf) {
        return Err(HandshakeFailure::new(Vec::new(), None));
    }

    let th_ch_cf = key_schedule::sha256(&{
        let mut h = Vec::new();
        h.extend_from_slice(&ch_frame_body);
        h.extend_from_slice(&sh_body);
        h.extend_from_slice(&sf_mac);
        h.extend_from_slice(&expected_cf);
        h
    });
    let final_secrets = match key_schedule::derive(
        &ext.client_nonce,
        &combined,
        &th_ch_sh,
        &th_ch_sf,
        &th_ch_cf,
    ) {
        Ok(s) => s,
        Err(_) => return Err(HandshakeFailure::new(Vec::new(), None)),
    };
    let (c_keys, s_keys) = match final_secrets.direction_keys() {
        Ok(k) => k,
        Err(_) => return Err(HandshakeFailure::new(Vec::new(), None)),
    };

    // Pass any post-CF tail bytes (coalesced DATA records) to the session
    // receiver so we don't lose them.
    //
    // Install asymmetric DH ratchet bootstrap: server holds
    // `server_x25519_eph_sk` (the fresh per-session ephemeral) and the
    // client's announced `client_x25519_pub`. Both halves are known
    // post-handshake, so no extra round-trip is needed to enable PCS-
    // strong ratcheting.
    let mut session = AlphaSession::with_prefix_and_suite(
        write,
        read,
        s_keys,
        c_keys,
        final_secrets.s_ap_secret.clone(),
        final_secrets.c_ap_secret.clone(),
        rx_buf,
        selected_suite,
    )
    .with_shape(ext.shape_seed, ext.cover_profile_id)
    .with_dh_ratchet(server_x25519_eph_sk, ext.client_x25519_pub);
    if let Some(uid) = matched_user_id {
        session = session.with_user_id(uid);
    }
    Ok(session)
}

/// Read one frame, draining bytes from a **persistent** receive buffer.
/// Critical to avoid losing coalesced post-handshake bytes — see the
/// parallel client-side fix.
async fn read_frame_drain<R: tokio::io::AsyncRead + Unpin>(
    read: &mut R,
    buf: &mut Vec<u8>,
) -> std::io::Result<OwnedFrame> {
    use tokio::io::AsyncReadExt;
    loop {
        if !buf.is_empty() {
            match proteus_wire::alpha::decode_frame(buf) {
                Ok((frame, consumed)) => {
                    let kind = frame.kind;
                    let body = frame.body.to_vec();
                    buf.drain(..consumed);
                    return Ok(OwnedFrame { kind, body });
                }
                Err(proteus_wire::WireError::Short { .. }) => {}
                Err(_) => {
                    return Err(std::io::Error::other("decode failure"));
                }
            }
        }
        // Cap handshake-time buffer (see crate::client::HANDSHAKE_RX_HARD_CAP).
        // A peer flooding bytes that never parse to a complete frame is
        // trying to OOM us — fail fast.
        if buf.len() >= crate::client::HANDSHAKE_RX_HARD_CAP {
            return Err(std::io::Error::other("handshake rx buffer cap exceeded"));
        }
        let mut tmp = [0u8; 4096];
        let n = read.read(&mut tmp).await?;
        if n == 0 {
            return Err(std::io::Error::other("eof"));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

/// As [`serve`] but for a single connection — useful for tests.
pub async fn handshake_over_tcp(
    stream: TcpStream,
    ctx: &Arc<ServerCtx>,
) -> AlphaResult<AlphaSession> {
    stream.set_nodelay(true)?;
    let (read, write) = stream.into_split();
    handshake_over_split(read, write, ctx).await
}

/// Wrap a `TcpStream` in TLS 1.3 (spec §4.2 outer wrapper) and then run
/// the Proteus α handshake inside the encrypted record stream.
///
/// On the wire a passive observer sees a standards-compliant TLS 1.3
/// handshake followed by encrypted application_data records.
pub async fn handshake_over_tls(
    stream: TcpStream,
    acceptor: &tokio_rustls::TlsAcceptor,
    ctx: &Arc<ServerCtx>,
) -> AlphaResult<
    AlphaSession<
        tokio::io::ReadHalf<crate::tls::ServerStream>,
        tokio::io::WriteHalf<crate::tls::ServerStream>,
    >,
> {
    stream.set_nodelay(true)?;
    let tls_stream = crate::tls::server_handshake(acceptor, stream)
        .await
        .map_err(|e| AlphaError::Io(std::io::Error::other(e.to_string())))?;
    handshake_over_tls_stream_post_accept(tls_stream, ctx).await
}

/// Generic-IO variant of [`handshake_over_tls`]. Accepts any
/// `AsyncRead + AsyncWrite` instead of being bound to
/// `TcpStream`. Used by the Path-A integration to drive
/// rustls over a [`crate::knock_dispatch::PrependedStream`]
/// (a TcpStream with a peeked-bytes prefix so the TLS
/// terminator sees the original ClientHello bytes after the
/// gate has consumed them for the knock check).
///
/// Same channel-binding extraction + same downstream
/// `handshake_over_split_bound` call as the legacy
/// `handshake_over_tls` — just lifted off the concrete
/// `TcpStream` type.
pub async fn handshake_over_tls_io<S>(
    stream: S,
    acceptor: &tokio_rustls::TlsAcceptor,
    ctx: &Arc<ServerCtx>,
) -> AlphaResult<
    AlphaSession<
        tokio::io::ReadHalf<tokio_rustls::server::TlsStream<S>>,
        tokio::io::WriteHalf<tokio_rustls::server::TlsStream<S>>,
    >,
>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let tls_stream = crate::tls::server_handshake_io(acceptor, stream)
        .await
        .map_err(|e| AlphaError::Io(std::io::Error::other(e.to_string())))?;
    handshake_over_tls_stream_post_accept(tls_stream, ctx).await
}

/// Shared post-TLS-accept logic (channel binding extraction +
/// split + inner Proteus handshake). Generic over the
/// post-accept TLS stream type so both `handshake_over_tls`
/// and `handshake_over_tls_io` route through the same code.
async fn handshake_over_tls_stream_post_accept<S>(
    tls_stream: tokio_rustls::server::TlsStream<S>,
    ctx: &Arc<ServerCtx>,
) -> AlphaResult<
    AlphaSession<
        tokio::io::ReadHalf<tokio_rustls::server::TlsStream<S>>,
        tokio::io::WriteHalf<tokio_rustls::server::TlsStream<S>>,
    >,
>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // Extract the same exporter tag the client will see on its side
    // of this TLS session — RFC 5705 / RFC 9266 channel binding.
    // A MITM bridging two distinct TLS sessions sees different
    // exporters on each side and therefore cannot relay the inner
    // Finished MAC chain (which now commits to the exporter via the
    // transcript hash on both ends).
    //
    // Iter-174: wrap the channel-binding tag in `Zeroizing` so the
    // 32-byte exporter output scrubs on drop. Mirrors the matching
    // client-side fix; see that comment block for the threat
    // analysis. Server-side has larger blast radius — this path is
    // taken for every accepted TLS-wrapped handshake.
    let mut binding = Zeroizing::new([0u8; crate::client::CHANNEL_BINDING_LEN]);
    {
        let (_io, conn) = tls_stream.get_ref();
        conn.export_keying_material(&mut binding[..], crate::client::TLS_EXPORTER_LABEL, None)
            .map_err(|e| {
                AlphaError::Io(std::io::Error::other(format!(
                    "TLS exporter unavailable: {e}"
                )))
            })?;
    }
    let (read, write) = tokio::io::split(tls_stream);
    // Pass the binding bytes by value; the receiver re-wraps them
    // in its own Zeroizing on entry. The wrapper here scrubs as
    // soon as this function exits.
    handshake_over_split_bound(read, write, ctx, Some(*binding)).await
}

/// Run the server-side Proteus handshake over an already-split
/// AsyncRead/AsyncWrite pair (any transport: raw TCP, TLS-wrapped TCP,
/// in-memory pipe, etc.).
///
/// Wrapper around `handshake_over_split_bound(.., None)` — no channel
/// binding. Use the bound variant when an outer TLS exporter is
/// available.
pub async fn handshake_over_split<R, W>(
    read: R,
    write: W,
    ctx: &Arc<ServerCtx>,
) -> AlphaResult<AlphaSession<R, W>>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    handshake_over_split_bound(read, write, ctx, None).await
}

/// Server-side handshake driver with optional TLS channel-binding tag.
/// Symmetric to `client::handshake_over_split_bound`.
pub async fn handshake_over_split_bound<R, W>(
    read: R,
    write: W,
    ctx: &Arc<ServerCtx>,
    channel_binding: Option<[u8; crate::client::CHANNEL_BINDING_LEN]>,
) -> AlphaResult<AlphaSession<R, W>>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut write = write;
    let mut read = read;
    let mut rx_buf: Vec<u8> = Vec::with_capacity(2048);

    // State machine starts at Init (spec §5.1).
    let mut state = State::Init;

    // ----- 1. Read ClientHello -----
    let ch = read_frame(&mut read, &mut rx_buf).await?;
    if ch.kind != alpha::FRAME_CLIENT_HELLO {
        return Err(AlphaError::Closed);
    }
    let ext = AuthExtension::decode_payload(&ch.body)?;
    state = state
        .step(proteus_handshake::state::Event::RecvClientHelloWithAuthExt)
        .expect("Init→AuthParsed");

    // Accept α or β here; reject γ. See `handshake_buffered` for the
    // matching check on the cover-forwarding path.
    if matches!(ext.profile_hint, ProfileHint::Gamma) {
        return Err(AlphaError::Wire(proteus_wire::WireError::BadProfileHint(
            ext.profile_hint.to_byte(),
        )));
    }
    let selected_suite = select_aead_suite(&ext)?;

    // ----- 2. Verify auth_tag -----
    let auth_key = auth_tag::derive_auth_key(
        ctx.pq_fingerprint(),
        &ext.client_x25519_pub,
        &ext.client_nonce,
    );
    let mac_input = ext.auth_mac_input();
    if !auth_tag::verify(&auth_key, &mac_input, &ext.auth_tag) {
        return Err(AlphaError::AuthTagInvalid);
    }
    state = state
        .step(proteus_handshake::state::Event::AuthTagOk)
        .expect("AuthParsed→AuthVerified");

    // ----- 3a. Proof-of-work (spec §8.3) -----
    let required = ctx.pow_difficulty();
    if required > 0
        && !crate::pow::verify(
            ctx.pq_fingerprint(),
            &ext.client_nonce,
            required,
            &ext.anti_dos_solution,
        )
    {
        return Err(AlphaError::AuthTagInvalid);
    }

    // ----- 3. Timestamp + replay window -----
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let verdict = ctx
        .replay
        .lock()
        .await
        .check(now, &ext.client_nonce, ext.timestamp_unix_seconds);
    match verdict {
        Verdict::Accept => {}
        Verdict::Stale => return Err(AlphaError::AuthStale),
        Verdict::Replay => return Err(AlphaError::AuthReplay),
    }

    // ----- 4. Decap ML-KEM-768 + per-session-ephemeral X25519 combine -----
    // Per-session ephemeral X25519: see comment block in
    // `handshake_with_cover` — same PFS hardening, applied identically
    // to the raw-TCP path so neither variant leaks classical-FS.
    let server_x25519_eph_sk = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
    let server_x25519_eph_pub = x25519_dalek::PublicKey::from(&server_x25519_eph_sk).to_bytes();
    let combined = kex::server_combine(
        &server_x25519_eph_sk,
        &ctx.keys.mlkem_sk,
        &ext.client_x25519_pub,
        &ext.client_mlkem768_ct,
    )?;
    state = state
        .step(proteus_handshake::state::Event::DecapsOk)
        .expect("AuthVerified→DecapsDone");
    // Iter-171: pass `&combined` directly to `key_schedule::derive`
    // — same residue fix as the matching site above. The bare
    // `let mut hybrid_shared = [0u8; 64]; hybrid_shared.copy_from_slice
    // (...)` pattern leaked the full hybrid shared on the stack.

    // ----- 5. Decrypt + verify client_id -----
    //
    // The full 24-byte ChaCha20-Poly1305 output (8-byte ct + 16-byte
    // tag) authenticates `user_id`. Decrypt fails on any tampering —
    // we drop those without further work (no Ed25519 verify) so a
    // garbage handshake cannot drain CPU. See the parallel comment
    // in `handshake_with_cover` for the threat-model write-up.
    let cid_key = &ctx.keys.client_id_aead_key;
    let mut cid_n = [0u8; 12];
    cid_n.copy_from_slice(&ext.client_nonce[..12]);
    let claimed_uid: [u8; 8] = {
        let pt = proteus_crypto::aead::open(cid_key, &cid_n, 0, b"proteus-cid-v1", &ext.client_id)
            .map_err(|_| AlphaError::AuthTagInvalid)?;
        let s = pt.as_slice();
        if s.len() != 8 {
            return Err(AlphaError::AuthTagInvalid);
        }
        let mut uid = [0u8; 8];
        uid.copy_from_slice(s);
        uid
    };

    // ----- 6. Ed25519 sig verify (exactly one verify, not N) -----
    let sig_msg = client_signature_input(&ext);
    let mut matched_user_id: Option<[u8; 8]> = None;
    if !ctx.keys.client_allowlist.is_empty() {
        if let Some((uid, vk)) = ctx
            .keys
            .client_allowlist
            .iter()
            .find(|(uid, _)| uid == &claimed_uid)
        {
            if proteus_crypto::sig::verify(vk, &sig_msg, &ext.client_kex_sig).is_ok() {
                matched_user_id = Some(*uid);
            }
        }
        if matched_user_id.is_none() {
            return Err(AlphaError::AuthTagInvalid);
        }
    } else {
        matched_user_id = Some(claimed_uid);
    }

    // ----- 7. Build ServerHello with server X25519 share -----
    let mut transcript = Transcript::new();
    // Mirror the client's channel-binding mix-in. See client.rs for
    // the rationale; both ends MUST hash the SAME tag before any
    // wire frame goes into the transcript, otherwise their inner
    // Finished MAC chains diverge — which is exactly the failure
    // mode we want when a MITM bridges two distinct TLS sessions.
    // Iter-174: rewrap the by-value param into Zeroizing so the
    // in-function copy scrubs on scope exit. Same approach as
    // the matching client-side fix; the public-API signature
    // can't change (β transport + integration tests consume it).
    if let Some(binding_raw) = channel_binding {
        let binding = Zeroizing::new(binding_raw);
        let mut pre = Zeroizing::new(Vec::with_capacity(2 + crate::client::CHANNEL_BINDING_LEN));
        pre.extend_from_slice(b"cb");
        pre.extend_from_slice(&*binding);
        transcript.update(&pre);
    }
    transcript.update(&ch.body);
    // SH carries the EPHEMERAL pub (PFS) — see `handshake_with_cover`.
    let sh_body = server_hello_body(ext.version, &server_x25519_eph_pub, selected_suite);
    let sh_frame = alpha::encode_handshake(alpha::FRAME_SERVER_HELLO, &sh_body);
    transcript.update(&sh_body);
    let th_ch_sh = transcript.snapshot();
    write.write_all(&sh_frame).await?;

    // ----- 8. Derive provisional secrets and emit ServerFinished -----
    let provisional = key_schedule::derive(
        &ext.client_nonce,
        &combined,
        &th_ch_sh,
        &th_ch_sh,
        &th_ch_sh,
    )?;
    // Iter-172: same Zeroizing wrap as the matching site in
    // `handshake_with_cover`. Closes the residue on the
    // raw-TCP (no-cover-forward) handshake path.
    let mut server_finished_key = Zeroizing::new([0u8; 32]);
    proteus_crypto::kdf::expand_label(
        &provisional.s_ap_secret,
        b"finished",
        b"",
        &mut *server_finished_key,
    )?;
    let sf_mac = hmac_sha256(&server_finished_key, &th_ch_sh);
    let sf_frame = alpha::encode_handshake(alpha::FRAME_SERVER_FINISHED, &sf_mac);
    write.write_all(&sf_frame).await?;
    state = state
        .step(proteus_handshake::state::Event::SecretsReady)
        .expect("DecapsDone→SecretsDerived");
    state = state
        .step(proteus_handshake::state::Event::ServerSendDone)
        .expect("SecretsDerived→ServerHelloSent");

    let _ = state; // M1: subsequent transitions are implicit.

    // ----- 9. Read ClientFinished -----
    let cf = read_frame(&mut read, &mut rx_buf).await?;
    if cf.kind != alpha::FRAME_CLIENT_FINISHED {
        return Err(AlphaError::Closed);
    }
    if cf.body.len() != 32 {
        return Err(AlphaError::BadClientFinished);
    }

    // For client_finished verification we need th_ch_sf (= H(CH||SH||SF)).
    let th_ch_sf = key_schedule::sha256(&{
        let mut h = Vec::new();
        h.extend_from_slice(&ch.body);
        h.extend_from_slice(&sh_body);
        h.extend_from_slice(&sf_mac);
        h
    });
    let mut client_finished_key = Zeroizing::new([0u8; 32]);
    proteus_crypto::kdf::expand_label(
        &provisional.c_ap_secret,
        b"finished",
        b"",
        &mut *client_finished_key,
    )?;
    let expected_cf = hmac_sha256(&client_finished_key, &th_ch_sf);
    // Defense-in-depth: even though the `cf.body.len() != 32` early
    // return above makes this conversion infallible TODAY, an
    // accidental refactor of the early check would convert this
    // into a server-side panic on adversary-supplied bytes.
    // `try_into()` + `?` makes the safety property local instead of
    // tracking a separate line.
    let received_cf: [u8; 32] = cf
        .body
        .as_slice()
        .try_into()
        .map_err(|_| AlphaError::BadClientFinished)?;
    if !ct_eq(&expected_cf, &received_cf) {
        return Err(AlphaError::BadClientFinished);
    }

    // ----- 10. Finalize key material -----
    let th_ch_cf = key_schedule::sha256(&{
        let mut h = Vec::new();
        h.extend_from_slice(&ch.body);
        h.extend_from_slice(&sh_body);
        h.extend_from_slice(&sf_mac);
        h.extend_from_slice(&expected_cf);
        h
    });
    let final_secrets = key_schedule::derive(
        &ext.client_nonce,
        &combined,
        &th_ch_sh,
        &th_ch_sf,
        &th_ch_cf,
    )?;
    let (c_keys, s_keys) = final_secrets.direction_keys()?;
    // Server: sends with s_ap_secret keys, receives with c_ap_secret keys.
    // DH ratchet bootstrap — same comment as in `handshake_with_cover`.
    let mut session = AlphaSession::with_prefix_and_suite(
        write,
        read,
        s_keys,
        c_keys,
        final_secrets.s_ap_secret.clone(),
        final_secrets.c_ap_secret.clone(),
        rx_buf,
        selected_suite,
    )
    .with_shape(ext.shape_seed, ext.cover_profile_id)
    .with_dh_ratchet(server_x25519_eph_sk, ext.client_x25519_pub);
    if let Some(uid) = matched_user_id {
        session = session.with_user_id(uid);
    }
    Ok(session)
}

/// Read one frame, draining bytes from a persistent receive buffer.
/// See `read_frame_drain` for rationale on why we must NOT discard
/// post-frame tail bytes.
async fn read_frame<R: tokio::io::AsyncRead + Unpin>(
    read: &mut R,
    buf: &mut Vec<u8>,
) -> AlphaResult<OwnedFrame> {
    use tokio::io::AsyncReadExt;
    loop {
        if !buf.is_empty() {
            match alpha::decode_frame(buf) {
                Ok((frame, consumed)) => {
                    let kind = frame.kind;
                    let body = frame.body.to_vec();
                    buf.drain(..consumed);
                    return Ok(OwnedFrame { kind, body });
                }
                Err(proteus_wire::WireError::Short { .. }) => {}
                Err(e) => return Err(e.into()),
            }
        }
        // Handshake-time buffer cap — see crate::client::HANDSHAKE_RX_HARD_CAP.
        if buf.len() >= crate::client::HANDSHAKE_RX_HARD_CAP {
            return Err(AlphaError::Closed);
        }
        let mut tmp = [0u8; 4096];
        let n = read.read(&mut tmp).await?;
        if n == 0 {
            return Err(AlphaError::Closed);
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

struct OwnedFrame {
    kind: u8,
    body: Vec<u8>,
}

fn hmac_sha256(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use zeroize::Zeroize as _;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    let mut out = mac.finalize().into_bytes();
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&out);
    // Iter-190: same stack-residue scrub as the matching client-
    // side helper. The hmac-0.12 GenericArray output doesn't
    // impl Zeroize; the 32-byte HMAC tag lingers on the stack
    // until later activity overwrites the slot. Server-side
    // blast radius is larger — `hmac_sha256` is called for the
    // ServerFinished + ClientFinished MAC computation on every
    // accepted handshake; residue accumulates per-session in
    // recently-freed stack pages.
    {
        let bytes: &mut [u8] = out.as_mut();
        bytes.zeroize();
    }
    tag
}

fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;
    bool::from(a.ct_eq(b))
}

// `accept_classifier_tests` moved to `crate::socket_opts` in
// iter-19 alongside the `is_transient_accept_error` helper
// itself. Server-side accept loops still use the local
// `use crate::socket_opts::is_transient_accept_error;`
// re-export so call sites are unchanged.

#[cfg(test)]
mod aead_negotiation_tests {
    use super::*;

    fn extension(version: u8, mask: u16) -> AuthExtension {
        AuthExtension {
            version,
            profile_hint: ProfileHint::Beta,
            aead_suite_mask: mask,
            client_nonce: [0x11; proteus_spec::CLIENT_NONCE_LEN],
            client_x25519_pub: [0x22; proteus_spec::X25519_PUB_LEN],
            client_mlkem768_ct: [0x33; proteus_spec::ML_KEM_768_CT_LEN],
            client_id: [0x44; proteus_spec::CLIENT_ID_LEN],
            timestamp_unix_seconds: 1,
            cover_profile_id: proteus_spec::COVER_PROFILE_STREAMING,
            shape_seed: 2,
            anti_dos_difficulty: 0,
            anti_dos_solution: [0; proteus_spec::ANTI_DOS_SOLUTION_LEN],
            client_kex_sig: [0; proteus_spec::ED25519_SIG_LEN],
            client_kex_sig_pq: [0; proteus_spec::ML_DSA_65_SIG_TRUNCATED_LEN],
            auth_tag: [0; proteus_spec::HMAC_TAG_LEN],
        }
    }

    #[test]
    fn v11_prefers_hardware_aes_and_v10_stays_chacha() {
        let modern = extension(
            PROTEUS_VERSION_V11,
            AEAD_SUITE_MASK_AES_256_GCM | AEAD_SUITE_MASK_CHACHA20_POLY1305,
        );
        assert_eq!(select_aead_suite(&modern).unwrap(), AeadSuite::Aes256Gcm);

        let chacha_only = extension(PROTEUS_VERSION_V11, AEAD_SUITE_MASK_CHACHA20_POLY1305);
        assert_eq!(
            select_aead_suite(&chacha_only).unwrap(),
            AeadSuite::ChaCha20Poly1305
        );

        let legacy = extension(PROTEUS_VERSION_V10, 0);
        assert_eq!(
            select_aead_suite(&legacy).unwrap(),
            AeadSuite::ChaCha20Poly1305
        );
    }

    #[test]
    fn changing_v11_offer_invalidates_client_identity_signature() {
        let mut offered = extension(
            PROTEUS_VERSION_V11,
            AEAD_SUITE_MASK_AES_256_GCM | AEAD_SUITE_MASK_CHACHA20_POLY1305,
        );
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x5a; 32]);
        let verifying_key = signing_key.verifying_key();
        let signature = proteus_crypto::sig::sign(&signing_key, &client_signature_input(&offered));

        offered.aead_suite_mask = AEAD_SUITE_MASK_CHACHA20_POLY1305;
        assert!(
            proteus_crypto::sig::verify(
                &verifying_key,
                &client_signature_input(&offered),
                &signature
            )
            .is_err(),
            "an on-path suite-offer downgrade must invalidate client identity authentication"
        );
    }

    #[test]
    fn server_selection_changes_finished_transcript() {
        let server_pub = [0x77; 32];
        let aes = server_hello_body(PROTEUS_VERSION_V11, &server_pub, AeadSuite::Aes256Gcm);
        let chacha = server_hello_body(
            PROTEUS_VERSION_V11,
            &server_pub,
            AeadSuite::ChaCha20Poly1305,
        );
        assert_eq!(aes.len(), 33);
        assert_eq!(chacha.len(), 33);
        assert_ne!(key_schedule::sha256(&aes), key_schedule::sha256(&chacha));
    }
}

#[cfg(test)]
mod cover_forward_limit_tests {
    //! Iter-20: prove the cover-forward semaphore actually
    //! gates the cover-forward path. Without these tests, a
    //! future refactor that silently broke the semaphore would
    //! reintroduce the unbounded-spawn FD-exhaustion class fixed
    //! in iter-20.

    use super::*;

    fn ctx_no_cap() -> ServerCtx {
        ServerCtx::new(ServerKeys::generate())
    }

    fn ctx_with_cap(n: usize) -> ServerCtx {
        ServerCtx::new(ServerKeys::generate()).with_max_cover_forwards(n)
    }

    /// No cap configured → returns Some(None) on every call
    /// (the unbounded sentinel). Preserves legacy behavior for
    /// operators who haven't opted in.
    #[test]
    fn no_cap_returns_unbounded_sentinel() {
        let ctx = ctx_no_cap();
        for _ in 0..100 {
            let r = ctx.try_acquire_cover_forward();
            assert!(matches!(r, Some(None)), "expected unbounded sentinel");
        }
    }

    /// Cap configured at N → up to N concurrent permits succeed;
    /// the (N+1)th returns None (rejected). Once any permit is
    /// dropped, the next try succeeds again.
    #[test]
    fn cap_rejects_beyond_n_concurrent_then_recovers_on_drop() {
        let ctx = ctx_with_cap(3);
        // Acquire 3 — all succeed.
        let p1 = ctx.try_acquire_cover_forward().unwrap();
        let p2 = ctx.try_acquire_cover_forward().unwrap();
        let p3 = ctx.try_acquire_cover_forward().unwrap();
        assert!(p1.is_some());
        assert!(p2.is_some());
        assert!(p3.is_some());
        // 4th — rejected (cap reached, semaphore drained).
        let r4 = ctx.try_acquire_cover_forward();
        assert!(r4.is_none(), "4th acquire on cap=3 should reject");
        // Release one permit; next acquire succeeds.
        drop(p2);
        let p_recovered = ctx.try_acquire_cover_forward();
        assert!(
            matches!(p_recovered, Some(Some(_))),
            "release-then-reacquire should succeed: {p_recovered:?}"
        );
    }

    /// Cap of 0 → every cover-forward request is rejected
    /// (the "drop everything routed-to-cover" operator stance).
    #[test]
    fn cap_zero_rejects_all() {
        let ctx = ctx_with_cap(0);
        for _ in 0..10 {
            let r = ctx.try_acquire_cover_forward();
            assert!(r.is_none(), "cap=0 must reject every request");
        }
    }

    /// Cap of 1 → exactly one concurrent permit. Smallest non-
    /// degenerate value; useful for testing the
    /// rejection-then-recovery edge.
    #[test]
    fn cap_one_serializes_concurrent_requests() {
        let ctx = ctx_with_cap(1);
        let p = ctx.try_acquire_cover_forward().unwrap();
        assert!(p.is_some());
        assert!(ctx.try_acquire_cover_forward().is_none());
        drop(p);
        assert!(matches!(ctx.try_acquire_cover_forward(), Some(Some(_))));
    }
}
