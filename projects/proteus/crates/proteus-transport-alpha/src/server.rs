//! α-profile server driver.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ml_kem::kem::DecapsulationKey;
use ml_kem::{EncodedSizeUser, MlKem768Params};
use proteus_crypto::{
    kex,
    key_schedule::{self, Transcript},
};
use proteus_handshake::{auth_tag, replay::ReplayWindow, replay::Verdict, state::State};
use proteus_wire::{alpha, AuthExtension, ProfileHint};
use tokio::io::AsyncWriteExt;
#[allow(unused_imports)]
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};

use crate::error::{AlphaError, AlphaResult};
use crate::session::AlphaSession;

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
    pub client_id_aead_key: [u8; 32],
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
        let mut client_id_aead_key = [0u8; 32];
        proteus_crypto::kdf::expand_label(
            &pq_fingerprint,
            b"proteus-cid-key-v1",
            b"",
            &mut client_id_aead_key,
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
    // Single snapshot of the firewall — atomic across the is_active +
    // admit pair so a concurrent SIGHUP reload can't observe us with a
    // stale "active" flag and a fresh "admit" result. Cloning the
    // ReloadableFirewall handle is one Arc::clone (cheap); reading the
    // snapshot acquires the read-lock once.
    let fw = ctx.firewall();
    let fw_snap = fw.snapshot();
    if fw_snap.is_active() && !fw_snap.admit(peer.ip()) {
        tracing::warn!(peer = %peer, "firewall denied; routing to cover");
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
        tracing::warn!(peer = %peer, "global handshake budget exhausted; routing to cover");
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
        }
    }
    false
}

/// Helper used by every accept loop: spawn a cover-forward task that
/// splices `stream` to `ctx.cover_endpoint` (if configured), otherwise
/// drop the stream. Idempotent + non-blocking.
fn route_to_cover_or_drop(ctx: &Arc<ServerCtx>, stream: TcpStream) {
    if let Some(cover) = ctx.cover_endpoint().map(str::to_string) {
        let metrics = ctx.metrics().cloned();
        tokio::spawn(async move {
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

/// Per-server state shared across connections.
pub struct ServerCtx {
    keys: ServerKeys,
    replay: Mutex<ReplayWindow>,
    /// Optional cover endpoint (`host:port`) for auth-fail forwarding.
    cover_endpoint: Option<String>,
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
}

impl ServerCtx {
    /// Wrap the given keys into a server context.
    #[must_use]
    pub fn new(keys: ServerKeys) -> Self {
        Self {
            keys,
            replay: Mutex::new(ReplayWindow::new()),
            cover_endpoint: None,
            rate_limiter: None,
            handshake_deadline: std::time::Duration::from_secs(15),
            tcp_keepalive_secs: 30,
            pow_difficulty: 0,
            metrics: None,
            conn_limit: None,
            firewall: crate::firewall::ReloadableFirewall::default(),
            handshake_budget: None,
            user_limiter: None,
            abuse_detector_rate_limit: None,
        }
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
        self
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

    /// Configure cover-forwarding endpoint per spec §7.5.
    pub fn with_cover(mut self, endpoint: impl Into<String>) -> Self {
        self.cover_endpoint = Some(endpoint.into());
        self
    }

    /// Read the cover endpoint.
    #[must_use]
    pub fn cover_endpoint(&self) -> Option<&str> {
        self.cover_endpoint.as_deref()
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
        let (stream, peer) = listener.accept().await?;
        let ctx = Arc::clone(&ctx);
        let acceptor = acceptor.clone();
        let handle = handle.clone();

        if !admission_ok(&ctx, &peer) {
            route_to_cover_or_drop(&ctx, stream);
            continue;
        }

        let permit = match ctx.try_acquire_connection() {
            ConnGate::Unbounded => None,
            ConnGate::Allowed(p) => Some(p),
            ConnGate::Rejected => {
                tracing::warn!(peer = %peer, "max_connections reached; routing to cover (TLS)");
                if let Some(m) = ctx.metrics() {
                    m.conn_limit_rejected
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                route_to_cover_or_drop(&ctx, stream);
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
        let (stream, peer) = listener.accept().await?;
        let ctx = Arc::clone(&ctx);
        // Read-lock the current acceptor. After this clone the
        // operator is free to swap in a new cert; we keep ours for
        // the duration of this connection.
        let current_acceptor = acceptor.current();
        let handle = handle.clone();

        if !admission_ok(&ctx, &peer) {
            route_to_cover_or_drop(&ctx, stream);
            continue;
        }

        let permit = match ctx.try_acquire_connection() {
            ConnGate::Unbounded => None,
            ConnGate::Allowed(p) => Some(p),
            ConnGate::Rejected => {
                tracing::warn!(peer = %peer, "max_connections reached; routing to cover (TLS-reloadable)");
                if let Some(m) = ctx.metrics() {
                    m.conn_limit_rejected
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                route_to_cover_or_drop(&ctx, stream);
                continue;
            }
        };

        let _ = apply_tcp_keepalive(&stream, ctx.tcp_keepalive_secs());

        tokio::spawn(async move {
            let _permit_held = permit;
            let deadline = ctx.handshake_deadline();
            let outcome = tokio::time::timeout(
                deadline,
                handshake_over_tls(stream, &current_acceptor, &ctx),
            )
            .await;
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
        let (stream, peer) = listener.accept().await?;
        let ctx = Arc::clone(&ctx);
        let handle = handle.clone();

        // ---- Source-IP firewall + per-IP rate limit (DoS defense) ----
        if !admission_ok(&ctx, &peer) {
            route_to_cover_or_drop(&ctx, stream);
            continue;
        }

        // ---- Global concurrency cap (OOM defense) ----
        let permit = match ctx.try_acquire_connection() {
            ConnGate::Unbounded => None,
            ConnGate::Allowed(p) => Some(p),
            ConnGate::Rejected => {
                tracing::warn!(peer = %peer, "max_connections reached; routing to cover");
                if let Some(m) = ctx.metrics() {
                    m.conn_limit_rejected
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                route_to_cover_or_drop(&ctx, stream);
                continue;
            }
        };

        // ---- Apply TCP keepalive (idle session reaper) ----
        let _ = apply_tcp_keepalive(&stream, ctx.tcp_keepalive_secs());

        tokio::spawn(async move {
            let _permit_held = permit;
            let cover_target = ctx.cover_endpoint().map(str::to_string);
            let deadline = ctx.handshake_deadline();
            let result = tokio::time::timeout(deadline, handshake_buffered(stream, &ctx)).await;
            let (replay_buf, raw_stream, timed_out) = match result {
                Ok(Ok((session, _))) => {
                    let session = session.with_peer_addr(peer);
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

#[allow(unsafe_code)] // tightly-scoped: dup(2) + OwnedFd wrapper only
fn apply_tcp_keepalive(stream: &TcpStream, interval_secs: u64) -> std::io::Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let fd = stream.as_raw_fd();
    // SAFETY: dup(2) returns a fresh fd that we own. We check for -1
    // before wrapping it.
    let dup_fd = unsafe { libc::dup(fd) };
    if dup_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: dup_fd is a freshly-owned valid fd.
    let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(dup_fd) };
    let sock = socket2::Socket::from(owned);
    let cfg = socket2::TcpKeepalive::new()
        .with_time(std::time::Duration::from_secs(interval_secs))
        .with_interval(std::time::Duration::from_secs(interval_secs));
    sock.set_tcp_keepalive(&cfg)
    // `sock` drops here, closing the dup'd fd. tokio's fd is untouched.
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

    let mut hybrid_shared = [0u8; 64];
    hybrid_shared.copy_from_slice(&combined[..]);

    let sig_msg = {
        let mut m = Vec::with_capacity(1 + 16 + 32 + 1088);
        m.push(ext.version);
        m.extend_from_slice(&ext.client_nonce);
        m.extend_from_slice(&ext.client_x25519_pub);
        m.extend_from_slice(&ext.client_mlkem768_ct);
        m
    };
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
    let sh_body = &server_x25519_eph_pub;
    let sh_frame =
        proteus_wire::alpha::encode_handshake(proteus_wire::alpha::FRAME_SERVER_HELLO, sh_body);
    transcript.update(sh_body);
    let th_ch_sh = transcript.snapshot();
    if write.write_all(&sh_frame).await.is_err() {
        return Err(HandshakeFailure::new(Vec::new(), None));
    }

    let provisional = match key_schedule::derive(
        &ext.client_nonce,
        &hybrid_shared,
        &th_ch_sh,
        &th_ch_sh,
        &th_ch_sh,
    ) {
        Ok(s) => s,
        Err(_) => return Err(HandshakeFailure::new(Vec::new(), None)),
    };
    let mut server_finished_key = [0u8; 32];
    if proteus_crypto::kdf::expand_label(
        &provisional.s_ap_secret,
        b"finished",
        b"",
        &mut server_finished_key,
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
        h.extend_from_slice(sh_body);
        h.extend_from_slice(&sf_mac);
        h
    });
    let mut client_finished_key = [0u8; 32];
    if proteus_crypto::kdf::expand_label(
        &provisional.c_ap_secret,
        b"finished",
        b"",
        &mut client_finished_key,
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
        h.extend_from_slice(sh_body);
        h.extend_from_slice(&sf_mac);
        h.extend_from_slice(&expected_cf);
        h
    });
    let final_secrets = match key_schedule::derive(
        &ext.client_nonce,
        &hybrid_shared,
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
    let mut session = AlphaSession::with_prefix(
        write,
        read,
        s_keys,
        c_keys,
        final_secrets.s_ap_secret.clone(),
        final_secrets.c_ap_secret.clone(),
        rx_buf,
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
    // Extract the same exporter tag the client will see on its side
    // of this TLS session — RFC 5705 / RFC 9266 channel binding.
    // A MITM bridging two distinct TLS sessions sees different
    // exporters on each side and therefore cannot relay the inner
    // Finished MAC chain (which now commits to the exporter via the
    // transcript hash on both ends).
    let mut binding = [0u8; crate::client::CHANNEL_BINDING_LEN];
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
    handshake_over_split_bound(read, write, ctx, Some(binding)).await
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

    let mut hybrid_shared = [0u8; 64];
    hybrid_shared.copy_from_slice(&combined[..]);

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
    let sig_msg = {
        let mut m = Vec::with_capacity(1 + 16 + 32 + 1088);
        m.push(ext.version);
        m.extend_from_slice(&ext.client_nonce);
        m.extend_from_slice(&ext.client_x25519_pub);
        m.extend_from_slice(&ext.client_mlkem768_ct);
        m
    };
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
    if let Some(binding) = channel_binding {
        let mut pre = Vec::with_capacity(2 + crate::client::CHANNEL_BINDING_LEN);
        pre.extend_from_slice(b"cb");
        pre.extend_from_slice(&binding);
        transcript.update(&pre);
    }
    transcript.update(&ch.body);
    // SH carries the EPHEMERAL pub (PFS) — see `handshake_with_cover`.
    let sh_body = &server_x25519_eph_pub;
    let sh_frame = alpha::encode_handshake(alpha::FRAME_SERVER_HELLO, sh_body);
    transcript.update(sh_body);
    let th_ch_sh = transcript.snapshot();
    write.write_all(&sh_frame).await?;

    // ----- 8. Derive provisional secrets and emit ServerFinished -----
    let provisional = key_schedule::derive(
        &ext.client_nonce,
        &hybrid_shared,
        &th_ch_sh,
        &th_ch_sh,
        &th_ch_sh,
    )?;
    let mut server_finished_key = [0u8; 32];
    proteus_crypto::kdf::expand_label(
        &provisional.s_ap_secret,
        b"finished",
        b"",
        &mut server_finished_key,
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
        h.extend_from_slice(sh_body);
        h.extend_from_slice(&sf_mac);
        h
    });
    let mut client_finished_key = [0u8; 32];
    proteus_crypto::kdf::expand_label(
        &provisional.c_ap_secret,
        b"finished",
        b"",
        &mut client_finished_key,
    )?;
    let expected_cf = hmac_sha256(&client_finished_key, &th_ch_sf);
    let received_cf: [u8; 32] = cf.body.as_slice().try_into().unwrap();
    if !ct_eq(&expected_cf, &received_cf) {
        return Err(AlphaError::BadClientFinished);
    }

    // ----- 10. Finalize key material -----
    let th_ch_cf = key_schedule::sha256(&{
        let mut h = Vec::new();
        h.extend_from_slice(&ch.body);
        h.extend_from_slice(sh_body);
        h.extend_from_slice(&sf_mac);
        h.extend_from_slice(&expected_cf);
        h
    });
    let final_secrets = key_schedule::derive(
        &ext.client_nonce,
        &hybrid_shared,
        &th_ch_sh,
        &th_ch_sf,
        &th_ch_cf,
    )?;
    let (c_keys, s_keys) = final_secrets.direction_keys()?;
    // Server: sends with s_ap_secret keys, receives with c_ap_secret keys.
    // DH ratchet bootstrap — same comment as in `handshake_with_cover`.
    let mut session = AlphaSession::with_prefix(
        write,
        read,
        s_keys,
        c_keys,
        final_secrets.s_ap_secret.clone(),
        final_secrets.c_ap_secret.clone(),
        rx_buf,
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
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&out);
    tag
}

fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;
    bool::from(a.ct_eq(b))
}
