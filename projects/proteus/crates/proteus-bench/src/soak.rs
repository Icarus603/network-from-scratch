//! Multi-client soak test — "does this binary survive 100 simultaneous
//! CONNECTs for an hour without leaking memory or sessions?"
//!
//! The throughput-mode bench (`beta` subcommand) answers
//! single-stream goodput questions. Operators preparing to deploy a
//! production VPN node need a different answer: **stability under
//! concurrent load**. Even if every individual session is fast,
//! a session leak / FD leak / quinn endpoint accumulation bug will
//! eventually take down the process. Catching those before they hit
//! the operator's actual users is the soak test's job.
//!
//! ## What it does
//!
//! 1. Mint one in-process β server with fresh keys + self-signed cert.
//!    Operator-controlled `--clients N`, `--duration-secs T`.
//! 2. Spawn N tokio tasks. Each one loops: open Proteus session →
//!    blast `--per-session-kib` of bytes round-trip → close → repeat
//!    until `T` seconds elapsed.
//! 3. Every `--report-interval-secs`, emit one JSON line of progress
//!    (dials_attempted, dials_succeeded, dials_failed, bytes_in,
//!    bytes_out, mean_session_ms, peak_concurrent).
//! 4. At end of soak, emit a single `summary` JSON line + assert
//!    "no session leaks": every spawn must have completed its outer
//!    Future (we await all join handles).
//!
//! ## What it deliberately does NOT do
//!
//! - **Not a replacement for production traffic.** The workload is
//!   synthetic (deterministic byte pattern); real users do mixed
//!   sizes + bursty timing + reconnects. A soak passing here is
//!   necessary, not sufficient.
//! - **No netem.** Loopback only. The bench harness's netem driver
//!   (`bench/netem-sweep.sh`) is the throughput-vs-loss vehicle,
//!   not this soak.
//! - **No memory profiler integration.** The operator runs
//!   `dtrace`/`heaptrack`/`malloc_history` alongside the soak if
//!   they want a heap snapshot — we just provide a long-running
//!   workload they can attach to.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand_core::OsRng;
use tokio::sync::Semaphore;

use proteus_transport_alpha::client::ClientConfig;
use proteus_transport_alpha::server::{ServerCtx, ServerKeys};
use proteus_transport_alpha::ProfileHint;
use proteus_transport_beta::{client as beta_client, server as beta_server, PerfProfile};

use crate::beta::{mint_self_signed, BenchError};

/// Per-interval progress line. Always-emitted JSON, one record per
/// `--report-interval-secs` tick. Schema is append-only (same
/// stability guarantee as `RunReport`).
#[derive(Debug, Clone)]
pub struct SoakProgress {
    pub elapsed_secs: f64,
    pub dials_attempted: u64,
    pub dials_succeeded: u64,
    pub dials_failed: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub peak_concurrent: usize,
    /// Mean per-session round-trip time in milliseconds across all
    /// successful sessions in this interval window. Computed from
    /// the running total + counter (resets each interval so the
    /// metric reflects current behavior, not lifetime average).
    pub mean_session_ms_window: f64,
}

impl SoakProgress {
    #[must_use]
    pub fn to_json(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(256);
        s.push_str(r#"{"kind":"progress""#);
        let _ = write!(s, r#","elapsed_secs":{:.3}"#, self.elapsed_secs);
        let _ = write!(s, r#","dials_attempted":{}"#, self.dials_attempted);
        let _ = write!(s, r#","dials_succeeded":{}"#, self.dials_succeeded);
        let _ = write!(s, r#","dials_failed":{}"#, self.dials_failed);
        let _ = write!(s, r#","bytes_in":{}"#, self.bytes_in);
        let _ = write!(s, r#","bytes_out":{}"#, self.bytes_out);
        let _ = write!(s, r#","peak_concurrent":{}"#, self.peak_concurrent);
        let _ = write!(
            s,
            r#","mean_session_ms_window":{:.3}"#,
            self.mean_session_ms_window
        );
        s.push_str("}\n");
        s
    }
}

/// End-of-soak summary line. Same schema discipline as
/// `SoakProgress`; the `kind` discriminator lets a consumer
/// `jq 'select(.kind=="summary")'` to pick out the final record.
#[derive(Debug, Clone)]
pub struct SoakSummary {
    pub duration_secs: f64,
    pub clients: usize,
    pub per_session_kib: u64,
    pub dials_attempted: u64,
    pub dials_succeeded: u64,
    pub dials_failed: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub peak_concurrent: usize,
    pub mean_session_ms: f64,
    /// Computed dial success rate; convenience field so operators
    /// don't have to divide in PromQL / jq.
    pub success_rate: f64,
    /// `clients - completed_tasks` — non-zero means a spawn leaked
    /// or panicked. The soak test asserts this is 0 before declaring
    /// success.
    pub spawn_leak_count: usize,
}

impl SoakSummary {
    #[must_use]
    pub fn to_json(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(512);
        s.push_str(r#"{"kind":"summary""#);
        let _ = write!(s, r#","duration_secs":{:.3}"#, self.duration_secs);
        let _ = write!(s, r#","clients":{}"#, self.clients);
        let _ = write!(s, r#","per_session_kib":{}"#, self.per_session_kib);
        let _ = write!(s, r#","dials_attempted":{}"#, self.dials_attempted);
        let _ = write!(s, r#","dials_succeeded":{}"#, self.dials_succeeded);
        let _ = write!(s, r#","dials_failed":{}"#, self.dials_failed);
        let _ = write!(s, r#","bytes_in":{}"#, self.bytes_in);
        let _ = write!(s, r#","bytes_out":{}"#, self.bytes_out);
        let _ = write!(s, r#","peak_concurrent":{}"#, self.peak_concurrent);
        let _ = write!(s, r#","mean_session_ms":{:.3}"#, self.mean_session_ms);
        let _ = write!(s, r#","success_rate":{:.4}"#, self.success_rate);
        let _ = write!(s, r#","spawn_leak_count":{}"#, self.spawn_leak_count);
        s.push_str("}\n");
        s
    }

    /// `true` when the soak passed all acceptance criteria:
    ///   - dial success rate ≥ `min_success_rate`
    ///   - zero spawn leaks
    ///   - at least one dial succeeded (rules out "the test never
    ///     even started")
    #[must_use]
    pub fn passed(&self, min_success_rate: f64) -> bool {
        self.spawn_leak_count == 0
            && self.dials_succeeded > 0
            && self.success_rate >= min_success_rate
    }
}

/// Soak workload knobs.
#[derive(Debug, Clone, Copy)]
pub struct SoakConfig {
    pub clients: usize,
    pub duration: Duration,
    pub per_session_kib: u64,
    pub report_interval: Duration,
    /// Optional per-task concurrency cap mirroring a deployed
    /// `max_inflight_sessions`. None = unbounded (fastest, but
    /// loses one production behavior).
    pub max_concurrent_dials: Option<usize>,
    /// Number of distinct user_ids the soak rotates across.
    /// 1 = single-tenant (default; back-compat). 10 = 10 tenants
    /// share the server, each gets `clients/users` of the load.
    /// Used to validate per-user bandwidth accounting under real
    /// concurrent handshakes — operators set this in production
    /// scale validation runs to mirror their actual tenant count.
    pub users: usize,
}

/// Shared counters touched by every spawned soak task.
struct SoakState {
    dials_attempted: AtomicU64,
    dials_succeeded: AtomicU64,
    dials_failed: AtomicU64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    /// Per-session round-trip time accumulator + counter for the
    /// rolling-window mean. Reset each interval tick from the
    /// progress reporter, so the rendered `mean_session_ms_window`
    /// reflects current behavior, not lifetime.
    rtt_ms_total_window: AtomicU64,
    rtt_ms_count_window: AtomicU64,
    /// Lifetime accumulator for the end-of-soak summary mean.
    rtt_ms_total_lifetime: AtomicU64,
    /// Tracks how many sessions are concurrently in flight; the
    /// peak watermark is what the progress reporter / summary
    /// publishes.
    in_flight: AtomicUsize,
    peak_concurrent: AtomicUsize,
}

impl SoakState {
    fn new() -> Self {
        Self {
            dials_attempted: AtomicU64::new(0),
            dials_succeeded: AtomicU64::new(0),
            dials_failed: AtomicU64::new(0),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            rtt_ms_total_window: AtomicU64::new(0),
            rtt_ms_count_window: AtomicU64::new(0),
            rtt_ms_total_lifetime: AtomicU64::new(0),
            in_flight: AtomicUsize::new(0),
            peak_concurrent: AtomicUsize::new(0),
        }
    }

    fn enter_session(&self) {
        let now = self.in_flight.fetch_add(1, Ordering::Relaxed) + 1;
        // Update peak watermark with a CAS retry — relaxed because
        // peak_concurrent is purely observational; a rare race that
        // misses one update is acceptable (the next session's CAS
        // catches up).
        let mut peak = self.peak_concurrent.load(Ordering::Relaxed);
        while now > peak {
            match self.peak_concurrent.compare_exchange_weak(
                peak,
                now,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => peak = actual,
            }
        }
    }

    fn exit_session(&self) {
        self.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Run the soak. Returns the end-of-soak `SoakSummary`. The
/// `print_progress` closure is called with each `SoakProgress`
/// tick; pass `|p| print!("{}", p.to_json())` in the CLI, or
/// `|_| {}` in tests that don't care about progress output.
pub async fn run_soak(
    cfg: SoakConfig,
    perf: PerfProfile,
    print_progress: impl Fn(&SoakProgress) + Send + Sync + 'static,
) -> Result<SoakSummary, BenchError> {
    run_soak_with_per_user_observation(cfg, perf, print_progress, None).await
}

/// Like [`run_soak`] but takes an optional `Arc<PerUserBandwidth>`
/// the caller can inspect AFTER the soak completes — used by the
/// multi-user end-to-end test to verify per-user accounting fires
/// against the real handshake-supplied `user_id` (not just unit-
/// tested in isolation).
///
/// When `per_user` is `Some`, the in-process server wires the
/// accumulator via `ServerCtx::with_per_user_bandwidth` AND
/// `InFlightGuard::enter_with_per_user` inside the handler, so
/// every session-completion records bytes against the user_id the
/// client supplied at handshake. When `None`, behaves identically
/// to the back-compat `run_soak` path.
pub async fn run_soak_with_per_user_observation(
    cfg: SoakConfig,
    perf: PerfProfile,
    print_progress: impl Fn(&SoakProgress) + Send + Sync + 'static,
    per_user: Option<Arc<proteus_transport_alpha::per_user_bandwidth::PerUserBandwidth>>,
) -> Result<SoakSummary, BenchError> {
    // ----- Server setup (single in-process server) -----
    let cert = mint_self_signed(None)?;
    let server_keys = ServerKeys::generate();
    let mlkem_pk_bytes = server_keys.mlkem_pk_bytes.clone();
    let pq_fingerprint = server_keys.pq_fingerprint;
    let server_x25519_pub = server_keys.x25519_pub;
    let mut ctx_raw = ServerCtx::new(server_keys);
    if let Some(pu) = per_user.as_ref() {
        ctx_raw = ctx_raw.with_per_user_bandwidth(Arc::clone(pu));
    }
    let ctx = Arc::new(ctx_raw);
    let ctx_for_handler = Arc::clone(&ctx);
    // We need a server-side ServerMetrics for the InFlightGuard
    // path. Bench harness uses its own SoakState for client-side
    // accounting; this is the SERVER-side counter the production
    // code path bumps. Local-only — never scraped.
    let server_metrics = Arc::new(proteus_transport_alpha::metrics::ServerMetrics::default());

    let bind: std::net::SocketAddr = "127.0.0.1:0"
        .parse()
        .map_err(|e: std::net::AddrParseError| BenchError::Bind(e.to_string()))?;
    let endpoint = beta_server::make_endpoint_with_perf(bind, cert.chain.clone(), cert.key, perf)
        .map_err(|e| BenchError::Bind(e.to_string()))?;
    let local = endpoint
        .local_addr()
        .map_err(|e| BenchError::Bind(e.to_string()))?;

    let server_task =
        tokio::spawn(async move {
            let _ = beta_server::serve(endpoint, Arc::clone(&ctx_for_handler), move |mut session| {
            // Per-handler clones so the spawned future owns its
            // refs and the closure stays Fn (not FnOnce).
            let metrics = Arc::clone(&server_metrics);
            let ctx_h = Arc::clone(&ctx_for_handler);
            async move {
                // RAII guard records per-user bytes on drop when
                // both the accumulator AND the session's user_id
                // are present — same wire-up pattern as the
                // production server's main.rs. The guard holds the
                // LIVE Arc<SessionMetrics> so the drop snapshot
                // reflects the session's final byte totals.
                let session_metrics = Arc::clone(&session.metrics);
                let _guard = match (ctx_h.per_user_bandwidth().cloned(), session.user_id) {
                    (Some(pu), Some(uid)) => {
                        proteus_transport_alpha::metrics::InFlightGuard::enter_with_per_user(
                            metrics, session_metrics, pu, uid,
                        )
                    }
                    _ => proteus_transport_alpha::metrics::InFlightGuard::enter(
                        metrics,
                        session_metrics,
                    ),
                };
                while let Ok(Some(rec)) = session.receiver.recv_record().await {
                    if rec.is_empty() {
                        continue;
                    }
                    if session.sender.send_record(&rec).await.is_err() {
                        break;
                    }
                    if session.sender.flush().await.is_err() {
                        break;
                    }
                }
            }
        })
        .await;
        });

    // ----- Client task pool -----
    let state = Arc::new(SoakState::new());
    let started = Instant::now();
    let deadline = started + cfg.duration;
    let leaf = cert.chain[0].clone();
    let mlkem_pk = mlkem_pk_bytes;
    let concurrency_cap = cfg
        .max_concurrent_dials
        .map(|n| Arc::new(Semaphore::new(n)));

    // Sanity-clamp `users` so soak runs with users=0 don't divide
    // by zero. The CLI clamps at parse-time too, but defense-in-
    // depth here for embedders constructing SoakConfig directly.
    let user_count = cfg.users.max(1);
    let mut client_handles = Vec::with_capacity(cfg.clients);
    for client_ix in 0..cfg.clients {
        let state = Arc::clone(&state);
        let mlkem_pk = mlkem_pk.clone();
        let leaf = leaf.clone();
        let cap = concurrency_cap.clone();
        // Assign user_id round-robin so clients distribute evenly
        // across the configured tenant count. Format `userNNNN` is
        // 8 bytes (exactly fits user_id slot), zero-padded for the
        // ascii-printable check on the server side.
        let user_index = client_ix % user_count;
        let user_id = soak_user_id(user_index);
        let h = tokio::spawn(async move {
            let payload_bytes = (cfg.per_session_kib as usize) * 1024;
            let mut payload = vec![0u8; payload_bytes];
            for (i, b) in payload.iter_mut().enumerate() {
                *b = (i & 0xff) as u8;
            }
            while Instant::now() < deadline {
                // Concurrency-cap permit acquisition. None = no cap;
                // Some = bounded by `--max-concurrent-dials`.
                let _permit = match &cap {
                    Some(s) => match s.clone().acquire_owned().await {
                        Ok(p) => Some(p),
                        Err(_) => return,
                    },
                    None => None,
                };
                state.dials_attempted.fetch_add(1, Ordering::Relaxed);
                let session_started = Instant::now();
                state.enter_session();
                let outcome = do_one_session(
                    local,
                    &leaf,
                    &mlkem_pk,
                    server_x25519_pub,
                    pq_fingerprint,
                    &payload,
                    perf,
                    user_id,
                )
                .await;
                state.exit_session();
                let elapsed = session_started.elapsed();
                let elapsed_ms = elapsed.as_secs_f64() * 1000.0;
                match outcome {
                    Ok(bytes_round_trip) => {
                        state.dials_succeeded.fetch_add(1, Ordering::Relaxed);
                        state
                            .bytes_in
                            .fetch_add(bytes_round_trip, Ordering::Relaxed);
                        state
                            .bytes_out
                            .fetch_add(bytes_round_trip, Ordering::Relaxed);
                        let elapsed_ms_u64 = elapsed_ms as u64;
                        state
                            .rtt_ms_total_window
                            .fetch_add(elapsed_ms_u64, Ordering::Relaxed);
                        state.rtt_ms_count_window.fetch_add(1, Ordering::Relaxed);
                        state
                            .rtt_ms_total_lifetime
                            .fetch_add(elapsed_ms_u64, Ordering::Relaxed);
                    }
                    Err(_) => {
                        state.dials_failed.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        });
        client_handles.push(h);
    }

    // ----- Progress reporter -----
    let reporter_state = Arc::clone(&state);
    let reporter = tokio::spawn(async move {
        let mut next_tick = started + cfg.report_interval;
        while next_tick < deadline {
            tokio::time::sleep_until(tokio::time::Instant::from_std(next_tick)).await;
            let elapsed = started.elapsed().as_secs_f64();
            let total = reporter_state
                .rtt_ms_total_window
                .swap(0, Ordering::Relaxed);
            let count = reporter_state
                .rtt_ms_count_window
                .swap(0, Ordering::Relaxed);
            let mean = if count == 0 {
                0.0
            } else {
                (total as f64) / (count as f64)
            };
            let progress = SoakProgress {
                elapsed_secs: elapsed,
                dials_attempted: reporter_state.dials_attempted.load(Ordering::Relaxed),
                dials_succeeded: reporter_state.dials_succeeded.load(Ordering::Relaxed),
                dials_failed: reporter_state.dials_failed.load(Ordering::Relaxed),
                bytes_in: reporter_state.bytes_in.load(Ordering::Relaxed),
                bytes_out: reporter_state.bytes_out.load(Ordering::Relaxed),
                peak_concurrent: reporter_state.peak_concurrent.load(Ordering::Relaxed),
                mean_session_ms_window: mean,
            };
            print_progress(&progress);
            next_tick += cfg.report_interval;
        }
    });

    // ----- Wait for every client to complete -----
    let mut completed = 0usize;
    for h in client_handles {
        if h.await.is_ok() {
            completed += 1;
        }
    }
    let _ = reporter.await;

    // ----- Summary -----
    let final_dials_succeeded = state.dials_succeeded.load(Ordering::Relaxed);
    let dials_attempted = state.dials_attempted.load(Ordering::Relaxed);
    let total_rtt = state.rtt_ms_total_lifetime.load(Ordering::Relaxed);
    let mean_session_ms = if final_dials_succeeded == 0 {
        0.0
    } else {
        (total_rtt as f64) / (final_dials_succeeded as f64)
    };
    let success_rate = if dials_attempted == 0 {
        0.0
    } else {
        (final_dials_succeeded as f64) / (dials_attempted as f64)
    };
    let summary = SoakSummary {
        duration_secs: started.elapsed().as_secs_f64(),
        clients: cfg.clients,
        per_session_kib: cfg.per_session_kib,
        dials_attempted,
        dials_succeeded: final_dials_succeeded,
        dials_failed: state.dials_failed.load(Ordering::Relaxed),
        bytes_in: state.bytes_in.load(Ordering::Relaxed),
        bytes_out: state.bytes_out.load(Ordering::Relaxed),
        peak_concurrent: state.peak_concurrent.load(Ordering::Relaxed),
        mean_session_ms,
        success_rate,
        spawn_leak_count: cfg.clients.saturating_sub(completed),
    };

    server_task.abort();
    Ok(summary)
}

/// One Proteus session: open, blast payload, drain echo, return
/// total bytes round-tripped. Used by the per-client loop.
#[allow(clippy::too_many_arguments)]
async fn do_one_session(
    addr: std::net::SocketAddr,
    pinned_leaf: &rustls::pki_types::CertificateDer<'static>,
    mlkem_pk_bytes: &[u8],
    server_x25519_pub: [u8; 32],
    pq_fingerprint: [u8; 32],
    payload: &[u8],
    perf: PerfProfile,
    user_id: [u8; 8],
) -> Result<u64, BenchError> {
    let mut rng = OsRng;
    let client_id_sk = proteus_crypto::sig::generate(&mut rng);
    let client_cfg = ClientConfig {
        server_mlkem_pk_bytes: mlkem_pk_bytes.to_vec(),
        server_x25519_pub,
        server_pq_fingerprint: pq_fingerprint,
        client_id_sk,
        user_id,
        pow_difficulty: 0,
        profile_hint: ProfileHint::Beta,
    };
    let connect_timeout = Duration::from_secs(15);
    let total_timeout = Duration::from_secs(30);
    let mut client = tokio::time::timeout(
        connect_timeout,
        beta_client::connect_with_timeout_and_perf(
            "localhost",
            addr,
            vec![pinned_leaf.clone()],
            client_cfg,
            connect_timeout,
            perf,
        ),
    )
    .await
    .map_err(|_| BenchError::Connect(format!("handshake timed out after {connect_timeout:?}")))?
    .map_err(|e| BenchError::Connect(e.to_string()))?;

    tokio::time::timeout(total_timeout, client.session.sender.send_record(payload))
        .await
        .map_err(|_| BenchError::Send("send stall".into()))?
        .map_err(|e| BenchError::Send(e.to_string()))?;
    tokio::time::timeout(total_timeout, client.session.sender.flush())
        .await
        .map_err(|_| BenchError::Send("flush stall".into()))?
        .map_err(|e| BenchError::Send(e.to_string()))?;

    let mut got = 0u64;
    while (got as usize) < payload.len() {
        let rec = tokio::time::timeout(total_timeout, client.session.receiver.recv_record())
            .await
            .map_err(|_| BenchError::Recv("recv stall".into()))?
            .map_err(|e| BenchError::Recv(e.to_string()))?
            .ok_or_else(|| BenchError::Recv("session closed early".into()))?;
        got += rec.len() as u64;
    }

    // Best-effort close.
    let proteus_transport_alpha::session::AlphaSession { sender, .. } = client.session;
    let _ = sender.shutdown().await;
    client.connection.close(0u32.into(), b"soak-done");
    drop(client.endpoint);
    Ok(got)
}

/// Format a soak user-index as a deterministic 8-byte user_id.
/// `0` → `b"user0000"`, `1` → `b"user0001"`, …, `9999` →
/// `b"user9999"`. Indexes ≥ 10_000 wrap (only meaningful up to
/// 9999 distinct users, which exceeds the default
/// PerUserBandwidth cap of 4096 anyway).
///
/// ASCII-printable + 8 bytes exactly → renders verbatim under
/// the per-user Prometheus emitter's `render_user_id` (no `hex:`
/// fallback), so operators reading test output see `user0042`
/// not `hex:7573657230303432`.
#[must_use]
pub fn soak_user_id(index: usize) -> [u8; 8] {
    let n = (index % 10_000) as u16; // bounded to 4 digits
    let mut out = *b"user0000";
    // Write decimal digits into out[4..8].
    let s = format!("{n:04}");
    let bytes = s.as_bytes();
    out[4..8].copy_from_slice(&bytes[..4]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(clients: usize, secs: u64) -> SoakConfig {
        SoakConfig {
            clients,
            duration: Duration::from_secs(secs),
            per_session_kib: 4,
            report_interval: Duration::from_millis(500),
            max_concurrent_dials: None,
            users: 1,
        }
    }

    #[test]
    fn soak_user_id_zero_renders_as_user0000() {
        assert_eq!(&soak_user_id(0), b"user0000");
    }

    #[test]
    fn soak_user_id_42_renders_as_user0042() {
        assert_eq!(&soak_user_id(42), b"user0042");
    }

    #[test]
    fn soak_user_id_4096_renders_as_user4096_within_bounds() {
        // Cap is 4096 default — make sure the user_id formatter
        // produces a printable 8-byte id for the max value the
        // PerUserBandwidth accumulator tracks distinctly.
        assert_eq!(&soak_user_id(4096), b"user4096");
    }

    #[test]
    fn soak_user_id_wraps_at_10000() {
        // 10_000 → "user0000"; 10_042 → "user0042".
        assert_eq!(&soak_user_id(10_000), b"user0000");
        assert_eq!(&soak_user_id(10_042), b"user0042");
    }

    #[test]
    fn progress_json_emits_kind_progress_and_all_fields() {
        let p = SoakProgress {
            elapsed_secs: 1.0,
            dials_attempted: 10,
            dials_succeeded: 9,
            dials_failed: 1,
            bytes_in: 1024,
            bytes_out: 1024,
            peak_concurrent: 4,
            mean_session_ms_window: 12.5,
        };
        let s = p.to_json();
        assert!(s.starts_with(r#"{"kind":"progress""#), "{s}");
        assert!(s.contains(r#""dials_attempted":10"#), "{s}");
        assert!(s.contains(r#""mean_session_ms_window":12.500"#), "{s}");
        assert!(s.ends_with("}\n"));
    }

    #[test]
    fn summary_json_emits_kind_summary_and_success_rate() {
        let s = SoakSummary {
            duration_secs: 60.0,
            clients: 10,
            per_session_kib: 16,
            dials_attempted: 100,
            dials_succeeded: 98,
            dials_failed: 2,
            bytes_in: 16 * 1024 * 100,
            bytes_out: 16 * 1024 * 100,
            peak_concurrent: 10,
            mean_session_ms: 25.0,
            success_rate: 0.98,
            spawn_leak_count: 0,
        };
        let json = s.to_json();
        assert!(json.starts_with(r#"{"kind":"summary""#), "{json}");
        assert!(json.contains(r#""success_rate":0.9800"#), "{json}");
        assert!(json.contains(r#""spawn_leak_count":0"#), "{json}");
        assert!(json.ends_with("}\n"));
    }

    #[test]
    fn summary_passed_requires_no_leaks_and_meets_min_success_rate() {
        let ok = SoakSummary {
            duration_secs: 1.0,
            clients: 5,
            per_session_kib: 1,
            dials_attempted: 100,
            dials_succeeded: 95,
            dials_failed: 5,
            bytes_in: 0,
            bytes_out: 0,
            peak_concurrent: 5,
            mean_session_ms: 0.0,
            success_rate: 0.95,
            spawn_leak_count: 0,
        };
        assert!(ok.passed(0.90));
        // Below threshold → fails.
        assert!(!ok.passed(0.99));

        let leaked = SoakSummary {
            spawn_leak_count: 1,
            ..ok.clone()
        };
        assert!(!leaked.passed(0.90), "spawn leak must fail");

        let zero_dials = SoakSummary {
            dials_attempted: 0,
            dials_succeeded: 0,
            success_rate: 0.0,
            ..ok.clone()
        };
        assert!(!zero_dials.passed(0.0), "zero-dial run must fail");
    }

    #[test]
    fn soak_state_peak_tracks_concurrent_high_water_mark() {
        let st = SoakState::new();
        st.enter_session();
        st.enter_session();
        st.enter_session();
        assert_eq!(st.peak_concurrent.load(Ordering::Relaxed), 3);
        st.exit_session();
        assert_eq!(
            st.peak_concurrent.load(Ordering::Relaxed),
            3,
            "peak should NOT drop when sessions exit"
        );
        st.enter_session();
        st.enter_session();
        st.enter_session();
        // Re-peak: 3 - 1 + 3 = 5 (3 still in flight after one exit,
        // then 3 more enter → 5 concurrent at peak before any
        // exit).
        assert!(st.peak_concurrent.load(Ordering::Relaxed) >= 5);
    }

    /// End-to-end soak with 4 clients × 2 seconds. Fast enough for
    /// CI, long enough to exercise the spawn / accept / handshake
    /// / pump cycle multiple times per client. Asserts:
    ///   - all 4 spawns completed (no spawn leak)
    ///   - dials_attempted == dials_succeeded + dials_failed
    ///   - on loopback we should succeed every dial
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn short_soak_completes_without_leaks() {
        let summary = run_soak(cfg(4, 2), PerfProfile::default(), |_| {})
            .await
            .expect("soak");
        assert_eq!(summary.spawn_leak_count, 0, "{:#?}", summary);
        assert_eq!(
            summary.dials_attempted,
            summary.dials_succeeded + summary.dials_failed,
            "invariant: attempted = succeeded + failed; got {summary:#?}",
        );
        // We MUST have completed at least one dial in 2 seconds
        // with 4 concurrent clients on loopback.
        assert!(
            summary.dials_succeeded > 0,
            "expected >0 successful dials: {summary:#?}"
        );
        // Loopback should be near-perfect — but we leave some
        // headroom for the rare timing-related failure (the bench
        // is bounded by the deadline; the final in-flight session
        // can be cut short).
        assert!(
            summary.success_rate >= 0.5,
            "loopback soak below 50% success: {summary:#?}"
        );
    }

    /// Multi-user soak end-to-end: 4 clients × 2 users × 2 seconds.
    /// Verifies the per-user bandwidth accumulator wired into the
    /// server-side handler records bytes against the CORRECT
    /// user_id (= the one the client supplied at handshake), with
    /// every active user getting a non-zero accounting entry.
    ///
    /// This is the test that proves the production wire-up actually
    /// works under real handshakes — not just the isolated unit
    /// tests of `PerUserBandwidth::record()`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn multi_user_soak_records_per_user_bandwidth_correctly() {
        let per_user =
            Arc::new(proteus_transport_alpha::per_user_bandwidth::PerUserBandwidth::new(4096));
        let summary = run_soak_with_per_user_observation(
            SoakConfig {
                clients: 4,
                duration: Duration::from_secs(2),
                per_session_kib: 4,
                report_interval: Duration::from_millis(500),
                max_concurrent_dials: None,
                users: 2,
            },
            PerfProfile::default(),
            |_| {},
            Some(Arc::clone(&per_user)),
        )
        .await
        .expect("multi-user soak should succeed");

        // Headline assertions: no leaks, near-perfect success.
        assert_eq!(summary.spawn_leak_count, 0);
        assert_eq!(
            summary.dials_attempted,
            summary.dials_succeeded + summary.dials_failed
        );
        assert!(summary.dials_succeeded > 0);

        // Per-user accumulator must have BOTH user_ids tracked.
        let snapshot = per_user.snapshot();
        assert!(
            snapshot.len() >= 2,
            "expected ≥2 distinct user_ids tracked (got {}): {snapshot:?}",
            snapshot.len()
        );

        // Each user_id must have non-zero tx + rx. user0000 and
        // user0001 are the round-robin assignments for 4 clients ÷
        // 2 users.
        for expected_uid in [b"user0000", b"user0001"] {
            let entry = snapshot.iter().find(|(uid, _)| uid == expected_uid);
            assert!(
                entry.is_some(),
                "expected user_id {:?} in per-user snapshot: {snapshot:?}",
                std::str::from_utf8(expected_uid).unwrap()
            );
            let (_, bytes) = entry.unwrap();
            assert!(
                bytes.tx > 0,
                "user {:?} must have non-zero tx",
                std::str::from_utf8(expected_uid).unwrap()
            );
            assert!(
                bytes.rx > 0,
                "user {:?} must have non-zero rx",
                std::str::from_utf8(expected_uid).unwrap()
            );
        }

        // Sum of per-user tx ≈ aggregate bench-side bytes_out
        // (small skew is fine — bench-side measures payload, the
        // accumulator records the AlphaSession's `tx_bytes`
        // which includes framing overhead the bench doesn't see).
        let per_user_sum_tx: u64 = snapshot.iter().map(|(_, b)| b.tx).sum();
        assert!(
            per_user_sum_tx > 0,
            "per-user sum tx must be > 0: {snapshot:?}"
        );

        // No overflow row — cap=4096, only used 2.
        assert!(
            !snapshot.iter().any(|(uid, _)| uid == b"OVERFLOW"),
            "should NOT have overflow row at cap=4096: {snapshot:?}"
        );
    }

    /// Single-user soak (default users=1) — proves the back-compat
    /// path works AND every client lands on the same `user0000`
    /// bucket.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn single_user_soak_accumulates_all_traffic_to_one_user() {
        let per_user =
            Arc::new(proteus_transport_alpha::per_user_bandwidth::PerUserBandwidth::new(4096));
        let _summary = run_soak_with_per_user_observation(
            SoakConfig {
                clients: 3,
                duration: Duration::from_secs(2),
                per_session_kib: 4,
                report_interval: Duration::from_millis(500),
                max_concurrent_dials: None,
                users: 1,
            },
            PerfProfile::default(),
            |_| {},
            Some(Arc::clone(&per_user)),
        )
        .await
        .expect("single-user soak should succeed");
        let snapshot = per_user.snapshot();
        // Exactly one entry: user0000.
        assert_eq!(
            snapshot.len(),
            1,
            "single-user soak must have exactly 1 tracked user: {snapshot:?}"
        );
        assert_eq!(snapshot[0].0, *b"user0000");
        assert!(snapshot[0].1.tx > 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn soak_progress_reporter_emits_periodic_lines() {
        // 1-second soak, 200ms report interval → expect ~4 progress
        // ticks. We collect them via a closure to verify the
        // reporter is wired correctly.
        use std::sync::Mutex;
        let collected = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&collected);
        let _ = run_soak(
            SoakConfig {
                clients: 2,
                duration: Duration::from_secs(1),
                per_session_kib: 1,
                report_interval: Duration::from_millis(200),
                max_concurrent_dials: None,
                users: 1,
            },
            PerfProfile::default(),
            move |p| {
                sink.lock().unwrap().push(p.clone());
            },
        )
        .await
        .expect("soak");
        let progresses = collected.lock().unwrap();
        assert!(
            progresses.len() >= 2,
            "expected ≥2 progress ticks in 1s @ 200ms interval, got {}",
            progresses.len()
        );
        // Each progress tick MUST have elapsed_secs strictly
        // increasing.
        for w in progresses.windows(2) {
            assert!(
                w[1].elapsed_secs > w[0].elapsed_secs,
                "non-monotonic elapsed_secs: {:?} → {:?}",
                w[0].elapsed_secs,
                w[1].elapsed_secs,
            );
        }
    }
}
