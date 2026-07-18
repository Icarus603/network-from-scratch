//! β-profile (QUIC) bench server + client.
//!
//! The server is a single accept loop that echos every record it
//! receives — no congestion-controller magic, no rate-limiting, no
//! cover-forward. The point is to measure the carrier's raw throughput
//! ceiling, not exercise the policy layer.
//!
//! The client connects, blasts a configurable payload in chunks,
//! drains the echo, and prints the structured [`RunReport`] as JSON.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use proteus_transport_alpha::client::ClientConfig;
use proteus_transport_alpha::server::{ServerCtx, ServerKeys};
use proteus_transport_alpha::ProfileHint;
use proteus_transport_beta::{client as beta_client, server as beta_server, PerfProfile};

use crate::report::RunReport;

/// Errors from running the β bench harness. Distinct from
/// `BetaError` so the bench CLI can attach its own context (which
/// stage failed, what the operator should check) without leaking
/// transport-layer details.
#[derive(Debug, thiserror::Error)]
pub enum BenchError {
    #[error("cert generation: {0}")]
    Cert(String),
    #[error("server bind: {0}")]
    Bind(String),
    #[error("server serve loop: {0}")]
    Serve(String),
    #[error("client connect: {0}")]
    Connect(String),
    #[error("send: {0}")]
    Send(String),
    #[error("recv: {0}")]
    Recv(String),
    #[error("hex decode of pinned cert: {0}")]
    HexDecode(String),
}

/// One handful of `(cert_chain, private_key, public_key_hex)`. The
/// public-key-hex is for the operator to copy-paste into the client
/// invocation when the client + server run on different hosts.
pub struct BenchCert {
    pub chain: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
    pub leaf_hex: String,
}

/// Server identity exported for the cross-host bench client. All
/// fields are public-key material — safe to print to stdout / copy
/// into the client invocation. The `pq_fingerprint` is redundant
/// (= SHA-256 of `mlkem_pk_bytes`) but bundled here so the client
/// can fail fast on a copy-paste error without doing the hash itself.
///
/// Wire format (printed by `bench beta-server` as banner lines):
///
/// ```text
/// BENCH_SERVER_LISTEN_ADDR=<host:port>
/// BENCH_SERVER_LEAF_CERT_HEX=<hex(DER)>
/// BENCH_SERVER_MLKEM_PK_HEX=<hex(1184 bytes)>
/// BENCH_SERVER_X25519_PUB_HEX=<hex(32 bytes)>
/// BENCH_SERVER_PQ_FINGERPRINT_HEX=<hex(32 bytes)>
/// ```
///
/// The client reads them via `--server-mlkem-pk-hex <hex>`,
/// `--server-x25519-pub-hex <hex>`, `--server-pq-fingerprint-hex
/// <hex>`, `--server-leaf-cert-hex <hex>`, `--server-addr <addr>`.
/// Field names map directly so a grep / sed pipeline between the
/// two banners is trivial.
#[derive(Clone)]
pub struct ExportedServerIdentity {
    pub mlkem_pk_bytes: Vec<u8>,
    pub x25519_pub: [u8; 32],
    pub pq_fingerprint: [u8; 32],
}

impl ExportedServerIdentity {
    /// Hex-encode each field as a fixed-prefix `KEY=VALUE` line. The
    /// caller prints these to stdout AFTER the listener has bound so
    /// the operator can copy them while the server is alive.
    #[must_use]
    pub fn banner(&self, listen_addr: SocketAddr, leaf_cert_hex: &str) -> String {
        format!(
            "BENCH_SERVER_LISTEN_ADDR={addr}\n\
             BENCH_SERVER_LEAF_CERT_HEX={leaf}\n\
             BENCH_SERVER_MLKEM_PK_HEX={mlkem}\n\
             BENCH_SERVER_X25519_PUB_HEX={x25519}\n\
             BENCH_SERVER_PQ_FINGERPRINT_HEX={pq}\n",
            addr = listen_addr,
            leaf = leaf_cert_hex,
            mlkem = hex::encode(&self.mlkem_pk_bytes),
            x25519 = hex::encode(self.x25519_pub),
            pq = hex::encode(self.pq_fingerprint),
        )
    }
}

/// Mint a self-signed cert with SAN `localhost` and (optionally)
/// `extra_san`. Used by both the bench server (which presents the
/// cert) and the operator who must pin it on the client side via
/// `--pin-cert-hex <hex>`. Same `generate_simple_self_signed` shape
/// as the in-tree throughput-smoke tests so the bench harness and
/// the in-process tests both validate the same TLS path.
pub fn mint_self_signed(extra_san: Option<&str>) -> Result<BenchCert, BenchError> {
    let mut sans = vec!["localhost".to_string()];
    if let Some(s) = extra_san {
        sans.push(s.to_string());
    }
    let ck = generate_simple_self_signed(sans).map_err(|e| BenchError::Cert(e.to_string()))?;
    let cert_der_bytes = ck.cert.der().to_vec();
    let leaf_hex = hex::encode(&cert_der_bytes);
    let cert = CertificateDer::from(cert_der_bytes);
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));
    Ok(BenchCert {
        chain: vec![cert],
        key,
        leaf_hex,
    })
}

/// Decode a leaf cert DER provided by the operator on the client side
/// (output by the server's `bench server` startup banner).
///
/// Returns one `CertificateDer` ready to feed to `connect`. The same
/// bytes the server presents must round-trip cleanly here; we do NOT
/// verify the operator-supplied bytes parse as X.509 — rustls does
/// that during the handshake and surfaces a clearer error than we
/// could here. Our job is just hex-to-bytes.
pub fn decode_pinned_cert(hex_str: &str) -> Result<CertificateDer<'static>, BenchError> {
    let bytes = hex::decode(hex_str).map_err(|e| BenchError::HexDecode(e.to_string()))?;
    Ok(CertificateDer::from(bytes))
}

/// Bind a β server and spin its accept loop forever (or until the
/// runtime is torn down). The handler echos every record. Used by the
/// bench CLI's `beta-server` subcommand.
///
/// Returns:
///   - the bound local address (so the CLI can print it for the
///     operator),
///   - the exported server identity (so the CLI can print the
///     copy-paste banner the cross-host client consumes),
///   - a future that drives the accept loop. The caller is expected
///     to spawn the future on the runtime and either `.await` it
///     (blocking the CLI on the loop, the typical case) or pair it
///     with a shutdown signal.
pub async fn spawn_echo_server(
    bind: SocketAddr,
    cert: BenchCert,
    perf: PerfProfile,
) -> Result<
    (
        SocketAddr,
        ExportedServerIdentity,
        impl std::future::Future<Output = Result<(), BenchError>>,
    ),
    BenchError,
> {
    let server_keys = ServerKeys::generate();
    let exported = ExportedServerIdentity {
        mlkem_pk_bytes: server_keys.mlkem_pk_bytes.clone(),
        x25519_pub: server_keys.x25519_pub,
        pq_fingerprint: server_keys.pq_fingerprint,
    };
    let ctx = Arc::new(ServerCtx::new(server_keys));

    let endpoint = beta_server::make_endpoint_with_perf(bind, cert.chain.clone(), cert.key, perf)
        .map_err(|e| BenchError::Bind(e.to_string()))?;
    let local = endpoint
        .local_addr()
        .map_err(|e| BenchError::Bind(e.to_string()))?;

    let server_fut = async move {
        beta_server::serve(endpoint, ctx, |mut session| async move {
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
        })
        .await
        .map_err(|e| BenchError::Serve(e.to_string()))
    };

    Ok((local, exported, server_fut))
}

/// Cross-host bench client. Connects to a server brought up via
/// `bench beta-server` (which prints the identity banner) and runs
/// one bench round-trip. Operator copies the banner fields verbatim
/// onto the client command line.
///
/// `server_name` MUST match the SAN baked into the server's cert
/// (today's `mint_self_signed` uses `localhost`; for a cross-host
/// deploy the operator passes a SAN like the server's hostname or
/// IP via the not-yet-exposed `extra_san` of `mint_self_signed`).
#[allow(clippy::too_many_arguments)]
pub async fn run_cross_host_bench(
    server_name: &str,
    server_addr: SocketAddr,
    pinned_leaf_cert: CertificateDer<'static>,
    server_mlkem_pk_bytes: Vec<u8>,
    server_x25519_pub: [u8; 32],
    server_pq_fingerprint: [u8; 32],
    payload_bytes: usize,
    chunk_bytes: usize,
    perf: PerfProfile,
    connect_timeout: Duration,
    total_timeout: Duration,
    recovery_probe_rounds: u32,
    recovery_tolerant_packet_threshold: u32,
    recovery_tolerant_time_threshold: f32,
) -> Result<RunReport, BenchError> {
    // Sanity-check the pq_fingerprint matches the supplied mlkem_pk.
    // Without this a typo / mismatched copy-paste would only surface
    // as an opaque "handshake failed" — much nicer to fail fast with
    // a clear message right at the boundary.
    let computed_fp = proteus_crypto::key_schedule::sha256(&server_mlkem_pk_bytes);
    if computed_fp != server_pq_fingerprint {
        return Err(BenchError::Connect(format!(
            "pq_fingerprint mismatch: supplied {} vs computed {} \
             from supplied mlkem_pk_bytes — check your copy-paste from \
             the bench server banner",
            hex::encode(server_pq_fingerprint),
            hex::encode(computed_fp),
        )));
    }

    let mut rng = rand_core::OsRng;
    let client_id_sk = proteus_crypto::sig::generate(&mut rng);
    let client_cfg = ClientConfig {
        server_mlkem_pk_bytes,
        server_x25519_pub,
        server_pq_fingerprint,
        client_id_sk,
        user_id: *b"benchcli",
        pow_difficulty: 0,
        profile_hint: ProfileHint::Beta,
    };

    let client = tokio::time::timeout(
        connect_timeout,
        beta_client::connect_with_timeout_and_perf(
            server_name,
            server_addr,
            vec![pinned_leaf_cert],
            client_cfg,
            connect_timeout,
            perf,
        ),
    )
    .await
    .map_err(|_| BenchError::Connect(format!("handshake timed out after {connect_timeout:?}")))?
    .map_err(|e| BenchError::Connect(e.to_string()))?;

    let (mut session, carrier) = client.into_session_and_carrier();
    let elapsed = blast_drain_once(
        &mut session.sender,
        &mut session.receiver,
        payload_bytes,
        chunk_bytes,
        total_timeout,
    )
    .await?;

    let bytes_per_sec = (payload_bytes as f64) / elapsed.as_secs_f64();
    let mib_per_sec = bytes_per_sec / (1024.0 * 1024.0);
    let gbps = bytes_per_sec * 8.0 / 1_000_000_000.0;

    // Best-effort teardown.
    let proteus_transport_alpha::session::AlphaSession { sender, .. } = session;
    let _ = sender.shutdown().await;

    if recovery_probe_rounds > 0 {
        for direction in [
            proteus_transport_beta::recovery::RecoveryDirection::ClientToServer,
            proteus_transport_beta::recovery::RecoveryDirection::ServerToClient,
        ] {
            let policy = proteus_transport_beta::recovery::RecoveryPolicy {
                reorder_tolerant: proteus_transport_beta::recovery::RecoveryThresholds {
                    packet_threshold: recovery_tolerant_packet_threshold,
                    time_threshold: recovery_tolerant_time_threshold,
                },
                ..proteus_transport_beta::recovery::RecoveryPolicy::default()
            };
            let mut selector =
                proteus_transport_beta::recovery::RecoverySelector::new(direction, policy)
                    .map_err(|error| BenchError::Connect(format!("recovery policy: {error:?}")))?;
            for round in 1..=u64::from(recovery_probe_rounds) {
                let decision = carrier
                    .run_matched_recovery_round(&mut selector, round)
                    .await
                    .map_err(|error| {
                        BenchError::Connect(format!(
                            "matched recovery probe round {round}: {error}"
                        ))
                    })?;
                tracing::info!(
                    round,
                    ?direction,
                    ?decision,
                    selected_profile = ?decision.profile(),
                    "β matched recovery decision"
                );
            }
        }
    }

    carrier.close();

    Ok(RunReport {
        profile: "beta",
        payload_bytes: payload_bytes as u64,
        chunk_bytes: chunk_bytes as u64,
        elapsed_secs: elapsed.as_secs_f64(),
        mib_per_sec,
        gbps,
        server_addr: server_addr.to_string(),
        perf_profile: format_perf_profile(perf),
        idle_timeout_secs: connect_timeout.as_secs(),
        connect_timeout_secs: connect_timeout.as_secs(),
        netem_c2s_packets_received: 0,
        netem_c2s_packets_dropped: 0,
        netem_s2c_packets_received: 0,
        netem_s2c_packets_dropped: 0,
    })
}

/// Shared inner loop: blast `payload_bytes` in `chunk_bytes`-sized
/// records, drain the echo with byte-pattern verification, return
/// the wall-clock elapsed between first send and last received byte.
/// Factored out so `run_same_host_bench` and `run_cross_host_bench`
/// can't drift apart in what they measure.
///
/// **Sequential variant** — send everything, THEN drain. Safe for β
/// because quinn's per-stream send window (64 MiB default, raised
/// up to 256 MiB by the bench knobs) buffers the whole payload
/// internally, so `send_record` never blocks waiting for the peer
/// to drain. For α (raw TCP / TLS), the kernel sndbuf is much
/// smaller (~128 KiB on macOS, 4-16 MiB on tuned Linux); sending
/// a multi-MiB payload sequentially deadlocks because the client
/// task can't service the echoed bytes coming back. α bench paths
/// use [`blast_drain_concurrent_once`] instead.
async fn blast_drain_once<S, R>(
    sender: &mut S,
    receiver: &mut R,
    payload_bytes: usize,
    chunk_bytes: usize,
    total_timeout: Duration,
) -> Result<Duration, BenchError>
where
    S: SenderLike,
    R: ReceiverLike,
{
    let mut payload = vec![0u8; payload_bytes];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = (i & 0xff) as u8;
    }

    let start = Instant::now();
    for chunk in payload.chunks(chunk_bytes) {
        tokio::time::timeout(total_timeout, sender.send_record(chunk))
            .await
            .map_err(|_| {
                BenchError::Send(format!("send stalled past total_timeout {total_timeout:?}"))
            })?
            .map_err(|e| BenchError::Send(e.to_string()))?;
    }
    tokio::time::timeout(total_timeout, sender.flush())
        .await
        .map_err(|_| {
            BenchError::Send(format!(
                "flush stalled past total_timeout {total_timeout:?}"
            ))
        })?
        .map_err(|e| BenchError::Send(e.to_string()))?;

    let mut got = 0usize;
    while got < payload_bytes {
        let rec = tokio::time::timeout(total_timeout, receiver.recv_record())
            .await
            .map_err(|_| {
                BenchError::Recv(format!("recv stalled past total_timeout {total_timeout:?}"))
            })?
            .map_err(|e| BenchError::Recv(e.to_string()))?
            .ok_or_else(|| BenchError::Recv("session closed before payload fully echoed".into()))?;
        for (i, b) in rec.iter().enumerate() {
            let idx = got + i;
            if *b != (idx & 0xff) as u8 {
                return Err(BenchError::Recv(format!(
                    "byte mismatch at offset {idx}: expected {:#x}, got {:#x}",
                    idx & 0xff,
                    *b
                )));
            }
        }
        got += rec.len();
    }
    Ok(start.elapsed())
}

/// Concurrent variant of [`blast_drain_once`] — owns sender + receiver
/// outright, spawns them onto independent futures, and joins. Required
/// for α-profile bench runs because raw TCP / TLS pumps deadlock when
/// the sender fills the kernel sndbuf and the receiver isn't being
/// serviced concurrently.
///
/// Generic over `Send` to allow a future `tokio::spawn` switch if we
/// want true parallel CPU execution; today both futures run on the
/// same task via `tokio::join!` which is enough to avoid the deadlock
/// (the kernel drains the receive path whenever the sender blocks
/// on sndbuf).
pub(crate) async fn blast_drain_concurrent_once<S, R>(
    mut sender: S,
    mut receiver: R,
    payload_bytes: usize,
    chunk_bytes: usize,
    total_timeout: Duration,
) -> Result<(S, R, Duration), BenchError>
where
    S: SenderLike + Send + 'static,
    R: ReceiverLike + Send + 'static,
{
    let payload_template_send: Vec<u8> = {
        let mut v = vec![0u8; payload_bytes];
        for (i, b) in v.iter_mut().enumerate() {
            *b = (i & 0xff) as u8;
        }
        v
    };
    let chunk_bytes_for_send = chunk_bytes;

    let start = Instant::now();
    let send_fut = async move {
        for chunk in payload_template_send.chunks(chunk_bytes_for_send) {
            tokio::time::timeout(total_timeout, sender.send_record(chunk))
                .await
                .map_err(|_| {
                    BenchError::Send(format!("send stalled past total_timeout {total_timeout:?}"))
                })?
                .map_err(|e| BenchError::Send(e.to_string()))?;
        }
        tokio::time::timeout(total_timeout, sender.flush())
            .await
            .map_err(|_| {
                BenchError::Send(format!(
                    "flush stalled past total_timeout {total_timeout:?}"
                ))
            })?
            .map_err(|e| BenchError::Send(e.to_string()))?;
        Ok::<S, BenchError>(sender)
    };
    let recv_fut = async move {
        let mut got = 0usize;
        while got < payload_bytes {
            let rec = tokio::time::timeout(total_timeout, receiver.recv_record())
                .await
                .map_err(|_| {
                    BenchError::Recv(format!("recv stalled past total_timeout {total_timeout:?}"))
                })?
                .map_err(|e| BenchError::Recv(e.to_string()))?
                .ok_or_else(|| {
                    BenchError::Recv("session closed before payload fully echoed".into())
                })?;
            for (i, b) in rec.iter().enumerate() {
                let idx = got + i;
                if *b != (idx & 0xff) as u8 {
                    return Err(BenchError::Recv(format!(
                        "byte mismatch at offset {idx}: expected {:#x}, got {:#x}",
                        idx & 0xff,
                        *b
                    )));
                }
            }
            got += rec.len();
        }
        Ok::<R, BenchError>(receiver)
    };
    let (send_res, recv_res) = tokio::join!(send_fut, recv_fut);
    let sender_back = send_res?;
    let receiver_back = recv_res?;
    Ok((sender_back, receiver_back, start.elapsed()))
}

/// Boxed-future return type for the `SenderLike` trait. Aliased to
/// keep the public trait signatures readable and satisfy clippy's
/// `type_complexity` lint.
pub type SendFut<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, std::io::Error>> + Send + 'a>>;

/// Trait shim so `blast_drain_once` can accept either an α-session's
/// AlphaSender<TcpStream> or β's AlphaSender<quinn::SendStream> without
/// pulling them both as generic parameters through the public API.
/// Only the two methods we need are exposed.
pub trait SenderLike {
    fn send_record<'a>(&'a mut self, rec: &'a [u8]) -> SendFut<'a, ()>;
    fn flush(&mut self) -> SendFut<'_, ()>;
}

/// Receiver-side counterpart. Returns `Ok(None)` on clean session
/// close, `Ok(Some(bytes))` on a delivered record.
pub trait ReceiverLike {
    fn recv_record(&mut self) -> SendFut<'_, Option<Vec<u8>>>;
}

// Blanket impls for the concrete α + β stream types via the
// concrete AlphaSender<W> / AlphaReceiver<R> the session crate
// exposes. Both wrap async send_record/recv_record returning their
// own error type; we erase to std::io::Error so the trait is simple.
impl<W> SenderLike for proteus_transport_alpha::session::AlphaSender<W>
where
    W: tokio::io::AsyncWrite + Unpin + Send,
{
    fn send_record<'a>(&'a mut self, rec: &'a [u8]) -> SendFut<'a, ()> {
        Box::pin(async move {
            // `send_record` returns the assigned record sequence
            // number; the bench discards it (correctness of the
            // sequence is enforced inside the AEAD layer).
            self.send_record(rec)
                .await
                .map(|_seq| ())
                .map_err(|e| std::io::Error::other(e.to_string()))
        })
    }
    fn flush(&mut self) -> SendFut<'_, ()> {
        Box::pin(async move {
            self.flush()
                .await
                .map_err(|e| std::io::Error::other(e.to_string()))
        })
    }
}

impl<R> ReceiverLike for proteus_transport_alpha::session::AlphaReceiver<R>
where
    R: tokio::io::AsyncRead + Unpin + Send,
{
    fn recv_record(&mut self) -> SendFut<'_, Option<Vec<u8>>> {
        Box::pin(async move {
            self.recv_record()
                .await
                .map_err(|e| std::io::Error::other(e.to_string()))
        })
    }
}

// Cross-host bench client was previously stubbed out with a comment
// pointing to this slot. Implemented above as `run_cross_host_bench`.

/// Single-host bench run (server + client share the in-process
/// `ServerKeys`). The matching cross-host variant lives in
/// `run_cross_host_bench` above — it consumes the [`ExportedServerIdentity`]
/// banner the `bench beta-server` subcommand emits and is fully
/// wired end-to-end.
///
/// Use this when the operator wants to measure raw Proteus β
/// throughput on a single dev box (e.g. confirm a `PerfProfile` tweak
/// doesn't regress vs the baseline) — same shape as the in-tree
/// `throughput_smoke` test but parameterized.
pub async fn run_same_host_bench(
    payload_bytes: usize,
    chunk_bytes: usize,
    perf: PerfProfile,
    connect_timeout: Duration,
    total_timeout: Duration,
) -> Result<RunReport, BenchError> {
    // Back-compat shim — forwards to _with_netem with a no-op
    // netem config (passthrough; no forwarder interposed).
    run_same_host_bench_with_netem(
        payload_bytes,
        chunk_bytes,
        perf,
        connect_timeout,
        total_timeout,
        crate::netem::NetemConfig::default(),
    )
    .await
}

/// Same as `run_same_host_bench` but interposes a UDP loss/delay
/// forwarder (see `crate::netem`) between client and server when
/// the supplied `NetemConfig` is non-noop. When `netem.is_noop()`,
/// behaves identically to the back-compat path — same code path,
/// no overhead.
///
/// The forwarder's stats are NOT surfaced in the returned
/// `RunReport` today (the report schema is append-only; adding a
/// netem stats nested object is a follow-up). Operators who care
/// about the per-direction drop counts run the harness via the
/// CLI which logs them on completion.
pub async fn run_same_host_bench_with_netem(
    payload_bytes: usize,
    chunk_bytes: usize,
    perf: PerfProfile,
    connect_timeout: Duration,
    total_timeout: Duration,
    netem: crate::netem::NetemConfig,
) -> Result<RunReport, BenchError> {
    let cert = mint_self_signed(None)?;
    let server_keys = ServerKeys::generate();
    let mlkem_pk_bytes = server_keys.mlkem_pk_bytes.clone();
    let pq_fingerprint = server_keys.pq_fingerprint;
    let server_x25519_pub = server_keys.x25519_pub;
    let ctx = Arc::new(ServerCtx::new(server_keys));

    let bind: SocketAddr = "127.0.0.1:0"
        .parse()
        .map_err(|e: std::net::AddrParseError| BenchError::Bind(e.to_string()))?;
    let endpoint = beta_server::make_endpoint_with_perf(bind, cert.chain.clone(), cert.key, perf)
        .map_err(|e| BenchError::Bind(e.to_string()))?;
    let server_real = endpoint
        .local_addr()
        .map_err(|e| BenchError::Bind(e.to_string()))?;

    let server_task = tokio::spawn(async move {
        let _ = beta_server::serve(endpoint, ctx, |mut session| async move {
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
        })
        .await;
    });

    // Decide the address the client dials: if netem is configured,
    // interpose a forwarder and dial THAT; otherwise dial the
    // server directly. Hold the NetemHandle for the lifetime of the
    // run so its tasks stay alive.
    let (local, netem_handle) = if netem.is_noop() {
        (server_real, None)
    } else {
        let h = crate::netem::spawn_forwarder(server_real, netem)
            .await
            .map_err(|e| BenchError::Bind(format!("netem forwarder bind: {e}")))?;
        (h.listen_addr, Some(h))
    };

    let mut rng = rand_core::OsRng;
    let client_id_sk = proteus_crypto::sig::generate(&mut rng);
    let client_cfg = ClientConfig {
        server_mlkem_pk_bytes: mlkem_pk_bytes,
        server_x25519_pub,
        server_pq_fingerprint: pq_fingerprint,
        client_id_sk,
        user_id: *b"benchcli",
        pow_difficulty: 0,
        profile_hint: ProfileHint::Beta,
    };

    let mut client = tokio::time::timeout(
        connect_timeout,
        beta_client::connect_with_timeout_and_perf(
            "localhost",
            local,
            vec![cert.chain[0].clone()],
            client_cfg,
            connect_timeout,
            perf,
        ),
    )
    .await
    .map_err(|_| BenchError::Connect(format!("handshake timed out after {connect_timeout:?}")))?
    .map_err(|e| BenchError::Connect(e.to_string()))?;

    let elapsed = blast_drain_once(
        &mut client.session.sender,
        &mut client.session.receiver,
        payload_bytes,
        chunk_bytes,
        total_timeout,
    )
    .await?;
    let elapsed_secs = elapsed.as_secs_f64();
    let bytes_per_sec = (payload_bytes as f64) / elapsed_secs;
    let mib_per_sec = bytes_per_sec / (1024.0 * 1024.0);
    let gbps = bytes_per_sec * 8.0 / 1_000_000_000.0;
    let (netem_c2s, netem_s2c) = match netem_handle.as_ref() {
        Some(handle) => (
            handle.c2s_stats.snapshot().await,
            handle.s2c_stats.snapshot().await,
        ),
        None => (
            crate::netem::NetemStats::default(),
            crate::netem::NetemStats::default(),
        ),
    };

    // Best-effort teardown so a fast bench loop doesn't accumulate
    // file descriptors.
    let proteus_transport_alpha::session::AlphaSession { sender, .. } = client.session;
    let _ = sender.shutdown().await;
    client.connection.close(0u32.into(), b"bench-done");
    drop(client.endpoint);
    server_task.abort();

    // Append netem label to perf_profile so the persisted JSONL
    // distinguishes baseline runs from netem-injected runs. The
    // RunReport schema's perf_profile field is a free-form
    // string by design; readers parse it for human auditing,
    // not as structured data.
    let mut perf_label = format_perf_profile(perf);
    if !netem.is_noop() {
        perf_label.push(',');
        perf_label.push_str(&netem.label());
    }

    Ok(RunReport {
        profile: "beta",
        payload_bytes: payload_bytes as u64,
        chunk_bytes: chunk_bytes as u64,
        elapsed_secs,
        mib_per_sec,
        gbps,
        server_addr: local.to_string(),
        perf_profile: perf_label,
        idle_timeout_secs: connect_timeout.as_secs(),
        connect_timeout_secs: connect_timeout.as_secs(),
        netem_c2s_packets_received: netem_c2s.packets_received,
        netem_c2s_packets_dropped: netem_c2s.packets_dropped,
        netem_s2c_packets_received: netem_s2c.packets_received,
        netem_s2c_packets_dropped: netem_s2c.packets_dropped,
    })
}

fn format_perf_profile(p: PerfProfile) -> String {
    format!(
        "pad={},mtu_init={},mtu_max={},ack_threshold={},spin={},stream_win={},conn_win={},cc={},brutal_target_mbps={}",
        p.pad_quic_datagrams_to_mtu,
        p.initial_mtu,
        p.mtu_upper_bound,
        p.ack_eliciting_threshold,
        p.allow_spin_bit,
        p.stream_receive_window_override
            .map(|n| format!("{}M", n / (1024 * 1024)))
            .unwrap_or_else(|| "default".to_string()),
        p.connection_receive_window_override
            .map(|n| format!("{}M", n / (1024 * 1024)))
            .unwrap_or_else(|| "default".to_string()),
        match p.congestion {
            proteus_transport_beta::CongestionKind::Bbr => "bbr",
            proteus_transport_beta::CongestionKind::Brutal => "brutal",
        },
        p.brutal_target_bps / 1_000_000,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_self_signed_produces_nonempty_chain_and_hex() {
        let c = mint_self_signed(None).expect("mint");
        assert_eq!(
            c.chain.len(),
            1,
            "self-signed should produce a 1-cert chain"
        );
        assert!(
            !c.leaf_hex.is_empty() && c.leaf_hex.len() & 1 == 0,
            "leaf_hex should be even-length non-empty hex: len={}",
            c.leaf_hex.len()
        );
    }

    #[test]
    fn decode_pinned_cert_round_trips_minted_bytes() {
        let c = mint_self_signed(None).unwrap();
        let decoded = decode_pinned_cert(&c.leaf_hex).expect("decode");
        assert_eq!(
            decoded.as_ref(),
            c.chain[0].as_ref(),
            "round-trip hex(leaf) → decode should equal original DER",
        );
    }

    #[test]
    fn decode_pinned_cert_rejects_odd_length_hex() {
        let bad = decode_pinned_cert("abc"); // odd length → invalid hex
        assert!(matches!(bad, Err(BenchError::HexDecode(_))));
    }

    #[test]
    fn decode_pinned_cert_rejects_non_hex_chars() {
        let bad = decode_pinned_cert("zzzz");
        assert!(matches!(bad, Err(BenchError::HexDecode(_))));
    }

    #[test]
    fn format_perf_profile_includes_every_knob() {
        let s = format_perf_profile(PerfProfile::default());
        assert!(s.contains("pad="));
        assert!(s.contains("mtu_init="));
        assert!(s.contains("mtu_max="));
        assert!(s.contains("ack_threshold="));
        assert!(s.contains("spin="));
    }

    #[test]
    fn exported_identity_banner_emits_all_five_lines() {
        // Synthesize a known-pattern identity so we can assert the
        // banner's hex output verbatim.
        let id = ExportedServerIdentity {
            mlkem_pk_bytes: vec![0xAB; 1184],
            x25519_pub: [0xCD; 32],
            pq_fingerprint: [0xEF; 32],
        };
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let banner = id.banner(addr, "deadbeef");

        // All five labels must appear, in order, each on its own line.
        let lines: Vec<&str> = banner.lines().collect();
        assert_eq!(lines.len(), 5, "banner should be 5 lines: {banner:?}");
        assert!(lines[0].starts_with("BENCH_SERVER_LISTEN_ADDR="));
        assert!(lines[0].ends_with("127.0.0.1:12345"));
        assert!(lines[1].starts_with("BENCH_SERVER_LEAF_CERT_HEX="));
        assert!(lines[1].ends_with("deadbeef"));
        assert!(lines[2].starts_with("BENCH_SERVER_MLKEM_PK_HEX="));
        assert!(lines[2].len() > "BENCH_SERVER_MLKEM_PK_HEX=".len() + 2000); // 1184 bytes → 2368 hex chars
        assert!(lines[3].starts_with("BENCH_SERVER_X25519_PUB_HEX="));
        assert!(lines[3].ends_with(&"cd".repeat(32)));
        assert!(lines[4].starts_with("BENCH_SERVER_PQ_FINGERPRINT_HEX="));
        assert!(lines[4].ends_with(&"ef".repeat(32)));
    }

    #[test]
    fn cross_host_bench_pq_fingerprint_mismatch_fails_fast() {
        // Smoke: a fingerprint mismatch should be caught BEFORE any
        // network I/O happens. We pass a fingerprint that disagrees
        // with the supplied mlkem_pk and expect Connect(...) error
        // with the mismatch language. The network params are dummies
        // (the function rejects before any of them are used).
        use std::net::Ipv4Addr;
        let mlkem_pk = vec![0xAB; 1184];
        let bogus_fp = [0u8; 32]; // SHA-256 of all-AB is definitely not zeros
        let addr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
        let fake_cert = CertificateDer::from(vec![0u8; 16]);

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt.block_on(async {
            run_cross_host_bench(
                "localhost",
                addr,
                fake_cert,
                mlkem_pk,
                [0u8; 32],
                bogus_fp,
                4 * 1024 * 1024,
                64 * 1024,
                PerfProfile::default(),
                Duration::from_secs(1),
                Duration::from_secs(1),
                0,
                10,
                1.125,
            )
            .await
            .expect_err("must fail on fingerprint mismatch")
        });
        match err {
            BenchError::Connect(msg) => assert!(
                msg.contains("pq_fingerprint mismatch"),
                "expected fingerprint-mismatch message, got: {msg}"
            ),
            other => panic!("expected Connect, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cross_host_bench_round_trips_over_loopback() {
        // End-to-end smoke for run_cross_host_bench using loopback as
        // a stand-in for two hosts. The path through spawn_echo_server
        // + run_cross_host_bench exactly mirrors what the cross-host
        // CLI does — bringing the server up, then dialing it with the
        // banner's identity bytes.
        let cert = mint_self_signed(None).expect("cert");
        // Clone the leaf BEFORE the server consumes the BenchCert.
        let leaf_for_client = cert.chain[0].clone();
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (local, identity, server_fut) = spawn_echo_server(bind, cert, PerfProfile::default())
            .await
            .expect("server");
        let server_task = tokio::spawn(server_fut);

        let report = run_cross_host_bench(
            "localhost",
            local,
            leaf_for_client,
            identity.mlkem_pk_bytes.clone(),
            identity.x25519_pub,
            identity.pq_fingerprint,
            4 * 1024 * 1024,
            64 * 1024,
            PerfProfile::default(),
            Duration::from_secs(30),
            Duration::from_secs(30),
            0,
            10,
            1.125,
        )
        .await
        .expect("cross-host bench should succeed on loopback");

        assert_eq!(report.profile, "beta");
        assert_eq!(report.payload_bytes, 4 * 1024 * 1024);
        assert!(report.mib_per_sec > 0.0);
        assert!(report.gbps > 0.0);
        // Server addr in the report matches what we dialed.
        assert_eq!(report.server_addr, local.to_string());

        server_task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cross_host_bench_round_trips_with_brutal_on_both_peers() {
        let cert = mint_self_signed(None).expect("cert");
        let leaf_for_client = cert.chain[0].clone();
        let perf = PerfProfile {
            congestion: proteus_transport_beta::CongestionKind::Brutal,
            brutal_target_bps: 100_000_000,
            ..PerfProfile::default()
        };
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (local, identity, server_fut) =
            spawn_echo_server(bind, cert, perf).await.expect("server");
        let server_task = tokio::spawn(server_fut);

        let report = run_cross_host_bench(
            "localhost",
            local,
            leaf_for_client,
            identity.mlkem_pk_bytes.clone(),
            identity.x25519_pub,
            identity.pq_fingerprint,
            4 * 1024 * 1024,
            64 * 1024,
            perf,
            Duration::from_secs(30),
            Duration::from_secs(30),
            0,
            10,
            1.125,
        )
        .await
        .expect("Brutal cross-host bench should succeed on loopback");

        assert_eq!(report.payload_bytes, 4 * 1024 * 1024);
        assert!(report.perf_profile.contains("cc=brutal"));
        assert!(report.mib_per_sec > 0.0);
        server_task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn same_host_bench_completes_with_positive_throughput() {
        // Small payload so this stays under CI's per-test timeout
        // while still being big enough that ratchet + handshake aren't
        // the dominant cost.
        let report = run_same_host_bench(
            4 * 1024 * 1024,
            64 * 1024,
            PerfProfile::default(),
            Duration::from_secs(30),
            Duration::from_secs(30),
        )
        .await
        .expect("bench should succeed on localhost");

        assert_eq!(report.profile, "beta");
        assert_eq!(report.payload_bytes, 4 * 1024 * 1024);
        assert!(
            report.mib_per_sec > 0.0,
            "throughput must be positive: {}",
            report.mib_per_sec
        );
        assert!(report.gbps > 0.0, "Gbps must be positive: {}", report.gbps);
        // Sanity: the JSON encoder works.
        let j = report.to_json();
        assert!(j.contains(r#""profile":"beta""#));
        assert!(j.contains(r#""payload_bytes":4194304"#));
    }

    /// Netem path: 0% loss + 0 ms delay should be functionally
    /// identical to the no-netem path (forwarder bypass is the
    /// `is_noop` short-circuit). Sanity-check that the
    /// `_with_netem` entry point with a no-op config produces a
    /// successful run.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn same_host_bench_with_noop_netem_works_like_baseline() {
        let report = run_same_host_bench_with_netem(
            4 * 1024 * 1024,
            64 * 1024,
            PerfProfile::default(),
            Duration::from_secs(30),
            Duration::from_secs(30),
            crate::netem::NetemConfig::default(),
        )
        .await
        .expect("noop-netem bench should succeed");
        assert!(report.mib_per_sec > 0.0);
        // No netem label in perf_profile when noop.
        assert!(
            !report.perf_profile.contains("loss="),
            "noop netem must NOT append loss/delay label: {}",
            report.perf_profile
        );
    }

    /// Real netem path: 50 ms one-way delay should add ~100 ms RTT
    /// to every send_record round-trip. The bench should still
    /// succeed (BBR tolerates RTT inflation; we're not dropping)
    /// AND the perf_profile string should carry the netem label.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn same_host_bench_with_50ms_delay_succeeds_with_netem_label() {
        // Small payload to stay under timeout — RTT inflation
        // matters more than throughput here.
        let report = run_same_host_bench_with_netem(
            256 * 1024,
            64 * 1024,
            PerfProfile::default(),
            Duration::from_secs(30),
            Duration::from_secs(30),
            crate::netem::NetemConfig {
                loss_pct: 0.0,
                delay: Duration::from_millis(50),
                seed: None,
            },
        )
        .await
        .expect("netem-delay bench should succeed");
        assert!(report.mib_per_sec > 0.0);
        assert!(
            report.perf_profile.contains("loss=0%,delay=50ms"),
            "expected netem label suffix: {}",
            report.perf_profile
        );
    }

    /// Real netem path with 5% loss. BBR should still recover and
    /// the bench should succeed (loss-tolerant by design). This is
    /// the headline use case — "how does Proteus β behave at 5%
    /// loss?".
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn same_host_bench_with_5pct_loss_succeeds() {
        let report = run_same_host_bench_with_netem(
            512 * 1024,
            64 * 1024,
            PerfProfile::default(),
            Duration::from_secs(60),
            Duration::from_secs(60),
            crate::netem::NetemConfig {
                loss_pct: 5.0,
                delay: Duration::from_millis(0),
                seed: None,
            },
        )
        .await
        .expect("5% loss bench should succeed");
        assert!(report.mib_per_sec > 0.0);
        assert!(report.perf_profile.contains("loss=5%"));
    }
}
