//! α-profile (TCP / TLS 1.3) bench server + client.
//!
//! Symmetric in shape with [`crate::beta`]: same `RunReport` schema,
//! same `blast_drain_once` inner loop, same banner protocol for the
//! cross-host variant. The differences are all carrier-mechanical:
//!
//! - **Two variants**: `raw-tcp` (no outer TLS — bench-only, matches
//!   the in-tree `throughput_smoke` test exactly so the bench number
//!   and the regression-floor are directly comparable) and `tls`
//!   (production-shape — TLS 1.3 outer + RFC 5705 channel binding).
//! - **Cert provisioning**: same `mint_self_signed` helper β uses;
//!   the leaf cert hex banner field is reused identically so an
//!   operator already familiar with `bench beta-server` can use
//!   `bench alpha-server-tls` with the same muscle memory.
//! - **`perf_profile` JSON field**: written as `"raw-tcp"` or
//!   `"tls-1.3-h2-http/1.1"` so a single `jq` query can split α-raw
//!   vs α-tls vs β-quic runs cleanly without inferring from the
//!   `profile` field alone.
//!
//! ## Why α-tls AND α-raw-tcp
//!
//! `raw-tcp` is the closest comparison to the in-tree throughput
//! smoke test — it answers "did a perf regression land?" without
//! the TLS overhead noise. `tls` answers "what does the operator
//! actually observe on their VPS?" — every production deploy MUST
//! use TLS (the spec §4.2 requires it; the validate CLI FAILs
//! without it). For operators making a real "should I upgrade
//! from VLESS+REALITY to Proteus?" decision, the tls number is
//! the only honest one — the raw-tcp number is a regression floor,
//! not a production claim.
//!
//! ## Cross-host TLS bench
//!
//! `run_cross_host_tls_bench` consumes the same 5-line identity
//! banner shape as β (`BENCH_SERVER_*_HEX`) plus the leaf cert hex
//! pinned by `--server-leaf-cert-hex`. The α-side TLS client uses
//! `tls::build_connector_with_ca_der` so the operator's self-signed
//! cert from `mint_self_signed` validates correctly without webpki
//! roots fallback — same trust path the production server.example.yaml
//! deployment uses (rustls + LE cert + matching SNI).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::CertificateDer;
use tokio::net::{TcpListener, TcpStream};

use proteus_transport_alpha::client::{self, ClientConfig};
use proteus_transport_alpha::server::{self, ServerCtx, ServerKeys};
use proteus_transport_alpha::tls as alpha_tls;
use proteus_transport_alpha::ProfileHint;

use crate::beta::{
    blast_drain_concurrent_once, mint_self_signed, BenchCert, BenchError, ExportedServerIdentity,
};
use crate::report::RunReport;

/// Wrapper around α `connect` so the bench reports a clean
/// `BenchError::Connect(...)` instead of the transport's internal
/// `AlphaError` type leaking into bench-side error handling.
async fn alpha_connect_raw(
    addr: SocketAddr,
    config: &ClientConfig,
) -> Result<
    proteus_transport_alpha::session::AlphaSession<
        tokio::net::tcp::OwnedReadHalf,
        tokio::net::tcp::OwnedWriteHalf,
    >,
    BenchError,
> {
    // Important: `client::connect` only accepts a `&str` target; convert
    // the SocketAddr back to that shape. We could also call
    // `handshake_over_tcp` directly with a freshly-opened TcpStream and
    // skip the addr->string->addr round-trip, which is what we do here
    // so the bench connect timing measures only the handshake, not DNS.
    let stream = TcpStream::connect(addr)
        .await
        .map_err(|e| BenchError::Connect(format!("TCP connect to {addr}: {e}")))?;
    client::handshake_over_tcp(stream, config)
        .await
        .map_err(|e| BenchError::Connect(format!("α handshake over raw TCP: {e}")))
}

/// Spawn an α echo server on the given listener. The handler echoes
/// every record back; matches `crate::beta::spawn_echo_server`'s shape
/// so cross-profile bench harnesses can use the same inner blast
/// pattern.
async fn spawn_alpha_raw_echo_server(
    listener: TcpListener,
    ctx: Arc<ServerCtx>,
) -> Result<(), BenchError> {
    server::serve(listener, ctx, |mut session| async move {
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
    .map_err(|e| BenchError::Serve(format!("α raw-TCP serve loop: {e}")))
}

/// Single-host α-profile bench (raw TCP, no outer TLS). Mints fresh
/// `ServerKeys` in-process, runs the server + client on the same
/// runtime, returns a `RunReport`. The `perf_profile` JSON field is
/// set to `"raw-tcp"` so downstream `jq` filters can distinguish this
/// run from the production-shape `tls` variant.
///
/// This variant is intentionally bench-only: production deploys
/// MUST use TLS (the server CLI's `validate` fails without a `tls:`
/// block — that's the protocol's identifying camouflage and any
/// real bench number must include it). Use `run_same_host_tls_bench`
/// for production-shaped numbers; this raw-TCP variant is for
/// isolating throughput regressions without TLS overhead noise.
pub async fn run_same_host_raw_tcp_bench(
    payload_bytes: usize,
    chunk_bytes: usize,
    connect_timeout: Duration,
    total_timeout: Duration,
) -> Result<RunReport, BenchError> {
    let server_keys = ServerKeys::generate();
    let mlkem_pk_bytes = server_keys.mlkem_pk_bytes.clone();
    let pq_fingerprint = server_keys.pq_fingerprint;
    let x25519_pub = server_keys.x25519_pub;
    let ctx = Arc::new(ServerCtx::new(server_keys));

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| BenchError::Bind(format!("TCP bind 127.0.0.1:0: {e}")))?;
    let local = listener
        .local_addr()
        .map_err(|e| BenchError::Bind(format!("local_addr: {e}")))?;

    let ctx_clone = Arc::clone(&ctx);
    let server_task =
        tokio::spawn(async move { spawn_alpha_raw_echo_server(listener, ctx_clone).await });

    let mut rng = rand_core::OsRng;
    let client_id_sk = proteus_crypto::sig::generate(&mut rng);
    let cfg = ClientConfig {
        server_mlkem_pk_bytes: mlkem_pk_bytes,
        server_x25519_pub: x25519_pub,
        server_pq_fingerprint: pq_fingerprint,
        client_id_sk,
        user_id: *b"benchalp",
        pow_difficulty: 0,
        profile_hint: ProfileHint::Alpha,
    };

    let session = tokio::time::timeout(connect_timeout, alpha_connect_raw(local, &cfg))
        .await
        .map_err(|_| {
            BenchError::Connect(format!("α handshake timed out after {connect_timeout:?}"))
        })??;

    let proteus_transport_alpha::session::AlphaSession {
        sender, receiver, ..
    } = session;

    let (sender, _receiver, elapsed) =
        blast_drain_concurrent_once(sender, receiver, payload_bytes, chunk_bytes, total_timeout)
            .await?;

    // Best-effort teardown — closing the sender signals EOF to the
    // server task, which then drops the session and the accept loop
    // continues running until we abort the task.
    let _ = sender.shutdown().await;
    server_task.abort();

    let bytes_per_sec = (payload_bytes as f64) / elapsed.as_secs_f64();
    let mib_per_sec = bytes_per_sec / (1024.0 * 1024.0);
    let gbps = bytes_per_sec * 8.0 / 1_000_000_000.0;

    Ok(RunReport {
        profile: "alpha",
        payload_bytes: payload_bytes as u64,
        chunk_bytes: chunk_bytes as u64,
        elapsed_secs: elapsed.as_secs_f64(),
        mib_per_sec,
        gbps,
        server_addr: local.to_string(),
        perf_profile: "raw-tcp".to_string(),
        idle_timeout_secs: total_timeout.as_secs(),
        connect_timeout_secs: connect_timeout.as_secs(),
        netem_c2s_packets_received: 0,
        netem_c2s_packets_dropped: 0,
        netem_s2c_packets_received: 0,
        netem_s2c_packets_dropped: 0,
    })
}

/// Single-host α-profile bench with TLS 1.3 outer wrapping the inner
/// Proteus handshake. This is the **production-shape** variant —
/// matches what `proteus-server run` does on the wire (TLS 1.3 +
/// ALPN h2/http/1.1 + RFC 5705 channel binding mixed into the inner
/// transcript). Operators making a real "is α faster than my current
/// REALITY setup?" decision read THIS number, not the raw-tcp one.
///
/// The cert is freshly minted via `mint_self_signed` (SAN
/// `localhost`); the client uses `build_connector_with_ca_der` to
/// pin it, matching the exact trust path the in-tree
/// `tls_end_to_end` integration test exercises.
pub async fn run_same_host_tls_bench(
    payload_bytes: usize,
    chunk_bytes: usize,
    connect_timeout: Duration,
    total_timeout: Duration,
) -> Result<RunReport, BenchError> {
    let cert = mint_self_signed(None)?;
    let BenchCert {
        chain,
        key,
        leaf_hex: _,
    } = cert;

    let acceptor = alpha_tls::build_acceptor(chain.clone(), key)
        .map_err(|e| BenchError::Cert(format!("build TLS acceptor: {e}")))?;
    // Pin the same self-signed cert on the client side. `chain[0]` is
    // the leaf — for a self-signed deployment the leaf IS the CA
    // (rcgen's `generate_simple_self_signed` produces a 1-element chain).
    let connector = alpha_tls::build_connector_with_ca_der(chain[0].clone())
        .map_err(|e| BenchError::Cert(format!("build TLS connector: {e}")))?;

    let server_keys = ServerKeys::generate();
    let mlkem_pk_bytes = server_keys.mlkem_pk_bytes.clone();
    let pq_fingerprint = server_keys.pq_fingerprint;
    let x25519_pub = server_keys.x25519_pub;
    let ctx = Arc::new(ServerCtx::new(server_keys));

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| BenchError::Bind(format!("TCP bind 127.0.0.1:0: {e}")))?;
    let local = listener
        .local_addr()
        .map_err(|e| BenchError::Bind(format!("local_addr: {e}")))?;

    let ctx_clone = Arc::clone(&ctx);
    let acceptor_clone = acceptor.clone();
    let server_task = tokio::spawn(async move {
        server::serve_tls(
            listener,
            ctx_clone,
            acceptor_clone,
            |mut session| async move {
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
            },
        )
        .await
        .map_err(|e| BenchError::Serve(format!("α TLS serve loop: {e}")))
    });

    let mut rng = rand_core::OsRng;
    let client_id_sk = proteus_crypto::sig::generate(&mut rng);
    let cfg = ClientConfig {
        server_mlkem_pk_bytes: mlkem_pk_bytes,
        server_x25519_pub: x25519_pub,
        server_pq_fingerprint: pq_fingerprint,
        client_id_sk,
        user_id: *b"benchatl",
        pow_difficulty: 0,
        profile_hint: ProfileHint::Alpha,
    };

    let stream = tokio::time::timeout(connect_timeout, TcpStream::connect(local))
        .await
        .map_err(|_| {
            BenchError::Connect(format!("TCP connect timed out after {connect_timeout:?}"))
        })?
        .map_err(|e| BenchError::Connect(format!("TCP connect to {local}: {e}")))?;
    let session = tokio::time::timeout(
        connect_timeout,
        client::handshake_over_tls(stream, &connector, "localhost", &cfg),
    )
    .await
    .map_err(|_| {
        BenchError::Connect(format!(
            "α TLS handshake timed out after {connect_timeout:?}"
        ))
    })?
    .map_err(|e| BenchError::Connect(format!("α TLS handshake: {e}")))?;

    let proteus_transport_alpha::session::AlphaSession {
        sender, receiver, ..
    } = session;

    let (sender, _receiver, elapsed) =
        blast_drain_concurrent_once(sender, receiver, payload_bytes, chunk_bytes, total_timeout)
            .await?;
    let _ = sender.shutdown().await;
    server_task.abort();

    let bytes_per_sec = (payload_bytes as f64) / elapsed.as_secs_f64();
    let mib_per_sec = bytes_per_sec / (1024.0 * 1024.0);
    let gbps = bytes_per_sec * 8.0 / 1_000_000_000.0;

    Ok(RunReport {
        profile: "alpha",
        payload_bytes: payload_bytes as u64,
        chunk_bytes: chunk_bytes as u64,
        elapsed_secs: elapsed.as_secs_f64(),
        mib_per_sec,
        gbps,
        server_addr: local.to_string(),
        perf_profile: "tls-1.3-h2-http/1.1".to_string(),
        idle_timeout_secs: total_timeout.as_secs(),
        connect_timeout_secs: connect_timeout.as_secs(),
        netem_c2s_packets_received: 0,
        netem_c2s_packets_dropped: 0,
        netem_s2c_packets_received: 0,
        netem_s2c_packets_dropped: 0,
    })
}

/// Bind an α-profile TLS bench server on the given SocketAddr and
/// return:
///   - the bound local address (for the CLI to print to the operator),
///   - the exported server identity (used in the cross-host banner),
///   - the freshly-minted leaf cert hex (for the operator to pin
///     client-side via `--server-leaf-cert-hex`),
///   - a future that drives the TLS serve loop forever.
///
/// Same banner-shape convention as β so the operator's `bench
/// alpha-server-tls` / `bench alpha-client-tls` flow mirrors
/// `bench beta-server` / `bench beta-client` exactly. Identity hex
/// fields are byte-identical between profiles (they're both
/// `ServerKeys`-derived); only the cert + the `--server-name` SAN
/// differ between α-TLS and β-QUIC.
pub async fn spawn_alpha_tls_echo_server(
    bind: SocketAddr,
    cert: BenchCert,
) -> Result<
    (
        SocketAddr,
        ExportedServerIdentity,
        String,
        impl std::future::Future<Output = Result<(), BenchError>>,
    ),
    BenchError,
> {
    let BenchCert {
        chain,
        key,
        leaf_hex,
    } = cert;
    let acceptor = alpha_tls::build_acceptor(chain, key)
        .map_err(|e| BenchError::Cert(format!("build TLS acceptor: {e}")))?;

    let server_keys = ServerKeys::generate();
    let exported = ExportedServerIdentity {
        mlkem_pk_bytes: server_keys.mlkem_pk_bytes.clone(),
        x25519_pub: server_keys.x25519_pub,
        pq_fingerprint: server_keys.pq_fingerprint,
    };
    let ctx = Arc::new(ServerCtx::new(server_keys));

    let listener = TcpListener::bind(bind)
        .await
        .map_err(|e| BenchError::Bind(format!("TCP bind {bind}: {e}")))?;
    let local = listener
        .local_addr()
        .map_err(|e| BenchError::Bind(format!("local_addr: {e}")))?;

    let serve_fut = async move {
        server::serve_tls(listener, ctx, acceptor, |mut session| async move {
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
        .map_err(|e| BenchError::Serve(format!("α TLS serve loop: {e}")))
    };

    Ok((local, exported, leaf_hex, serve_fut))
}

/// Cross-host α-profile TLS bench client. Consumes the banner the
/// matching `spawn_alpha_tls_echo_server` printed (operator copy-
/// pastes the 5 hex fields onto the client command line). Pins the
/// server's self-signed leaf cert via the supplied `pinned_leaf` —
/// matches the trust path `proteus-client run` uses when its
/// `trusted_ca:` is a self-signed CA bundle.
///
/// Same pq_fingerprint guard as the β client: a copy-paste typo in
/// either `--server-mlkem-pk-hex` or `--server-pq-fingerprint-hex`
/// is caught at the boundary with a clear error instead of an
/// opaque "α handshake failed" 30 s later.
#[allow(clippy::too_many_arguments)]
pub async fn run_cross_host_tls_bench(
    server_name: &str,
    server_addr: SocketAddr,
    pinned_leaf: CertificateDer<'static>,
    server_mlkem_pk_bytes: Vec<u8>,
    server_x25519_pub: [u8; 32],
    server_pq_fingerprint: [u8; 32],
    payload_bytes: usize,
    chunk_bytes: usize,
    connect_timeout: Duration,
    total_timeout: Duration,
) -> Result<RunReport, BenchError> {
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

    let connector = alpha_tls::build_connector_with_ca_der(pinned_leaf)
        .map_err(|e| BenchError::Cert(format!("build TLS connector: {e}")))?;

    let mut rng = rand_core::OsRng;
    let client_id_sk = proteus_crypto::sig::generate(&mut rng);
    let cfg = ClientConfig {
        server_mlkem_pk_bytes,
        server_x25519_pub,
        server_pq_fingerprint,
        client_id_sk,
        user_id: *b"benchatl",
        pow_difficulty: 0,
        profile_hint: ProfileHint::Alpha,
    };

    let stream = tokio::time::timeout(connect_timeout, TcpStream::connect(server_addr))
        .await
        .map_err(|_| {
            BenchError::Connect(format!("TCP connect timed out after {connect_timeout:?}"))
        })?
        .map_err(|e| BenchError::Connect(format!("TCP connect to {server_addr}: {e}")))?;

    let session = tokio::time::timeout(
        connect_timeout,
        client::handshake_over_tls(stream, &connector, server_name, &cfg),
    )
    .await
    .map_err(|_| {
        BenchError::Connect(format!(
            "α TLS handshake timed out after {connect_timeout:?}"
        ))
    })?
    .map_err(|e| BenchError::Connect(format!("α TLS handshake: {e}")))?;

    let proteus_transport_alpha::session::AlphaSession {
        sender, receiver, ..
    } = session;
    let (sender, _receiver, elapsed) =
        blast_drain_concurrent_once(sender, receiver, payload_bytes, chunk_bytes, total_timeout)
            .await?;
    let _ = sender.shutdown().await;

    let bytes_per_sec = (payload_bytes as f64) / elapsed.as_secs_f64();
    let mib_per_sec = bytes_per_sec / (1024.0 * 1024.0);
    let gbps = bytes_per_sec * 8.0 / 1_000_000_000.0;

    Ok(RunReport {
        profile: "alpha",
        payload_bytes: payload_bytes as u64,
        chunk_bytes: chunk_bytes as u64,
        elapsed_secs: elapsed.as_secs_f64(),
        mib_per_sec,
        gbps,
        server_addr: server_addr.to_string(),
        perf_profile: "tls-1.3-h2-http/1.1".to_string(),
        idle_timeout_secs: total_timeout.as_secs(),
        connect_timeout_secs: connect_timeout.as_secs(),
        netem_c2s_packets_received: 0,
        netem_c2s_packets_dropped: 0,
        netem_s2c_packets_received: 0,
        netem_s2c_packets_dropped: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test: raw-TCP α bench runs end-to-end and reports a
    /// non-degenerate throughput number. Floor is generous (0.1 MiB/s)
    /// because debug-mode crypto + small payload + CI noise can drag
    /// the number down; the point is "the path is wired", not
    /// "throughput is at production levels" (that's the in-tree
    /// throughput_smoke test's job).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn alpha_raw_tcp_bench_runs_end_to_end() {
        let report = run_same_host_raw_tcp_bench(
            1024 * 1024, // 1 MiB
            64 * 1024,
            Duration::from_secs(30),
            Duration::from_secs(60),
        )
        .await
        .expect("raw-tcp bench end-to-end");
        assert_eq!(report.profile, "alpha");
        assert_eq!(report.perf_profile, "raw-tcp");
        assert!(report.mib_per_sec > 0.1, "got {}", report.mib_per_sec);
        assert!(report.elapsed_secs > 0.0);
    }

    /// Smoke test: TLS-wrapped α bench runs end-to-end. Same floor
    /// rationale as above; TLS adds maybe 10% overhead on loopback
    /// so the absolute number is lower than raw-tcp but the path
    /// being wired is the test goal.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn alpha_tls_bench_runs_end_to_end() {
        let report = run_same_host_tls_bench(
            1024 * 1024, // 1 MiB
            64 * 1024,
            Duration::from_secs(30),
            Duration::from_secs(60),
        )
        .await
        .expect("tls bench end-to-end");
        assert_eq!(report.profile, "alpha");
        assert_eq!(report.perf_profile, "tls-1.3-h2-http/1.1");
        assert!(report.mib_per_sec > 0.1, "got {}", report.mib_per_sec);
    }

    /// `run_cross_host_tls_bench` MUST fail fast on a fingerprint
    /// mismatch — that's the copy-paste-typo guard. Validates the
    /// error message names both the supplied and computed
    /// fingerprints so the operator can immediately see which field
    /// was wrong.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cross_host_rejects_fingerprint_mismatch() {
        // Mint identity, then deliberately corrupt the fingerprint.
        let server_keys = ServerKeys::generate();
        let bad_fp = [0xffu8; 32];
        assert_ne!(server_keys.pq_fingerprint, bad_fp);
        let bench_cert = mint_self_signed(None).expect("mint cert");
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap(); // unused — guard fires before connect

        let err = run_cross_host_tls_bench(
            "localhost",
            addr,
            bench_cert.chain[0].clone(),
            server_keys.mlkem_pk_bytes.clone(),
            server_keys.x25519_pub,
            bad_fp,
            1024,
            512,
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .await
        .expect_err("should fail on fingerprint mismatch");
        let msg = format!("{err}");
        assert!(
            msg.contains("pq_fingerprint mismatch"),
            "error should name the mismatch class: {msg}"
        );
        assert!(
            msg.contains(&hex::encode(bad_fp))
                && msg.contains(&hex::encode(server_keys.pq_fingerprint)),
            "error should name both supplied + computed hashes: {msg}"
        );
    }
}
