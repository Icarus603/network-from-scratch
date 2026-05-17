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
/// bench CLI's `server` subcommand.
///
/// Returns the bound local address (so the CLI can print it for the
/// operator) AND a future that drives the accept loop. The caller is
/// expected to spawn the future on the runtime and either `.await`
/// it (blocking the CLI on the loop, the typical case) or pair it
/// with a shutdown signal.
pub async fn spawn_echo_server(
    bind: SocketAddr,
    cert: BenchCert,
    perf: PerfProfile,
) -> Result<
    (
        SocketAddr,
        impl std::future::Future<Output = Result<(), BenchError>>,
    ),
    BenchError,
> {
    let server_keys = ServerKeys::generate();
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

    Ok((local, server_fut))
}

// Cross-host bench client is intentionally NOT implemented yet —
// it needs a server-side identity-export flag (mlkem_pk +
// x25519_pub + pq_fingerprint) so the client can verify the peer
// without a shared in-process `ServerKeys`. Same-host bench uses
// `run_same_host_bench` below, which works end-to-end today.

/// Single-host bench run (server + client share the in-process
/// `ServerKeys`). This is the variant that actually works end-to-end
/// today; the cross-host variant requires server-identity export
/// which is the next iteration.
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
    let local = endpoint
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

    let mut payload = vec![0u8; payload_bytes];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = (i & 0xff) as u8;
    }

    let start = Instant::now();
    for chunk in payload.chunks(chunk_bytes) {
        tokio::time::timeout(total_timeout, client.session.sender.send_record(chunk))
            .await
            .map_err(|_| {
                BenchError::Send(format!("send stalled past total_timeout {total_timeout:?}"))
            })?
            .map_err(|e| BenchError::Send(e.to_string()))?;
    }
    tokio::time::timeout(total_timeout, client.session.sender.flush())
        .await
        .map_err(|_| {
            BenchError::Send(format!(
                "flush stalled past total_timeout {total_timeout:?}"
            ))
        })?
        .map_err(|e| BenchError::Send(e.to_string()))?;

    let mut got = 0usize;
    while got < payload_bytes {
        let rec = tokio::time::timeout(total_timeout, client.session.receiver.recv_record())
            .await
            .map_err(|_| {
                BenchError::Recv(format!("recv stalled past total_timeout {total_timeout:?}"))
            })?
            .map_err(|e| BenchError::Recv(e.to_string()))?
            .ok_or_else(|| BenchError::Recv("session closed before payload fully echoed".into()))?;
        // Byte-pattern verification so we catch silent corruption in
        // the same harness call rather than a follow-up validation
        // step.
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

    let elapsed = start.elapsed();
    let elapsed_secs = elapsed.as_secs_f64();
    let bytes_per_sec = (payload_bytes as f64) / elapsed_secs;
    let mib_per_sec = bytes_per_sec / (1024.0 * 1024.0);
    let gbps = bytes_per_sec * 8.0 / 1_000_000_000.0;

    // Best-effort teardown so a fast bench loop doesn't accumulate
    // file descriptors.
    let proteus_transport_alpha::session::AlphaSession { sender, .. } = client.session;
    let _ = sender.shutdown().await;
    client.connection.close(0u32.into(), b"bench-done");
    drop(client.endpoint);
    server_task.abort();

    Ok(RunReport {
        profile: "beta",
        payload_bytes: payload_bytes as u64,
        chunk_bytes: chunk_bytes as u64,
        elapsed_secs,
        mib_per_sec,
        gbps,
        server_addr: local.to_string(),
        perf_profile: format_perf_profile(perf),
        idle_timeout_secs: connect_timeout.as_secs(),
        connect_timeout_secs: connect_timeout.as_secs(),
    })
}

fn format_perf_profile(p: PerfProfile) -> String {
    format!(
        "pad={},mtu_init={},mtu_max={},ack_threshold={},spin={}",
        p.pad_quic_datagrams_to_mtu,
        p.initial_mtu,
        p.mtu_upper_bound,
        p.ack_eliciting_threshold,
        p.allow_spin_bit,
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
            !c.leaf_hex.is_empty() && c.leaf_hex.len().is_multiple_of(2),
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
}
