//! Loopback throughput smoke test.
//!
//! Pushes 16 MiB through a real β-profile QUIC session and measures
//! wall-clock + effective throughput. NOT a contention/lossy-network
//! benchmark — that requires netem + cross-host setup. The point of
//! this test is: catch a regression where BBR / window tuning gets
//! reverted and throughput collapses to a few MB/s on loopback.
//!
//! Test measures end-to-end RTT throughput (send N bytes, wait for
//! the same N bytes echoed back). The reported MiB/s figure is
//! `N / elapsed` where elapsed is full round-trip — so the actual
//! aggregate goodput on the wire is 2× this number.
//!
//! On modern dev boxes the bottleneck is AEAD encrypt+decrypt per
//! ~16 KiB record, not the QUIC carrier itself; expect 30–60 MiB/s
//! single-thread one-way (60–120 MiB/s aggregate).
//!
//! ## Threshold (debug-mode-safe, mirrors α `throughput_smoke`)
//!
//! Floor split by build profile, same pattern as the α throughput
//! guard (commit b9ed25d):
//!
//!   - **Release** (`cargo test --release`): 30 MiB/s — well under a
//!     healthy dev-box number (30–60 MiB/s typical); fires only on
//!     real BBR / flow-control window regression.
//!   - **Debug** (default `cargo test`): 5 MiB/s — debug mode pays
//!     ~10× for AEAD + QUIC packet processing, AND CI / dev-box
//!     concurrent test execution starves cores, AND another test
//!     in the same binary can push us under the historical 20 MiB/s
//!     line without anything actually broken. The 5 MiB/s floor is
//!     still tight enough to catch the specific "perf tuning got
//!     reverted, flow-control window collapsed to QUIC defaults"
//!     regression (which on loopback drops throughput to fractional
//!     MiB/s because every record waits for a 1-RTT window credit).
//!
//! Without this split, the test flakes under `cargo test
//! -p proteus-transport-beta` when run alongside the other 8 β tests
//! that all hammer multi-threaded tokio runtimes — a regression
//! we hit on 2026-05-17.

use std::sync::Arc;
use std::time::{Duration, Instant};

use proteus_transport_alpha::client::ClientConfig;
use proteus_transport_alpha::server::{ServerCtx, ServerKeys};
use proteus_transport_alpha::ProfileHint;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::time::timeout;

const STEP: Duration = Duration::from_secs(60);

/// One 16 MiB record. AlphaSession::send_record handles fragmentation
/// for us — quinn's stream layer is byte-oriented.
const PAYLOAD_BYTES: usize = 16 * 1024 * 1024;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn beta_loopback_16mib_throughput() {
    let ck = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(ck.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));

    let server_keys = ServerKeys::generate();
    let mlkem_pk_bytes = server_keys.mlkem_pk_bytes.clone();
    let pq_fingerprint = server_keys.pq_fingerprint;
    let server_x25519_pub = server_keys.x25519_pub;
    let ctx = Arc::new(ServerCtx::new(server_keys));

    let bind: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let endpoint =
        proteus_transport_beta::server::make_endpoint(bind, vec![cert_der.clone()], key_der)
            .expect("make_endpoint");
    let local = endpoint.local_addr().expect("local_addr");

    let server_ctx = Arc::clone(&ctx);
    let server_task = tokio::spawn(async move {
        let _ =
            proteus_transport_beta::server::serve(endpoint, server_ctx, |mut session| async move {
                // Receive 1 record, echo it back. send_record splits
                // the 16 MiB across whatever fragment size the inner
                // AEAD layer uses (~16 KiB per record IIRC).
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
        user_id: *b"throughp",
        pow_difficulty: 0,
        profile_hint: ProfileHint::Beta,
    };
    let mut client = timeout(
        STEP,
        proteus_transport_beta::client::connect("localhost", local, vec![cert_der], client_cfg),
    )
    .await
    .expect("connect timed out")
    .expect("β connect ok");

    // 16 MiB payload. Use a deterministic pattern so we can sanity-
    // check the echo without storing the whole thing twice in memory.
    let mut payload = vec![0u8; PAYLOAD_BYTES];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = (i & 0xff) as u8;
    }

    let start = Instant::now();

    // Send in ~64 KiB chunks — that's what a real bulk transfer
    // looks like and what the AEAD record size handles efficiently.
    const CHUNK: usize = 64 * 1024;
    for chunk in payload.chunks(CHUNK) {
        timeout(STEP, client.session.sender.send_record(chunk))
            .await
            .unwrap()
            .unwrap();
    }
    timeout(STEP, client.session.sender.flush())
        .await
        .unwrap()
        .unwrap();

    // Drain `PAYLOAD_BYTES` from the echo.
    let mut got = 0usize;
    while got < PAYLOAD_BYTES {
        let rec = timeout(STEP, client.session.receiver.recv_record())
            .await
            .expect("recv timed out")
            .expect("recv ok")
            .expect("session closed early");
        // Spot-check the bytes match.
        for (i, b) in rec.iter().enumerate() {
            let idx = got + i;
            assert_eq!(*b, (idx & 0xff) as u8, "byte mismatch at offset {idx}",);
        }
        got += rec.len();
    }

    let elapsed = start.elapsed();
    let bytes_per_sec = (PAYLOAD_BYTES as f64) / elapsed.as_secs_f64();
    let mib_per_sec = bytes_per_sec / (1024.0 * 1024.0);
    eprintln!(
        "β loopback round-trip: {} MiB in {:?} → {:.1} MiB/s (one-way effective)",
        PAYLOAD_BYTES / (1024 * 1024),
        elapsed,
        mib_per_sec,
    );

    // Regression-only floor — see file-level doc comment for the
    // debug vs. release split rationale. If this fires under
    // RELEASE, the perf tuning has regressed (BBR / flow-control
    // windows reverted to QUIC defaults). If it fires under DEBUG,
    // something is genuinely catastrophic — even debug-mode AEAD
    // through loopback QUIC should clear 5 MiB/s comfortably.
    let floor = if cfg!(debug_assertions) { 5.0 } else { 30.0 };
    assert!(
        mib_per_sec >= floor,
        "β throughput collapsed to {mib_per_sec:.1} MiB/s one-way \
         (floor {floor:.1} MiB/s; profile = {}); \
         perf tuning regressed (BBR / windows reverted?)",
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
    );

    let proteus_transport_alpha::session::AlphaSession { sender, .. } = client.session;
    let _ = timeout(STEP, sender.shutdown()).await;
    client.connection.close(0u32.into(), b"bye");
    drop(client.endpoint);
    server_task.abort();
}
