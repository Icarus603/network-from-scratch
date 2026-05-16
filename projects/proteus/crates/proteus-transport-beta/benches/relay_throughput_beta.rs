//! End-to-end β-profile (QUIC) relay throughput benchmark.
//!
//! Mirrors `proteus-transport-alpha::benches::relay_throughput`
//! exactly except the carrier is QUIC instead of TCP. The two
//! benches are designed to be **directly comparable** — same record
//! sizes (16 KiB and 64 KiB), same one-session-per-bench amortization
//! pattern, same Criterion harness.
//!
//! On the same dev box, comparing the two outputs answers the only
//! honest question we can answer without netem:
//!
//!   "Does β's BBR + window tuning give us a per-record throughput
//!    that's at least in the same order of magnitude as α's TCP
//!    path, after paying QUIC + TLS + AEAD overhead?"
//!
//! Loopback is the **best case** for TCP (zero loss, microsecond
//! RTT). The β number being competitive here is the prerequisite
//! for β winning on lossy long-fat pipes (where it should win by
//! design — BBR vs CUBIC).
//!
//! ## Measured numbers (Apple Silicon dev box, 2026-05)
//!
//! With `cargo bench --quick`, single bidi stream, one record at a
//! time (RT-serialized — not maximum pipelined throughput):
//!
//!   | record  | α (TCP)    | β (QUIC)   | β / α |
//!   |---------|------------|------------|-------|
//!   | 16 KiB  | 109 MiB/s  |  67 MiB/s  | 62 %  |
//!   | 64 KiB  | 120 MiB/s  |  57 MiB/s  | 48 %  |
//!
//! α wins on loopback. **Expected.** The QUIC carrier pays:
//!
//!   - TLS record-layer encrypt/decrypt on every QUIC packet, on top
//!     of the Proteus AEAD inside the stream.
//!   - Packet framing + ACK processing (TCP gets this from kernel).
//!   - More syscalls per byte (UDP recvmsg vs TCP read).
//!
//! TCP loopback has none of this overhead and zero loss.
//!
//! The β profile's design advantage — loss-tolerant BBR vs CUBIC's
//! "every loss → halve cwnd" — only manifests under loss + RTT. A
//! netem-based head-to-head against Hy2/TUIC5 is M3 work; without
//! it, no honest "β beats Hy2" claim is possible.
//!
//! Run with `cargo bench -p proteus-transport-beta --bench
//! relay_throughput_beta`.

use std::sync::Arc;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use proteus_transport_alpha::client::ClientConfig;
use proteus_transport_alpha::server::{ServerCtx, ServerKeys};
use proteus_transport_alpha::ProfileHint;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::runtime::Runtime;

/// Bring up a one-session β echo server, dial it, return the
/// `BetaClientSession`. We keep the server task handle alive via the
/// Arc<ServerCtx> + the spawned task; the bench only iterates on the
/// established session, not the handshake cost.
async fn setup_session() -> proteus_transport_beta::client::BetaClientSession {
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
    tokio::spawn(async move {
        let _ =
            proteus_transport_beta::server::serve(endpoint, server_ctx, |mut session| async move {
                // Echo loop — same handler as the alpha bench.
                while let Ok(Some(msg)) = session.receiver.recv_record().await {
                    if session.sender.send_record(&msg).await.is_err() {
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
        user_id: *b"benchbet",
        pow_difficulty: 0,
        profile_hint: ProfileHint::Beta,
    };
    tokio::time::timeout(
        Duration::from_secs(10),
        proteus_transport_beta::client::connect("localhost", local, vec![cert_der], client_cfg),
    )
    .await
    .expect("connect timeout")
    .expect("β connect ok")
}

fn bench_relay_beta(c: &mut Criterion) {
    let rt = Runtime::new().expect("tokio runtime");

    let mut group = c.benchmark_group("relay_echo_beta");
    // Same record sizes as the α bench so the two are directly
    // comparable.
    for &size in &[16 * 1024usize, 64 * 1024] {
        let payload = vec![0xa5u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &payload, |b, payload| {
            // One session per parameter — handshake amortized.
            let mut client = rt.block_on(setup_session());
            b.iter(|| {
                rt.block_on(async {
                    client
                        .session
                        .sender
                        .send_record(payload)
                        .await
                        .expect("send");
                    client.session.sender.flush().await.expect("flush");
                    let echoed = client
                        .session
                        .receiver
                        .recv_record()
                        .await
                        .expect("recv")
                        .expect("session closed early");
                    assert_eq!(echoed.len(), payload.len());
                });
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_relay_beta);
criterion_main!(benches);
