//! End-to-end relay throughput benchmark.
//!
//! Measures **goodput** of bytes shipped through a fully-established
//! Proteus α session over loopback TCP. This is the production-relevant
//! number for the "speed superior to Hy2/TUIC5" claim: it includes
//! AEAD seal+open, framing, BufWriter coalescing, ratchet trigger
//! checks, and tokio scheduling.
//!
//! Numbers come back as MiB/s — divide by ~125 to convert to Gbps.
//!
//! Run with `cargo bench -p proteus-transport-alpha --bench
//! relay_throughput`.

use std::sync::Arc;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use proteus_transport_alpha::client::{self, ClientConfig};
use proteus_transport_alpha::server::{self, ServerCtx, ServerKeys};
use rand_core::OsRng;
use tokio::net::TcpListener;
use tokio::runtime::Runtime;

/// Bring up a one-session echo server and connect a Proteus client to
/// it. Returns the established session.
async fn setup_session() -> proteus_transport_alpha::session::AlphaSession {
    let server_keys = ServerKeys::generate();
    let mlkem_pk_bytes = server_keys.mlkem_pk_bytes.clone();
    let pq_fingerprint = server_keys.pq_fingerprint;
    let server_x25519_pub = server_keys.x25519_pub;
    let ctx = Arc::new(ServerCtx::new(server_keys));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_ctx = Arc::clone(&ctx);
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        if let Ok(mut session) = server::handshake_over_tcp(stream, &server_ctx).await {
            while let Ok(Some(msg)) = session.receiver.recv_record().await {
                if session.sender.send_record(&msg).await.is_err() {
                    break;
                }
                if session.sender.flush().await.is_err() {
                    break;
                }
            }
        }
    });

    let mut rng = OsRng;
    let client_id_sk = proteus_crypto::sig::generate(&mut rng);
    let client_cfg = ClientConfig::new(
        mlkem_pk_bytes,
        server_x25519_pub,
        pq_fingerprint,
        client_id_sk,
        *b"bench___",
    );
    tokio::time::timeout(
        Duration::from_secs(10),
        client::connect(&addr.to_string(), &client_cfg),
    )
    .await
    .expect("connect timeout")
    .expect("handshake fail")
}

fn bench_relay(c: &mut Criterion) {
    let rt = Runtime::new().expect("tokio runtime");

    let mut group = c.benchmark_group("relay_echo");
    // 16 KiB and 64 KiB are the realistic record sizes from the SOCKS5
    // relay path (it reads up to 16 KiB from the inbound socket per loop).
    for &size in &[16 * 1024usize, 64 * 1024] {
        let payload = vec![0xa5u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &payload, |b, payload| {
            // One session per benchmark — handshake cost is
            // amortized across the entire iter loop, so the result
            // is steady-state goodput.
            let mut session = rt.block_on(setup_session());
            b.iter(|| {
                rt.block_on(async {
                    session.sender.send_record(payload).await.expect("send");
                    session.sender.flush().await.expect("flush");
                    let echoed = session
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

criterion_group!(benches, bench_relay);
criterion_main!(benches);
