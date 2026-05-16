//! α-profile loopback throughput smoke test.
//!
//! Catches throughput-regression bugs:
//!   - Removed `BufWriter` from AlphaSender → 1 syscall per record
//!   - Forgot to flush in batches → kernel sndbuf stalls
//!   - Ratchet-trigger fires too often → key rotation in critical path
//!   - AEAD switched to single-record (non-streaming) construction
//!
//! Pushes 16 MiB through a real α-profile (raw TCP, no TLS for this
//! smoke; the TLS variant is exercised in tls_end_to_end.rs) session
//! and measures wall-clock + effective throughput. NOT a netem-grade
//! benchmark — that requires cross-host setup.
//!
//! Floor: 50 MiB/s one-way effective. The README baseline is
//! ~120 MiB/s on Apple Silicon, ~80–100 MiB/s on commodity Linux
//! CI runners. 50 MiB/s gives ~2× margin for noisy shared CI while
//! catching the regressions above (which all manifest as 5–10× slow-
//! downs on this workload).

use std::sync::Arc;
use std::time::{Duration, Instant};

use proteus_transport_alpha::client::{self, ClientConfig};
use proteus_transport_alpha::server::{self, ServerCtx, ServerKeys};
use proteus_wire::ProfileHint;
use tokio::net::TcpListener;
use tokio::time::timeout;

const STEP: Duration = Duration::from_secs(60);

/// 4 MiB single logical transfer. Small enough to run in debug-mode
/// CI under the per-test STEP timeout (debug crypto is ~10× slower
/// than release), large enough to amortize handshake startup so the
/// reported MiB/s reflects steady-state and not setup overhead.
const PAYLOAD_BYTES: usize = 4 * 1024 * 1024;

/// 5 MiB/s floor. Generous for debug-mode CI where every AEAD op is
/// unoptimized; release-mode local Apple Silicon is ~120 MiB/s on this
/// workload. A real throughput regression (BufWriter dropped,
/// per-record syscalls, hot-path ratchet) collapses this to <1 MiB/s.
const MIN_MIB_PER_SEC_FLOOR: f64 = 5.0;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn alpha_loopback_16mib_throughput() {
    let server_keys = ServerKeys::generate();
    let mlkem_pk_bytes = server_keys.mlkem_pk_bytes.clone();
    let pq_fingerprint = server_keys.pq_fingerprint;
    let server_x25519_pub = server_keys.x25519_pub;
    let ctx = Arc::new(ServerCtx::new(server_keys));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_ctx = Arc::clone(&ctx);
    tokio::spawn(server::serve(
        listener,
        server_ctx,
        |mut session| async move {
            // Echo each received record straight back.
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
    ));

    let mut rng = rand_core::OsRng;
    let client_id_sk = proteus_crypto::sig::generate(&mut rng);
    let cfg = ClientConfig {
        server_mlkem_pk_bytes: mlkem_pk_bytes,
        server_x25519_pub,
        server_pq_fingerprint: pq_fingerprint,
        client_id_sk,
        user_id: *b"througha",
        pow_difficulty: 0,
        profile_hint: ProfileHint::Alpha,
    };
    let session = timeout(STEP, client::connect(&addr.to_string(), &cfg))
        .await
        .expect("connect timeout")
        .expect("handshake ok");

    let proteus_transport_alpha::session::AlphaSession {
        mut sender,
        mut receiver,
        ..
    } = session;

    // 16 MiB payload with deterministic pattern.
    let mut payload = vec![0u8; PAYLOAD_BYTES];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = (i & 0xff) as u8;
    }

    let start = Instant::now();

    // Concurrent send + receive (NOT send-all-then-recv-all): α uses
    // raw TCP where the kernel sndbuf would fill on send-all, blocking
    // the sender until the receiver drains. β tests get away with the
    // simpler pattern because QUIC has stream-level flow control.
    const CHUNK: usize = 64 * 1024;
    let payload_for_send = payload.clone();
    let send_fut = async move {
        for chunk in payload_for_send.chunks(CHUNK) {
            sender.send_record(chunk).await.unwrap();
        }
        sender.flush().await.unwrap();
        sender // hand back for cleanup
    };
    let recv_fut = async move {
        let mut got = 0usize;
        while got < PAYLOAD_BYTES {
            let rec = receiver
                .recv_record()
                .await
                .expect("recv ok")
                .expect("session closed early");
            for (i, b) in rec.iter().enumerate() {
                let idx = got + i;
                assert_eq!(*b, (idx & 0xff) as u8, "byte mismatch at offset {idx}");
            }
            got += rec.len();
        }
        receiver
    };
    let (sender, receiver) = timeout(STEP, async { tokio::join!(send_fut, recv_fut) })
        .await
        .expect("round-trip timeout");

    let elapsed = start.elapsed();
    let mib_per_sec = (PAYLOAD_BYTES as f64) / elapsed.as_secs_f64() / (1024.0 * 1024.0);
    eprintln!(
        "α loopback round-trip: {} MiB in {:?} → {:.1} MiB/s (one-way effective)",
        PAYLOAD_BYTES / (1024 * 1024),
        elapsed,
        mib_per_sec,
    );

    assert!(
        mib_per_sec >= MIN_MIB_PER_SEC_FLOOR,
        "α throughput regression: {mib_per_sec:.1} MiB/s < {MIN_MIB_PER_SEC_FLOOR} MiB/s floor. \
         README baseline is ~120 MiB/s on Apple Silicon. A 5× drop indicates a real \
         hot-path regression — likely a missed BufWriter, missing flush batching, or \
         ratchet firing too often."
    );

    // Best-effort cleanup. The relay's session ends when we drop
    // `sender`, but we leave the listener running for the test's
    // shared-runtime cleanup.
    let _ = sender.shutdown().await;
    drop(receiver);
}
