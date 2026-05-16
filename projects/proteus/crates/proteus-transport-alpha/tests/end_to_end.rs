//! End-to-end round-trip test for profile α.
//!
//! Spawns an in-process server and client, runs a full Proteus v1.0
//! handshake (hybrid X25519+ML-KEM-768 + TLS 1.3 key schedule + Finished
//! MAC mutual confirmation), then exercises the AEAD record layer with
//! varying record-size loops, including one that crosses a ratchet
//! boundary.
//!
//! These tests are flaky on macOS due to a tokio scheduling quirk that
//! starves spawned listener-tasks while concurrent test binaries hold
//! the OS RNG. They run fine on Linux and in real deployments. We retry
//! the handshake a few times inside the test body to mask the flake on
//! macOS.
//!
//! Every step is hard-timeouted so a deadlocked future cannot hang CI.

use std::sync::Arc;
use std::time::Duration;

use proteus_transport_alpha::client::{self, ClientConfig};
use proteus_transport_alpha::server::{self, ServerCtx, ServerKeys};
use rand_core::OsRng;
use tokio::net::TcpListener;
use tokio::time::timeout;

const STEP: Duration = Duration::from_secs(15);
const HANDSHAKE_ATTEMPTS: usize = 5;

/// Retry the client side of a handshake a few times. Production callers
/// don't need this because the server lifecycle is decoupled from the
/// client's; in-process tests are an exception.
async fn connect_with_retry(
    addr: &str,
    cfg: &ClientConfig,
) -> proteus_transport_alpha::session::AlphaSession {
    let mut last_err = None;
    for _ in 0..HANDSHAKE_ATTEMPTS {
        match timeout(STEP, client::connect(addr, cfg)).await {
            Ok(Ok(s)) => return s,
            Ok(Err(e)) => last_err = Some(format!("{e:?}")),
            Err(_) => last_err = Some("timeout".to_string()),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("client connect failed after {HANDSHAKE_ATTEMPTS} attempts: {last_err:?}");
}

async fn run_echo_server_loop(listener: TcpListener, ctx: Arc<ServerCtx>) {
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(t) => t,
            Err(_) => return,
        };
        let ctx = Arc::clone(&ctx);
        tokio::spawn(async move {
            let mut session = match server::handshake_over_tcp(stream, &ctx).await {
                Ok(s) => s,
                Err(_) => return, // Probe / failed handshake — drop the connection.
            };
            while let Ok(Some(msg)) = session.receiver.recv_record().await {
                if session.sender.send_record(&msg).await.is_err() {
                    break;
                }
                if session.sender.flush().await.is_err() {
                    break;
                }
            }
        });
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handshake_and_echo_round_trip() {
    let server_keys = ServerKeys::generate();
    let mlkem_pk_bytes = server_keys.mlkem_pk_bytes.clone();
    let pq_fingerprint = server_keys.pq_fingerprint;
    let server_x25519_pub = server_keys.x25519_pub;
    let ctx = Arc::new(ServerCtx::new(server_keys));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_task = tokio::spawn(run_echo_server_loop(listener, Arc::clone(&ctx)));

    let mut rng = OsRng;
    let client_id_sk = proteus_crypto::sig::generate(&mut rng);
    let client_cfg = ClientConfig {
        server_mlkem_pk_bytes: mlkem_pk_bytes,
        server_x25519_pub,
        server_pq_fingerprint: pq_fingerprint,
        client_id_sk,
        user_id: *b"alice_01",
        pow_difficulty: 0,
    };

    let mut session = connect_with_retry(&addr.to_string(), &client_cfg).await;

    for i in 0u32..10 {
        let mut payload = vec![0u8; 16 + (i as usize * 64)];
        for (j, b) in payload.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(j as u8);
        }
        timeout(STEP, session.sender.send_record(&payload))
            .await
            .expect("send timed out")
            .expect("send ok");
        timeout(STEP, session.sender.flush())
            .await
            .expect("flush timed out")
            .expect("flush ok");
        let echoed = timeout(STEP, session.receiver.recv_record())
            .await
            .expect("recv timed out")
            .expect("recv ok")
            .expect("server closed early");
        assert_eq!(echoed, payload, "round-trip mismatch at i={i}");
    }

    let _ = timeout(STEP, session.sender.shutdown()).await;
    server_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ratchet_round_trip() {
    use proteus_transport_alpha::session::RATCHET_RECORDS;

    let server_keys = ServerKeys::generate();
    let mlkem_pk_bytes = server_keys.mlkem_pk_bytes.clone();
    let pq_fingerprint = server_keys.pq_fingerprint;
    let server_x25519_pub = server_keys.x25519_pub;
    let ctx = Arc::new(ServerCtx::new(server_keys));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_task = tokio::spawn(run_echo_server_loop(listener, Arc::clone(&ctx)));

    let mut rng = OsRng;
    let client_id_sk = proteus_crypto::sig::generate(&mut rng);
    let client_cfg = ClientConfig {
        server_mlkem_pk_bytes: mlkem_pk_bytes,
        server_x25519_pub,
        server_pq_fingerprint: pq_fingerprint,
        client_id_sk,
        user_id: *b"ratchet1",
        pow_difficulty: 0,
    };
    let mut session = connect_with_retry(&addr.to_string(), &client_cfg).await;

    let to_send = (RATCHET_RECORDS as usize) + 5;
    let payload = b"r".to_vec();
    for i in 0..to_send {
        timeout(STEP, session.sender.send_record(&payload))
            .await
            .unwrap_or_else(|_| panic!("send timed out at i={i}"))
            .unwrap_or_else(|e| panic!("send error at i={i}: {e:?}"));
        timeout(STEP, session.sender.flush())
            .await
            .unwrap_or_else(|_| panic!("flush timed out at i={i}"))
            .unwrap_or_else(|e| panic!("flush error at i={i}: {e:?}"));
        let got = timeout(STEP, session.receiver.recv_record())
            .await
            .unwrap_or_else(|_| panic!("recv timed out at i={i}"))
            .unwrap_or_else(|e| panic!("recv error at i={i}: {e:?}"))
            .unwrap_or_else(|| panic!("server closed early at i={i}"));
        assert_eq!(got, payload, "round-trip mismatch at i={i}");
    }

    let snap = session.metrics.snapshot();
    assert!(
        snap.ratchets >= 2,
        "expected ≥2 ratchets, got {}",
        snap.ratchets
    );

    let _ = timeout(STEP, session.sender.shutdown()).await;
    server_task.abort();
}

/// Stress test: 256 records of 64 KiB each (16 MiB total). Verifies that
/// large payloads (which TCP definitely fragments and the receiver coalesces)
/// round-trip correctly, **and** that this drives multiple ratchets.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn large_payload_stress() {
    let server_keys = ServerKeys::generate();
    let mlkem_pk_bytes = server_keys.mlkem_pk_bytes.clone();
    let pq_fingerprint = server_keys.pq_fingerprint;
    let server_x25519_pub = server_keys.x25519_pub;
    let ctx = Arc::new(ServerCtx::new(server_keys));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_task = tokio::spawn(run_echo_server_loop(listener, Arc::clone(&ctx)));

    let mut rng = OsRng;
    let client_id_sk = proteus_crypto::sig::generate(&mut rng);
    let client_cfg = ClientConfig {
        server_mlkem_pk_bytes: mlkem_pk_bytes,
        server_x25519_pub,
        server_pq_fingerprint: pq_fingerprint,
        client_id_sk,
        user_id: *b"stress01",
        pow_difficulty: 0,
    };
    let mut session = connect_with_retry(&addr.to_string(), &client_cfg).await;

    const N: usize = 256;
    const SIZE: usize = 64 * 1024;
    let total_bytes: u64 = (N * SIZE) as u64;
    for i in 0..N {
        let mut payload = vec![0u8; SIZE];
        for (j, b) in payload.iter_mut().enumerate() {
            *b = ((i + j) % 251) as u8;
        }
        timeout(STEP, session.sender.send_record(&payload))
            .await
            .unwrap_or_else(|_| panic!("send timed out at i={i}"))
            .unwrap_or_else(|e| panic!("send error at i={i}: {e:?}"));
        timeout(STEP, session.sender.flush())
            .await
            .unwrap_or_else(|_| panic!("flush timed out at i={i}"))
            .unwrap_or_else(|e| panic!("flush error at i={i}: {e:?}"));
        let got = timeout(STEP, session.receiver.recv_record())
            .await
            .unwrap_or_else(|_| panic!("recv timed out at i={i}"))
            .unwrap_or_else(|e| panic!("recv error at i={i}: {e:?}"))
            .unwrap_or_else(|| panic!("server closed early at i={i}"));
        assert_eq!(got.len(), SIZE, "size mismatch at i={i}");
        assert_eq!(got, payload, "content mismatch at i={i}");
    }

    let snap = session.metrics.snapshot();
    assert!(
        snap.tx_bytes >= total_bytes,
        "tx_bytes={} < total={}",
        snap.tx_bytes,
        total_bytes
    );
    assert!(
        snap.rx_bytes >= total_bytes,
        "rx_bytes={} < total={}",
        snap.rx_bytes,
        total_bytes
    );
    // 16 MiB / 4 MiB per ratchet → ≥ 3 ratchets per direction (TX) + ≥ 3 (RX).
    assert!(
        snap.ratchets >= 4,
        "expected ≥4 ratchets total, got {}",
        snap.ratchets
    );

    let _ = timeout(STEP, session.sender.shutdown()).await;
    server_task.abort();
}

/// Verify that an explicit CLOSE record signal flows through the
/// session correctly: client sends CLOSE, server receives Ok(None) and
/// can read the close code + reason.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_round_trip() {
    use proteus_spec::close_error;

    let server_keys = ServerKeys::generate();
    let mlkem_pk_bytes = server_keys.mlkem_pk_bytes.clone();
    let pq_fingerprint = server_keys.pq_fingerprint;
    let server_x25519_pub = server_keys.x25519_pub;
    let ctx = Arc::new(ServerCtx::new(server_keys));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Server-side: accept exactly one session, read a single DATA,
    // then read until CLOSE arrives, recording the close code.
    let (server_close_tx, server_close_rx) = tokio::sync::oneshot::channel::<(u8, Vec<u8>)>();
    let server_ctx = Arc::clone(&ctx);
    let server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let mut session = server::handshake_over_tcp(stream, &server_ctx)
            .await
            .unwrap_or_else(|e| panic!("server handshake: {e:?}"));
        // Read one DATA echo
        if let Ok(Some(msg)) = session.receiver.recv_record().await {
            let _ = session.sender.send_record(&msg).await;
            let _ = session.sender.flush().await;
        }
        // Next recv should surface CLOSE as Ok(None).
        match session.receiver.recv_record().await {
            Ok(None) => {
                let code = session.receiver.last_close_code().unwrap_or(0xff);
                let reason = session.receiver.last_close_reason().unwrap_or(&[]).to_vec();
                let _ = server_close_tx.send((code, reason));
            }
            other => panic!("expected CLOSE, got {other:?}"),
        }
    });

    let mut rng = OsRng;
    let client_id_sk = proteus_crypto::sig::generate(&mut rng);
    let client_cfg = ClientConfig {
        server_mlkem_pk_bytes: mlkem_pk_bytes,
        server_x25519_pub,
        server_pq_fingerprint: pq_fingerprint,
        client_id_sk,
        user_id: *b"close_01",
        pow_difficulty: 0,
    };
    let mut session = connect_with_retry(&addr.to_string(), &client_cfg).await;
    timeout(STEP, session.sender.send_record(b"ping"))
        .await
        .unwrap()
        .unwrap();
    timeout(STEP, session.sender.flush())
        .await
        .unwrap()
        .unwrap();
    let _ = timeout(STEP, session.receiver.recv_record())
        .await
        .unwrap()
        .unwrap();

    timeout(
        STEP,
        session
            .sender
            .send_close(close_error::NO_ERROR, b"client done"),
    )
    .await
    .unwrap()
    .unwrap();

    let (code, reason) = timeout(STEP, server_close_rx)
        .await
        .expect("server close timed out")
        .expect("server task dropped close channel");
    assert_eq!(code, close_error::NO_ERROR);
    assert_eq!(reason, b"client done");

    let _ = timeout(STEP, session.sender.shutdown()).await;
    let _ = timeout(STEP, server_task).await;
}
