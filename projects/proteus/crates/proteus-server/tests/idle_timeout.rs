//! Per-session idle timeout integration test.
//!
//! Scenario:
//! 1. Stand up an in-process Proteus server whose relay has
//!    `idle_timeout = 300 ms`.
//! 2. Stand up an upstream echo server that goes silent after the
//!    initial CONNECT-style handshake (never writes, never reads).
//! 3. Client opens a Proteus session, sends a CONNECT for the echo
//!    target, then sits silently with no further traffic.
//! 4. After ~300 ms, both pump directions should hit the idle
//!    deadline and the session should be torn down — `recv_record()`
//!    on the client side returns `Ok(None)` (clean EOF) within
//!    well under 1 second.

use std::sync::Arc;
use std::time::Duration;

use proteus_server::relay::{self, encode_connect, RelayConfig};
use proteus_transport_alpha::client::{self, ClientConfig};
use proteus_transport_alpha::metrics::ServerMetrics;
use proteus_transport_alpha::server::{self, ServerCtx, ServerKeys};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Instant};

const STEP: Duration = Duration::from_secs(15);

async fn spawn_silent_upstream() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(t) => t,
                Err(_) => return,
            };
            // Hold the upstream connection open without writing
            // anything. The relay's upstream→client pump should see
            // its read() block until the idle timeout fires.
            tokio::spawn(async move {
                let _hold = stream;
                tokio::time::sleep(Duration::from_secs(60)).await;
            });
        }
    });
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn idle_session_reaps_within_deadline() {
    let upstream_addr = spawn_silent_upstream().await;

    // ----- Proteus server -----
    let server_keys = ServerKeys::generate();
    let mlkem_pk_bytes = server_keys.mlkem_pk_bytes.clone();
    let pq_fingerprint = server_keys.pq_fingerprint;
    let server_x25519_pub = server_keys.x25519_pub;
    let ctx = Arc::new(ServerCtx::new(server_keys));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let server_ctx = Arc::clone(&ctx);

    let server_metrics = Arc::new(ServerMetrics::default());
    let relay_cfg = RelayConfig {
        idle_timeout: Some(Duration::from_millis(300)),
        metrics: Some(Arc::clone(&server_metrics)),
        access_log: None,
        max_session_bytes: None,
        abuse_detector_byte_budget: None,
    };
    let server_task = tokio::spawn(server::serve(listener, server_ctx, move |session| {
        let cfg = relay_cfg.clone();
        async move {
            // Drive the binary's real relay logic with the short idle.
            let _ = relay::handle_session(session, cfg).await;
        }
    }));

    // ----- Proteus client -----
    let mut rng = rand_core::OsRng;
    let client_id_sk = proteus_crypto::sig::generate(&mut rng);
    let client_cfg = ClientConfig {
        server_mlkem_pk_bytes: mlkem_pk_bytes,
        server_x25519_pub,
        server_pq_fingerprint: pq_fingerprint,
        client_id_sk,
        user_id: *b"idletest",
        pow_difficulty: 0,
    };
    let stream = TcpStream::connect(proxy_addr).await.unwrap();
    let mut session = timeout(STEP, client::handshake_over_tcp(stream, &client_cfg))
        .await
        .expect("connect timed out")
        .expect("handshake ok");

    // Send CONNECT — the relay dials the silent upstream and the two
    // pumps go idle.
    let connect = encode_connect("127.0.0.1", upstream_addr.port());
    session.sender.send_record(&connect).await.unwrap();
    session.sender.flush().await.unwrap();

    // Now sit silent. The server should reap within the idle window
    // (300 ms) plus some scheduling slack. Bound at 2 seconds so a
    // broken implementation can't hang the test indefinitely.
    let start = Instant::now();
    let r = timeout(Duration::from_secs(2), session.receiver.recv_record()).await;
    let elapsed = start.elapsed();

    let outcome = r.expect("idle reaper failed — recv_record() hung past 2 s");
    // Server should clean-close: Ok(None) or Err (peer dropped).
    match outcome {
        Ok(None) => {}                    // clean EOF from server's send_close()
        Ok(Some(b)) if b.is_empty() => {} // tolerate empty-keepalive marker
        Err(_) => {}                      // peer-reset is also acceptable
        Ok(Some(b)) => panic!("expected EOF/Err after idle, got {} bytes", b.len()),
    }
    assert!(
        elapsed < Duration::from_millis(1800),
        "idle reaper overshot: {elapsed:?}"
    );
    assert!(
        elapsed >= Duration::from_millis(200),
        "idle reaper fired suspiciously early: {elapsed:?}"
    );

    // Give the server's pump tasks a moment to record the counter
    // (they fire `session_idle_reaped` just after the timeout breaks
    // out of the loop).
    for _ in 0..50 {
        if server_metrics
            .session_idle_reaped
            .load(std::sync::atomic::Ordering::Relaxed)
            > 0
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let reaped = server_metrics
        .session_idle_reaped
        .load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        reaped >= 1,
        "session_idle_reaped_total must increment when idle fires; got {reaped}"
    );

    server_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn active_session_not_killed_by_idle_timeout() {
    // Stand up an echo upstream and an idle of 300 ms. Send a record
    // every 100 ms for 1 second; the session must NOT be reaped.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(t) => t,
                Err(_) => return,
            };
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = vec![0u8; 4096];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });

    let server_keys = ServerKeys::generate();
    let mlkem_pk_bytes = server_keys.mlkem_pk_bytes.clone();
    let pq_fingerprint = server_keys.pq_fingerprint;
    let server_x25519_pub = server_keys.x25519_pub;
    let ctx = Arc::new(ServerCtx::new(server_keys));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let server_ctx = Arc::clone(&ctx);
    let relay_cfg = RelayConfig {
        idle_timeout: Some(Duration::from_millis(300)),
        metrics: None,
        access_log: None,
        max_session_bytes: None,
        abuse_detector_byte_budget: None,
    };
    let server_task = tokio::spawn(server::serve(listener, server_ctx, move |session| {
        let cfg = relay_cfg.clone();
        async move {
            let _ = relay::handle_session(session, cfg).await;
        }
    }));

    let mut rng = rand_core::OsRng;
    let client_id_sk = proteus_crypto::sig::generate(&mut rng);
    let client_cfg = ClientConfig {
        server_mlkem_pk_bytes: mlkem_pk_bytes,
        server_x25519_pub,
        server_pq_fingerprint: pq_fingerprint,
        client_id_sk,
        user_id: *b"activeOK",
        pow_difficulty: 0,
    };
    let stream = TcpStream::connect(proxy_addr).await.unwrap();
    let mut session = timeout(STEP, client::handshake_over_tcp(stream, &client_cfg))
        .await
        .expect("connect timed out")
        .expect("handshake ok");

    let connect = encode_connect("127.0.0.1", echo_addr.port());
    session.sender.send_record(&connect).await.unwrap();
    session.sender.flush().await.unwrap();

    // Send and read each cycle every 100 ms for 10 rounds (1 second
    // total, > 3× the idle window). Each round MUST round-trip.
    for i in 0u32..10 {
        let payload = format!("ping-{i}");
        session
            .sender
            .send_record(payload.as_bytes())
            .await
            .unwrap();
        session.sender.flush().await.unwrap();
        let r = timeout(Duration::from_millis(500), session.receiver.recv_record())
            .await
            .expect("round trip timed out — idle false-positive")
            .expect("recv err")
            .expect("server closed mid-active session");
        assert_eq!(r, payload.as_bytes());
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    server_task.abort();
}
