//! End-to-end test for the byte-budget abuse detector.
//!
//! Stand up a server with `max_session_bytes = 32 KiB` and an
//! AbuseDetector configured for `(threshold=2, window=10s)`. Open
//! three sessions in a row from the same user_id; each one hits the
//! cap. The detector should:
//! - NOT fire after session 1 (below threshold)
//! - FIRE exactly once between session 2 and session 3 (at-or-above
//!   threshold, fire-once semantics)
//! - keep `abuse_alerts_byte_budget` at 1, not 2, even after a 3rd
//!   abusive session (still in the same burst)

use std::sync::Arc;
use std::time::Duration;

use proteus_server::relay::{self, encode_connect, RelayConfig};
use proteus_transport_alpha::abuse_detector::AbuseDetector;
use proteus_transport_alpha::client::{self, ClientConfig};
use proteus_transport_alpha::metrics::ServerMetrics;
use proteus_transport_alpha::server::{self, ServerCtx, ServerKeys};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const STEP: Duration = Duration::from_secs(15);

async fn spawn_echo_upstream() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(t) => t,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                loop {
                    let n = match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

async fn one_byte_budget_session(
    proxy_addr: std::net::SocketAddr,
    echo_addr: std::net::SocketAddr,
    client_cfg: &ClientConfig,
) {
    let stream = TcpStream::connect(proxy_addr).await.unwrap();
    let mut session = timeout(STEP, client::handshake_over_tcp(stream, client_cfg))
        .await
        .expect("connect timeout")
        .expect("handshake ok");

    let connect = encode_connect("127.0.0.1", echo_addr.port());
    session.sender.send_record(&connect).await.unwrap();
    session.sender.flush().await.unwrap();

    let payload = vec![0xCDu8; 16 * 1024];
    let _ = session.sender.send_record(&payload).await;
    let _ = session.sender.flush().await;
    // Drain until EOF/close — server should tear us down on byte cap.
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
        match timeout(Duration::from_millis(200), session.receiver.recv_record()).await {
            Ok(Ok(None)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(Some(_))) => continue,
        }
    }
    let _ = session.sender.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn abuse_detector_fires_once_per_burst_on_repeated_byte_cap_hits() {
    let echo_addr = spawn_echo_upstream().await;

    // Server identity + allowlist with one user.
    let mut server_keys = ServerKeys::generate();
    let mut rng = rand_core::OsRng;
    let client_sk = proteus_crypto::sig::generate(&mut rng);
    let client_vk = ed25519_dalek::VerifyingKey::from(&client_sk);
    server_keys.allow(*b"abuser01", client_vk);
    let mlkem_pk_bytes = server_keys.mlkem_pk_bytes.clone();
    let pq_fingerprint = server_keys.pq_fingerprint;
    let server_x25519_pub = server_keys.x25519_pub;

    let server_metrics = Arc::new(ServerMetrics::default());
    let ctx = Arc::new(ServerCtx::new(server_keys).with_metrics(Arc::clone(&server_metrics)));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();

    // Threshold = 2, window = 10s. The 2nd cap-hit should fire.
    let detector = Arc::new(AbuseDetector::new(Duration::from_secs(10), 2));
    let relay_cfg = RelayConfig {
        idle_timeout: Some(Duration::from_secs(5)),
        metrics: Some(Arc::clone(&server_metrics)),
        access_log: None,
        max_session_bytes: Some(32 * 1024),
        abuse_detector_byte_budget: Some(Arc::clone(&detector)),
    };
    let server_task = tokio::spawn(server::serve(listener, ctx, move |session| {
        let cfg = relay_cfg.clone();
        async move {
            let _ = relay::handle_session(session, cfg).await;
        }
    }));

    let client_cfg = ClientConfig {
        server_mlkem_pk_bytes: mlkem_pk_bytes,
        server_x25519_pub,
        server_pq_fingerprint: pq_fingerprint,
        client_id_sk: client_sk,
        user_id: *b"abuser01",
        pow_difficulty: 0,
    };

    // Session 1: cap hit. Counter goes to 0 (below threshold).
    one_byte_budget_session(proxy_addr, echo_addr, &client_cfg).await;
    // Wait for server-side metrics to flush.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let alerts_after_1 = server_metrics
        .abuse_alerts_byte_budget
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        alerts_after_1, 0,
        "below threshold — no alert yet, got {alerts_after_1}"
    );

    // Session 2: cap hit. Now we're at threshold — should fire.
    one_byte_budget_session(proxy_addr, echo_addr, &client_cfg).await;
    let mut alerts_after_2 = 0u64;
    for _ in 0..50 {
        alerts_after_2 = server_metrics
            .abuse_alerts_byte_budget
            .load(std::sync::atomic::Ordering::Relaxed);
        if alerts_after_2 >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        alerts_after_2, 1,
        "exactly 1 alert at threshold, got {alerts_after_2}"
    );

    // Session 3: cap hit AGAIN in same burst. Fire-once semantics:
    // alert MUST NOT increment.
    one_byte_budget_session(proxy_addr, echo_addr, &client_cfg).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let alerts_after_3 = server_metrics
        .abuse_alerts_byte_budget
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        alerts_after_3, 1,
        "fire-once: should still be 1 after session 3, got {alerts_after_3}"
    );

    server_task.abort();
}
