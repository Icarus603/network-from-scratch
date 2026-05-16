//! End-to-end test for the rate-limit abuse detector.
//!
//! Server has `user_rate_limit` with capacity 1 + zero refill, AND
//! an `AbuseDetector(threshold=2, window=10s)` for the rate-limit
//! axis. Three sessions from the same user:
//!   - Session 1: admitted (initial token).
//!   - Session 2: REJECTED (no tokens) → 1st rate-limit hit.
//!   - Session 3: REJECTED → 2nd rate-limit hit → detector fires.
//!
//! Verifies the `abuse_alerts_rate_limit` counter ticks exactly
//! once (fire-once-per-burst semantics), parallel to the
//! byte-budget detector.

use std::sync::Arc;
use std::time::Duration;

use proteus_transport_alpha::abuse_detector::AbuseDetector;
use proteus_transport_alpha::client::{self, ClientConfig};
use proteus_transport_alpha::metrics::ServerMetrics;
use proteus_transport_alpha::server::{self, ServerCtx, ServerKeys};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const STEP: Duration = Duration::from_secs(15);

async fn one_session(proxy_addr: std::net::SocketAddr, cfg: &ClientConfig) -> bool {
    let stream = match timeout(STEP, TcpStream::connect(proxy_addr)).await {
        Ok(Ok(s)) => s,
        _ => return false,
    };
    let mut session = match timeout(STEP, client::handshake_over_tcp(stream, cfg)).await {
        Ok(Ok(s)) => s,
        _ => return false,
    };
    // If the server admitted us, the handler will echo "pong" to
    // any record we send; if user_admission_ok rejected us, the
    // server closes immediately and we see EOF before any reply.
    let _ = session.sender.send_record(b"ping").await;
    let _ = session.sender.flush().await;
    matches!(
        timeout(Duration::from_millis(800), session.receiver.recv_record()).await,
        Ok(Ok(Some(ref b))) if b == b"pong"
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn abuse_detector_fires_once_per_burst_on_rate_limit_hits() {
    // Server allows ONE user; rate limit is 1 token, no refill →
    // every session after the first hits the rate limit.
    let mut server_keys = ServerKeys::generate();
    let mut rng = rand_core::OsRng;
    let client_sk = proteus_crypto::sig::generate(&mut rng);
    server_keys.allow(*b"abuser02", ed25519_dalek::VerifyingKey::from(&client_sk));
    let mlkem_pk_bytes = server_keys.mlkem_pk_bytes.clone();
    let pq_fingerprint = server_keys.pq_fingerprint;
    let server_x25519_pub = server_keys.x25519_pub;

    let metrics = Arc::new(ServerMetrics::default());
    let detector = Arc::new(AbuseDetector::new(Duration::from_secs(10), 2));

    let ctx = Arc::new(
        ServerCtx::new(server_keys)
            .with_user_rate_limit(1.0, 0.001, 1024)
            .with_abuse_detector_rate_limit(Arc::clone(&detector))
            .with_metrics(Arc::clone(&metrics)),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let server_task = tokio::spawn(server::serve(listener, ctx, |mut session| async move {
        while let Ok(Some(rec)) = session.receiver.recv_record().await {
            if rec == b"ping" {
                let _ = session.sender.send_record(b"pong").await;
                let _ = session.sender.flush().await;
            }
        }
    }));

    let client_cfg = ClientConfig {
        server_mlkem_pk_bytes: mlkem_pk_bytes,
        server_x25519_pub,
        server_pq_fingerprint: pq_fingerprint,
        client_id_sk: client_sk,
        user_id: *b"abuser02",
        pow_difficulty: 0,
        profile_hint: proteus_wire::ProfileHint::Alpha,
    };

    // Session 1 succeeds (1 token in the bucket).
    assert!(
        one_session(proxy_addr, &client_cfg).await,
        "first session must succeed"
    );
    assert_eq!(
        metrics
            .abuse_alerts_rate_limit
            .load(std::sync::atomic::Ordering::Relaxed),
        0,
        "no rate-limit rejections yet, no alert"
    );

    // Session 2 rejected — 1st rate-limit hit (below threshold).
    assert!(!one_session(proxy_addr, &client_cfg).await);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        metrics
            .abuse_alerts_rate_limit
            .load(std::sync::atomic::Ordering::Relaxed),
        0,
        "below threshold — no alert"
    );

    // Session 3 rejected — 2nd hit → detector fires.
    assert!(!one_session(proxy_addr, &client_cfg).await);
    // Give the server's WARN log + counter increment a moment.
    let mut alerts = 0u64;
    for _ in 0..50 {
        alerts = metrics
            .abuse_alerts_rate_limit
            .load(std::sync::atomic::Ordering::Relaxed);
        if alerts >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(alerts, 1, "exactly 1 alert at threshold");

    // Session 4 rejected again — same burst, fire-once: counter
    // MUST NOT increment.
    assert!(!one_session(proxy_addr, &client_cfg).await);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let final_alerts = metrics
        .abuse_alerts_rate_limit
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        final_alerts, 1,
        "fire-once-per-burst: should still be 1 after session 4"
    );

    // user_rate_rejected should reflect the 3 rejections.
    let rejected = metrics
        .user_rate_rejected
        .load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        rejected >= 3,
        "user_rate_rejected should be >= 3, got {rejected}"
    );

    server_task.abort();
}
