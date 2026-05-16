//! Integration test for the per-user rate limit.
//!
//! Scenario: server has a 2-token-per-user bucket, virtually no
//! refill. Authenticated user "limited1" opens 3 successful sessions
//! in quick succession. The first two go through normally; the third
//! must be torn down by the per-user limiter before `handle()` runs.
//! `user_rate_rejected_total` must increment.
//!
//! Distinct users sharing a source IP (CGNAT-fairness) are exercised
//! in a separate test: alice and bob each get their own 2-token
//! bucket so alice exhausting hers doesn't block bob.

use std::sync::Arc;
use std::time::Duration;

use proteus_transport_alpha::client::{self, ClientConfig};
use proteus_transport_alpha::metrics::ServerMetrics;
use proteus_transport_alpha::server::{self, ServerCtx, ServerKeys};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const STEP: Duration = Duration::from_secs(15);

/// Open one Proteus session and return `true` if the relay closure
/// got to run. The test handler echoes back a single byte so the
/// client can confirm `handle()` actually executed.
async fn one_session(proxy_addr: std::net::SocketAddr, cfg: &ClientConfig) -> bool {
    let stream = match timeout(STEP, TcpStream::connect(proxy_addr)).await {
        Ok(Ok(s)) => s,
        _ => return false,
    };
    let mut session = match timeout(STEP, client::handshake_over_tcp(stream, cfg)).await {
        Ok(Ok(s)) => s,
        _ => return false,
    };
    // Send a marker byte and try to read a reply within a short
    // window. If the per-user limiter rejected this session, the
    // server closed without ever invoking `handle()` so the read
    // returns either an empty None or a CLOSE-induced error fast.
    let _ = session.sender.send_record(b"ping").await;
    let _ = session.sender.flush().await;
    let reply = timeout(Duration::from_millis(800), session.receiver.recv_record()).await;
    matches!(reply, Ok(Ok(Some(ref b))) if b == b"pong")
}

fn make_server_keys_with_user(uid: [u8; 8]) -> (ServerKeys, ed25519_dalek::SigningKey) {
    let mut keys = ServerKeys::generate();
    let mut rng = rand_core::OsRng;
    let sk = proteus_crypto::sig::generate(&mut rng);
    let vk = ed25519_dalek::VerifyingKey::from(&sk);
    keys.allow(uid, vk);
    (keys, sk)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn per_user_limit_blocks_third_session_for_same_user() {
    let (server_keys, client_sk) = make_server_keys_with_user(*b"limited1");
    let mlkem_pk_bytes = server_keys.mlkem_pk_bytes.clone();
    let pq_fingerprint = server_keys.pq_fingerprint;
    let server_x25519_pub = server_keys.x25519_pub;
    let metrics = Arc::new(ServerMetrics::default());

    let ctx = Arc::new(
        ServerCtx::new(server_keys)
            .with_user_rate_limit(2.0, 0.001, 1024)
            .with_metrics(Arc::clone(&metrics)),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let ctx_clone = Arc::clone(&ctx);
    let server_task = tokio::spawn(server::serve(
        listener,
        ctx_clone,
        |mut session| async move {
            // Echo "pong" back for each "ping" the client sends.
            while let Ok(Some(rec)) = session.receiver.recv_record().await {
                if rec == b"ping" {
                    let _ = session.sender.send_record(b"pong").await;
                    let _ = session.sender.flush().await;
                }
            }
        },
    ));

    let client_cfg = ClientConfig {
        server_mlkem_pk_bytes: mlkem_pk_bytes,
        server_x25519_pub,
        server_pq_fingerprint: pq_fingerprint,
        client_id_sk: client_sk,
        user_id: *b"limited1",
        pow_difficulty: 0,
        profile_hint: proteus_wire::ProfileHint::Alpha,
    };

    assert!(
        one_session(proxy_addr, &client_cfg).await,
        "session 1 should succeed"
    );
    assert!(
        one_session(proxy_addr, &client_cfg).await,
        "session 2 should succeed"
    );
    // 3rd hits the per-user limit — handshake completes (server
    // already did the ML-KEM work) but the relay closure never runs,
    // so no "pong" comes back within the timeout.
    let third = one_session(proxy_addr, &client_cfg).await;
    assert!(!third, "session 3 should be denied by per-user limiter");

    let rejected = metrics
        .user_rate_rejected
        .load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        rejected >= 1,
        "user_rate_rejected_total must increment; got {rejected}"
    );

    server_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn per_user_limit_is_fair_across_users() {
    // alice exhausts her bucket; bob (sharing the same loopback IP)
    // must still be admitted — that's the CGNAT-fairness property.
    let mut server_keys = ServerKeys::generate();
    let mut rng = rand_core::OsRng;
    let alice_sk = proteus_crypto::sig::generate(&mut rng);
    let bob_sk = proteus_crypto::sig::generate(&mut rng);
    server_keys.allow(*b"alice000", ed25519_dalek::VerifyingKey::from(&alice_sk));
    server_keys.allow(*b"bob00000", ed25519_dalek::VerifyingKey::from(&bob_sk));
    let mlkem_pk_bytes = server_keys.mlkem_pk_bytes.clone();
    let pq_fingerprint = server_keys.pq_fingerprint;
    let server_x25519_pub = server_keys.x25519_pub;

    let ctx = Arc::new(ServerCtx::new(server_keys).with_user_rate_limit(1.0, 0.001, 1024));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let ctx_clone = Arc::clone(&ctx);
    let server_task = tokio::spawn(server::serve(
        listener,
        ctx_clone,
        |mut session| async move {
            while let Ok(Some(rec)) = session.receiver.recv_record().await {
                if rec == b"ping" {
                    let _ = session.sender.send_record(b"pong").await;
                    let _ = session.sender.flush().await;
                }
            }
        },
    ));

    let alice_cfg = ClientConfig {
        server_mlkem_pk_bytes: mlkem_pk_bytes.clone(),
        server_x25519_pub,
        server_pq_fingerprint: pq_fingerprint,
        client_id_sk: alice_sk,
        user_id: *b"alice000",
        pow_difficulty: 0,
        profile_hint: proteus_wire::ProfileHint::Alpha,
    };
    let bob_cfg = ClientConfig {
        server_mlkem_pk_bytes: mlkem_pk_bytes,
        server_x25519_pub,
        server_pq_fingerprint: pq_fingerprint,
        client_id_sk: bob_sk,
        user_id: *b"bob00000",
        pow_difficulty: 0,
        profile_hint: proteus_wire::ProfileHint::Alpha,
    };

    assert!(
        one_session(proxy_addr, &alice_cfg).await,
        "alice 1 should succeed"
    );
    // alice's bucket is empty — her 2nd would fail; but we test bob.
    assert!(
        one_session(proxy_addr, &bob_cfg).await,
        "bob (different user) must NOT be blocked by alice's quota"
    );

    server_task.abort();
}
