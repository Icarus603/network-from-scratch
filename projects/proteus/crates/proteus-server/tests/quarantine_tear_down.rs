//! End-to-end test for auto-quarantine tear-down of IN-FLIGHT sessions.
//!
//! Scenario:
//!   1. Stand up an in-process Proteus server with auto-quarantine wired.
//!   2. Stand up a silent upstream — the relay's pumps block reading.
//!   3. Client opens a Proteus session and sends a CONNECT. The session
//!      is now in-flight with both pumps parked on reads.
//!   4. Operator code calls `qlist.insert(uid, "test")` — this should
//!      `notify_waiters()` on the per-user notify and tear the session
//!      down IMMEDIATELY, without waiting for idle timeout or byte budget.
//!   5. Client's `recv_record()` returns within milliseconds.
//!
//! Without the tear-down wiring (the bug this iteration fixes), the
//! session would sit until the idle timeout fired — meaning a mid-burst
//! exfiltrator gets to finish their upload after being banned.

use std::sync::Arc;
use std::time::Duration;

use proteus_server::relay::{self, encode_connect, RelayConfig};
use proteus_transport_alpha::client::{self, ClientConfig};
use proteus_transport_alpha::metrics::ServerMetrics;
use proteus_transport_alpha::server::{self, ServerCtx, ServerKeys};
use proteus_transport_alpha::user_quarantine::UserQuarantineList;
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
            tokio::spawn(async move {
                let _hold = stream;
                tokio::time::sleep(Duration::from_secs(60)).await;
            });
        }
    });
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn in_flight_session_torn_down_when_user_quarantined() {
    let upstream_addr = spawn_silent_upstream().await;

    // ----- Proteus server with quarantine list wired -----
    let server_keys = ServerKeys::generate();
    let mlkem_pk_bytes = server_keys.mlkem_pk_bytes.clone();
    let pq_fingerprint = server_keys.pq_fingerprint;
    let server_x25519_pub = server_keys.x25519_pub;
    let ctx = Arc::new(ServerCtx::new(server_keys));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let server_ctx = Arc::clone(&ctx);

    let qlist = Arc::new(UserQuarantineList::new(Duration::from_secs(600), 4096));
    let server_metrics = Arc::new(ServerMetrics::default());
    let relay_cfg = RelayConfig {
        // Long idle so we can prove the tear-down beats it; if idle
        // fires first the assertion below will catch it.
        idle_timeout: Some(Duration::from_secs(30)),
        metrics: Some(Arc::clone(&server_metrics)),
        access_log: None,
        max_session_bytes: None,
        abuse_detector_byte_budget: None,
        abuse_fires: None,
        user_quarantine: Some(Arc::clone(&qlist)),
        quarantine_on_byte_budget: false,
        outbound_filter: None,
        dns_resolver_stats: None,
        pad_quantum: None,
        tcp_keepalive_secs: None,
    };
    let server_task = tokio::spawn(server::serve(listener, server_ctx, move |session| {
        let cfg = relay_cfg.clone();
        async move {
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
        user_id: *b"alice001",
        pow_difficulty: 0,
        profile_hint: proteus_wire::ProfileHint::Alpha,
    };
    let stream = TcpStream::connect(proxy_addr).await.unwrap();
    let mut session = timeout(STEP, client::handshake_over_tcp(stream, &client_cfg))
        .await
        .expect("connect timed out")
        .expect("handshake ok");

    // CONNECT to the silent upstream — both pumps go idle reading.
    let connect = encode_connect("127.0.0.1", upstream_addr.port());
    session.sender.send_record(&connect).await.unwrap();
    session.sender.flush().await.unwrap();

    // Wait a moment so the server-side relay has registered its
    // notify with the quarantine list AND parked on its pumps.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // OPERATOR / ABUSE PATH FIRES: ban alice001.
    let inserted = qlist.insert(*b"alice001", "test_trigger");
    assert!(inserted, "quarantine insert must succeed");

    // Client's recv_record() should now return within ~100 ms
    // (server's select! wakes on the notify, drops the pump
    // futures, sends a CLOSE record, shuts down the stream).
    // We use a 3-second bound — generous enough for slow CI,
    // tight enough that an idle-timeout fallback (30s) couldn't
    // possibly pass this test.
    let start = Instant::now();
    let r = timeout(Duration::from_secs(3), session.receiver.recv_record()).await;
    let elapsed = start.elapsed();

    let outcome = r.expect("tear-down failed — recv_record() hung past 3 s");
    match outcome {
        Ok(None) => {}                    // clean EOF from server's send_close()
        Ok(Some(b)) if b.is_empty() => {} // tolerate empty marker
        Err(_) => {}                      // peer-reset is also acceptable
        Ok(Some(b)) => panic!("expected EOF/Err after quarantine, got {} bytes", b.len()),
    }
    assert!(
        elapsed < Duration::from_secs(2),
        "tear-down overshot — must be sub-second, got {elapsed:?} \
         (idle timeout is 30s so this would only pass with real tear-down wiring)"
    );

    // Verify the quarantine list bumped its tear-down counter.
    // Give a few iterations in case the server's metric bump is
    // racing the client's recv exit.
    for _ in 0..50 {
        if qlist.sessions_torn_down_total() > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        qlist.sessions_torn_down_total() >= 1,
        "sessions_torn_down_total must increment; got {}",
        qlist.sessions_torn_down_total()
    );

    server_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quarantine_does_not_tear_down_sessions_for_other_users() {
    // alice and bob both have in-flight sessions. Quarantine only
    // bob — alice's session must NOT be torn down.
    let upstream_addr = spawn_silent_upstream().await;

    let server_keys = ServerKeys::generate();
    let mlkem_pk_bytes = server_keys.mlkem_pk_bytes.clone();
    let pq_fingerprint = server_keys.pq_fingerprint;
    let server_x25519_pub = server_keys.x25519_pub;
    let ctx = Arc::new(ServerCtx::new(server_keys));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let server_ctx = Arc::clone(&ctx);

    let qlist = Arc::new(UserQuarantineList::new(Duration::from_secs(600), 4096));
    let server_metrics = Arc::new(ServerMetrics::default());
    let relay_cfg = RelayConfig {
        idle_timeout: Some(Duration::from_secs(30)),
        metrics: Some(Arc::clone(&server_metrics)),
        access_log: None,
        max_session_bytes: None,
        abuse_detector_byte_budget: None,
        abuse_fires: None,
        user_quarantine: Some(Arc::clone(&qlist)),
        quarantine_on_byte_budget: false,
        outbound_filter: None,
        dns_resolver_stats: None,
        pad_quantum: None,
        tcp_keepalive_secs: None,
    };
    let server_task = tokio::spawn(server::serve(listener, server_ctx, move |session| {
        let cfg = relay_cfg.clone();
        async move {
            let _ = relay::handle_session(session, cfg).await;
        }
    }));

    // Helper closure to open one session as a given user_id.
    let open_session = |user_id: [u8; 8]| {
        let mlkem_pk_bytes = mlkem_pk_bytes.clone();
        async move {
            let mut rng = rand_core::OsRng;
            let client_id_sk = proteus_crypto::sig::generate(&mut rng);
            let client_cfg = ClientConfig {
                server_mlkem_pk_bytes: mlkem_pk_bytes,
                server_x25519_pub,
                server_pq_fingerprint: pq_fingerprint,
                client_id_sk,
                user_id,
                pow_difficulty: 0,
                profile_hint: proteus_wire::ProfileHint::Alpha,
            };
            let stream = TcpStream::connect(proxy_addr).await.unwrap();
            let mut session = timeout(STEP, client::handshake_over_tcp(stream, &client_cfg))
                .await
                .expect("connect timed out")
                .expect("handshake ok");
            let connect = encode_connect("127.0.0.1", upstream_addr.port());
            session.sender.send_record(&connect).await.unwrap();
            session.sender.flush().await.unwrap();
            session
        }
    };

    let mut alice = open_session(*b"alice001").await;
    let mut bob = open_session(*b"bob00002").await;

    // Wait for both sessions' relay handlers to park on their pumps.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Quarantine bob only.
    qlist.insert(*b"bob00002", "test_trigger");

    // Bob's recv MUST return promptly.
    let bob_r = timeout(Duration::from_secs(3), bob.receiver.recv_record())
        .await
        .expect("bob's tear-down hung past 3s");
    match bob_r {
        Ok(None) | Err(_) => {}
        Ok(Some(b)) if b.is_empty() => {}
        Ok(Some(b)) => panic!("expected bob EOF/Err, got {} bytes", b.len()),
    }

    // Alice's recv MUST still block (no tear-down for her).
    // 500ms is enough to be confident the notify didn't leak.
    let alice_r = timeout(Duration::from_millis(500), alice.receiver.recv_record()).await;
    assert!(
        alice_r.is_err(),
        "alice's session was torn down despite NOT being quarantined — \
         notify leakage bug: {alice_r:?}"
    );

    assert!(qlist.sessions_torn_down_total() >= 1);
    server_task.abort();
}
