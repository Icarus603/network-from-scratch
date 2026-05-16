//! Regression test for the server-side session-leak bug fixed by
//! switching `tokio::join!` → `tokio::select!` in the relay pump.
//!
//! ## The bug
//!
//! Pre-fix: the relay's `client_to_upstream` half blocked on
//! `receiver.recv_record()`. When the UPSTREAM returned EOF (e.g.
//! HTTP server replied with full content + close), `upstream_to_client`
//! exited and sent a Proteus CLOSE record, then `tokio::join!` kept
//! waiting on `client_to_upstream`. But `client_to_upstream` was
//! blocked on `recv_record()` — and as long as the CLIENT keeps the
//! TLS/TCP connection alive (a perfectly legitimate scenario: many
//! HTTP clients pool connections for reuse), no record ever arrives,
//! `recv_record()` blocks indefinitely, the session leaks its
//! `max_connections` semaphore permit forever.
//!
//! ## The test
//!
//! 1. Server with `max_connections = 2`. `idle_timeout` is set to a
//!    LONG value (60 s) so the pre-fix code path can't "save itself"
//!    via the idle reaper — the leak would manifest as a real hang
//!    in production.
//! 2. Open 2 concurrent client sessions; for each, send a CONNECT
//!    then immediately have the upstream emit FIN. KEEP THE CLIENT
//!    SESSIONS ALIVE — that's the bug-triggering condition.
//! 3. Attempt a 3rd handshake. Under the fix it succeeds within
//!    seconds. Under the bug it hangs (handshake never completes
//!    because `max_connections` is saturated by the 2 leaked permits).
//!
//! Assertion: 3rd handshake completes within `STEP`. Bug would
//! manifest as a timeout panic.

use std::sync::Arc;
use std::time::Duration;

use proteus_server::relay::{self, encode_connect, RelayConfig};
use proteus_transport_alpha::client::{self, ClientConfig};
use proteus_transport_alpha::metrics::ServerMetrics;
use proteus_transport_alpha::server::{self, ServerCtx, ServerKeys};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const STEP: Duration = Duration::from_secs(10);

/// Spawn an upstream that accepts, reads the SOCKS-CONNECT-style
/// stream until EOF or a small ceiling, then drops — i.e. immediately
/// emits FIN. This is the "upstream finished early" pattern that
/// triggered the leak.
async fn spawn_fast_close_upstream() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(t) => t,
                Err(_) => return,
            };
            tokio::spawn(async move {
                // Read up to a few bytes (don't care what they are),
                // then drop the connection. Closing the TcpStream here
                // sends FIN — the server's `upstream_to_client` half
                // sees `up_r.read() == Ok(0)` and exits, sending a
                // CLOSE record to the client.
                let mut buf = [0u8; 64];
                let _ = stream.read(&mut buf).await;
                // Drop stream → FIN.
            });
        }
    });
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn server_does_not_leak_session_permits_on_upstream_eof() {
    let upstream_addr = spawn_fast_close_upstream().await;

    let server_keys = ServerKeys::generate();
    let mlkem_pk_bytes = server_keys.mlkem_pk_bytes.clone();
    let pq_fingerprint = server_keys.pq_fingerprint;
    let server_x25519_pub = server_keys.x25519_pub;
    let server_metrics = Arc::new(ServerMetrics::default());

    // Critical: cap at 2. If sessions leak, the 3rd dial gets
    // ConnGate::Rejected and the client-side handshake fails.
    let ctx = Arc::new(
        ServerCtx::new(server_keys)
            .with_max_connections(2)
            .with_metrics(Arc::clone(&server_metrics)),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();

    let relay_cfg = RelayConfig {
        // Long idle timeout so the pre-fix code can't escape the
        // leak via the idle reaper — the bug must manifest as a
        // real session-permit leak observable within the test
        // window. Production deployments routinely use 600 s here.
        idle_timeout: Some(Duration::from_secs(60)),
        metrics: Some(Arc::clone(&server_metrics)),
        access_log: None,
        max_session_bytes: None,
        abuse_detector_byte_budget: None,
        outbound_filter: None,
        pad_quantum: None,
    };
    let _server_task = tokio::spawn(server::serve(listener, ctx, move |session| {
        let cfg = relay_cfg.clone();
        async move {
            let _ = relay::handle_session(session, cfg).await;
        }
    }));

    let mut rng = rand_core::OsRng;
    let mk_cfg = |sk| ClientConfig {
        server_mlkem_pk_bytes: mlkem_pk_bytes.clone(),
        server_x25519_pub,
        server_pq_fingerprint: pq_fingerprint,
        client_id_sk: sk,
        user_id: *b"leak0001",
        pow_difficulty: 0,
        profile_hint: proteus_wire::ProfileHint::Alpha,
    };

    // ---- Phase 1: open 2 sessions, trigger upstream-side EOF,
    //                KEEP THEM ALIVE ----
    //
    // The leak-triggering condition: upstream-side EOF (causes the
    // server's `upstream_to_client` half to exit + emit CLOSE) AND
    // the client never closes. Pre-fix, this hung
    // `client_to_upstream` on `recv_record()` forever → semaphore
    // permit leaked.
    let mut held: Vec<(_, _)> = Vec::new();
    for i in 0..2 {
        let sk = proteus_crypto::sig::generate(&mut rng);
        let stream = TcpStream::connect(proxy_addr).await.unwrap();
        let session = timeout(STEP, client::handshake_over_tcp(stream, &mk_cfg(sk)))
            .await
            .unwrap_or_else(|_| panic!("phase-1 session #{i} handshake timed out"))
            .unwrap_or_else(|e| panic!("phase-1 session #{i} handshake failed: {e:?}"));

        let proteus_transport_alpha::session::AlphaSession {
            mut sender,
            mut receiver,
            ..
        } = session;

        let connect = encode_connect("127.0.0.1", upstream_addr.port());
        sender.send_record(&connect).await.unwrap();
        // One byte makes the fast-close upstream read → drop → FIN.
        sender.send_record(b"x").await.unwrap();
        sender.flush().await.unwrap();

        // Drain until the server emits CLOSE — proves the upstream-
        // side half exited (and the buggy codepath was triggered).
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        let mut saw_close = false;
        while std::time::Instant::now() < deadline {
            match timeout(Duration::from_millis(200), receiver.recv_record()).await {
                Ok(Ok(None)) | Ok(Err(_)) | Err(_) => {
                    saw_close = true;
                    break;
                }
                Ok(Ok(Some(_))) => continue,
            }
        }
        assert!(
            saw_close,
            "phase-1 #{i}: server never emitted CLOSE — upstream FIN didn't reach the relay"
        );

        // CRITICAL: keep sender + receiver alive so the
        // server-side TCP connection stays up. Pre-fix this is what
        // pinned the permit in the leaked state.
        held.push((sender, receiver));
    }

    // ---- Phase 2: 3rd handshake while the first 2 sessions are
    //                still alive from the server's POV ----
    //
    // Under the fix, the server already released both permits via
    // `select!` teardown when each upstream FIN'd. This handshake
    // completes within `STEP`.
    //
    // Under the bug, the server holds both permits → semaphore is
    // saturated → `try_acquire_connection()` returns Rejected → the
    // 3rd connection gets routed to cover (or dropped). The client
    // handshake hangs forever and `timeout(STEP, ...)` panics.
    let sk = proteus_crypto::sig::generate(&mut rng);
    let stream = TcpStream::connect(proxy_addr).await.unwrap();
    let probe = timeout(STEP, client::handshake_over_tcp(stream, &mk_cfg(sk)))
        .await
        .expect(
            "phase-2 handshake timed out — server leaked session permits. \
             The select!-vs-join! fix has regressed.",
        )
        .expect("phase-2 handshake failed");
    drop(probe);

    // Cleanup: held sessions can now be dropped.
    drop(held);
}
