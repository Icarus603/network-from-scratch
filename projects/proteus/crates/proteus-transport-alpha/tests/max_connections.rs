//! Integration test for the `max_connections` semaphore (OOM defense).
//!
//! Scenario:
//! 1. Stand up a Proteus server with `max_connections = 2` and a cover
//!    server attached.
//! 2. Open *three* simultaneous TCP connections that send garbage
//!    (won't survive the handshake) and hold them open.
//! 3. The first two connections occupy the two slots. The third MUST
//!    be routed to the cover server immediately — it must see the
//!    cover sentinel, NOT a silent drop, and `conn_limit_rejected`
//!    must increment.
//!
//! This proves:
//! - The cap is enforced.
//! - Over-cap connections still get the cover-server treatment, so an
//!   attacker can't distinguish "max_connections hit" from a generic
//!   HTTPS proxy. (REALITY property holds under load.)

use std::sync::Arc;
use std::time::Duration;

use proteus_transport_alpha::metrics::ServerMetrics;
use proteus_transport_alpha::server::{self, ServerCtx, ServerKeys};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const SENTINEL: &[u8] = b"HTTP/1.1 200 OK\r\nServer: cover\r\n\r\nHELLO";
const STEP: Duration = Duration::from_secs(10);

async fn spawn_cover() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(t) => t,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let _ = timeout(Duration::from_millis(200), stream.read(&mut buf)).await;
                let _ = stream.write_all(SENTINEL).await;
                let _ = stream.flush().await;
                let _ = stream.shutdown().await;
            });
        }
    });
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn third_connection_over_max_routes_to_cover() {
    let cover_addr = spawn_cover().await;

    let server_keys = ServerKeys::generate();
    // Slow the slowloris deadline way up so the two slot-holders DON'T
    // get reaped during the test window. (Default 15s is fine; we want
    // them parked, not killed.)
    let metrics = Arc::new(ServerMetrics::default());
    let ctx = Arc::new(
        ServerCtx::new(server_keys)
            .with_cover(cover_addr.to_string())
            .with_max_connections(2)
            .with_metrics(Arc::clone(&metrics))
            .with_handshake_deadline(Duration::from_secs(60)),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let server_ctx = Arc::clone(&ctx);
    let server_task = tokio::spawn(server::serve(listener, server_ctx, |_session| async {}));

    // 1+2: open two connections that send a *partial* frame header so
    // the server's accept-task is parked in handshake_buffered waiting
    // for more bytes. These hold the two semaphore slots open.
    let mut slot1 = timeout(STEP, TcpStream::connect(proxy_addr))
        .await
        .unwrap()
        .unwrap();
    slot1.write_all(&[0x01]).await.unwrap(); // 1 byte, server still reading
    slot1.flush().await.unwrap();

    let mut slot2 = timeout(STEP, TcpStream::connect(proxy_addr))
        .await
        .unwrap()
        .unwrap();
    slot2.write_all(&[0x01]).await.unwrap();
    slot2.flush().await.unwrap();

    // Give the server's accept loop a moment to admit both connections
    // into the spawned tasks (semaphore acquire happens before spawn).
    for _ in 0..50 {
        if ctx.available_connection_slots() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        ctx.available_connection_slots(),
        0,
        "two parked connections should consume both slots"
    );

    // 3rd connection — must be admitted by TCP accept(), then bounced
    // by the semaphore, then spliced to the cover server. We should
    // see SENTINEL.
    let mut over = timeout(STEP, TcpStream::connect(proxy_addr))
        .await
        .unwrap()
        .unwrap();
    over.write_all(b"garbage").await.unwrap();
    over.flush().await.unwrap();

    let mut response = Vec::new();
    let mut chunk = vec![0u8; 4096];
    loop {
        match timeout(Duration::from_secs(3), over.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => response.extend_from_slice(&chunk[..n]),
        }
        if response.windows(SENTINEL.len()).any(|w| w == SENTINEL) {
            break;
        }
    }
    assert!(
        response.windows(SENTINEL.len()).any(|w| w == SENTINEL),
        "over-cap connection must reach cover server. Got {} bytes: {:?}",
        response.len(),
        &response[..response.len().min(80)]
    );

    // The conn_limit_rejected counter must have ticked.
    let rejected = metrics
        .conn_limit_rejected
        .load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        rejected >= 1,
        "conn_limit_rejected_total must be >= 1, got {rejected}"
    );

    // Close the held slots — slot should free up.
    let _ = slot1.shutdown().await;
    let _ = slot2.shutdown().await;

    server_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slot_released_after_session_ends() {
    let server_keys = ServerKeys::generate();
    let ctx = Arc::new(
        ServerCtx::new(server_keys)
            .with_max_connections(1)
            .with_handshake_deadline(Duration::from_millis(200)),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let server_ctx = Arc::clone(&ctx);
    let server_task = tokio::spawn(server::serve(listener, server_ctx, |_| async {}));

    // Open + immediately close → slowloris deadline fires fast → task
    // returns → semaphore permit dropped.
    for _ in 0..3 {
        let mut sock = TcpStream::connect(proxy_addr).await.unwrap();
        sock.write_all(&[0x01]).await.unwrap();
        sock.flush().await.unwrap();
        // Wait past the 200ms deadline.
        tokio::time::sleep(Duration::from_millis(400)).await;
        let _ = sock.shutdown().await;
        // After deadline elapses + task drops permit, slot should be free.
        for _ in 0..50 {
            if ctx.available_connection_slots() >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            ctx.available_connection_slots() >= 1,
            "permit should be released after the session task ends"
        );
    }

    server_task.abort();
}
