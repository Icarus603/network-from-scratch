//! Integration test for the global handshake budget.
//!
//! Scenario: stand up a server whose global budget has capacity 2 and
//! virtually no refill, then attempt three "garbage" connections from
//! loopback. The first two should reach the cover server through the
//! auth-fail path (the budget is consumed *before* the handshake, so
//! the budget bucket gets debited even for connections that ultimately
//! fail). The third should route to cover via the budget-rejection
//! path. The `handshake_budget_rejected_total` counter must increment.
//!
//! The point: this layer protects ML-KEM CPU regardless of per-IP
//! limits — a botnet with 10 k IPs each staying under the per-IP
//! ceiling still can't saturate the server.

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

async fn probe(addr: std::net::SocketAddr) -> Vec<u8> {
    let mut sock = timeout(STEP, TcpStream::connect(addr))
        .await
        .unwrap()
        .unwrap();
    // Trigger the cover-forward decoder path (kind=0x55, varint=0).
    let _ = sock.write_all(&[0x55, 0x00]).await;
    let _ = sock.flush().await;
    let mut out = Vec::new();
    let mut chunk = vec![0u8; 4096];
    loop {
        match timeout(Duration::from_secs(2), sock.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => out.extend_from_slice(&chunk[..n]),
        }
        if out.windows(SENTINEL.len()).any(|w| w == SENTINEL) {
            break;
        }
    }
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn global_budget_rejects_third_handshake() {
    let cover_addr = spawn_cover().await;
    let metrics = Arc::new(ServerMetrics::default());

    // Capacity 2, virtually no refill — the third probe in any short
    // window must hit the budget cap.
    let ctx = Arc::new(
        ServerCtx::new(ServerKeys::generate())
            .with_cover(cover_addr.to_string())
            .with_handshake_budget(2.0, 0.001)
            .with_metrics(Arc::clone(&metrics)),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let ctx_clone = Arc::clone(&ctx);
    let server_task = tokio::spawn(server::serve(listener, ctx_clone, |_session| async {}));

    // Three probes back-to-back. All should reach cover, but the
    // *reason* the third did is the budget — proteus_handshake_budget_rejected_total
    // must show > 0.
    for _ in 0..3 {
        let r = probe(proxy_addr).await;
        assert!(
            r.windows(SENTINEL.len()).any(|w| w == SENTINEL),
            "every probe (including budget-rejected) should reach cover"
        );
    }

    let rejected = metrics
        .handshake_budget_rejected
        .load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        rejected >= 1,
        "expected handshake_budget_rejected_total >= 1, got {rejected}"
    );

    server_task.abort();
}
