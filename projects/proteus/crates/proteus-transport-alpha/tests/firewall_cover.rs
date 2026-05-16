//! Integration test for the CIDR firewall.
//!
//! Scenario: stand up a Proteus server whose firewall denies
//! `127.0.0.0/8`. Connect from loopback — the connection must be
//! byte-spliced to the cover server. This proves:
//!
//! 1. The firewall is checked before the handshake even begins (the
//!    test never speaks the Proteus wire format).
//! 2. Denied connections still get the REALITY-grade indistinguishability
//!    treatment via cover-forward.
//! 3. `firewall_denied_total` increments.

use std::sync::Arc;
use std::time::Duration;

use proteus_transport_alpha::firewall::Firewall;
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
async fn denied_source_is_routed_to_cover() {
    let cover_addr = spawn_cover().await;

    let server_keys = ServerKeys::generate();
    let metrics = Arc::new(ServerMetrics::default());
    let mut fw = Firewall::new();
    fw.extend_deny(["127.0.0.0/8"]).unwrap();

    let ctx = Arc::new(
        ServerCtx::new(server_keys)
            .with_cover(cover_addr.to_string())
            .with_firewall(fw)
            .with_metrics(Arc::clone(&metrics)),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let server_ctx = Arc::clone(&ctx);
    let server_task = tokio::spawn(server::serve(listener, server_ctx, |_session| async {}));

    let mut sock = timeout(STEP, TcpStream::connect(proxy_addr))
        .await
        .unwrap()
        .unwrap();
    // Send any non-zero traffic; the server should immediately route us
    // to cover before even reading.
    sock.write_all(b"garbage").await.unwrap();
    sock.flush().await.unwrap();

    let mut response = Vec::new();
    let mut chunk = vec![0u8; 4096];
    loop {
        match timeout(Duration::from_secs(3), sock.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => response.extend_from_slice(&chunk[..n]),
        }
        if response.windows(SENTINEL.len()).any(|w| w == SENTINEL) {
            break;
        }
    }
    assert!(
        response.windows(SENTINEL.len()).any(|w| w == SENTINEL),
        "denied source must reach cover server. Got {} bytes: {:?}",
        response.len(),
        &response[..response.len().min(80)],
    );

    let denied = metrics
        .firewall_denied
        .load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        denied >= 1,
        "firewall_denied_total must increment, got {denied}"
    );

    server_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn allowlist_non_match_also_denies() {
    // Allowlist that does NOT include loopback. Loopback connections
    // must be denied (and routed to cover).
    let cover_addr = spawn_cover().await;

    let server_keys = ServerKeys::generate();
    let metrics = Arc::new(ServerMetrics::default());
    let mut fw = Firewall::new();
    fw.extend_allow(["10.0.0.0/8"]).unwrap();

    let ctx = Arc::new(
        ServerCtx::new(server_keys)
            .with_cover(cover_addr.to_string())
            .with_firewall(fw)
            .with_metrics(Arc::clone(&metrics)),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let server_ctx = Arc::clone(&ctx);
    let server_task = tokio::spawn(server::serve(listener, server_ctx, |_session| async {}));

    let mut sock = timeout(STEP, TcpStream::connect(proxy_addr))
        .await
        .unwrap()
        .unwrap();
    sock.write_all(b"garbage").await.unwrap();
    sock.flush().await.unwrap();

    let mut response = Vec::new();
    let mut chunk = vec![0u8; 4096];
    loop {
        match timeout(Duration::from_secs(3), sock.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => response.extend_from_slice(&chunk[..n]),
        }
        if response.windows(SENTINEL.len()).any(|w| w == SENTINEL) {
            break;
        }
    }
    assert!(
        response.windows(SENTINEL.len()).any(|w| w == SENTINEL),
        "non-allowlisted source must reach cover server"
    );

    server_task.abort();
}
