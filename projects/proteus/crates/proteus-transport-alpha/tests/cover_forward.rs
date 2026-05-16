//! Cover-server forwarding integration test (spec §7.5).
//!
//! Scenario: an attacker (or wrong-key client) sends garbage to the
//! Proteus server. With `cover_endpoint` configured, the server MUST
//! splice the connection byte-verbatim to the cover server so that
//! externally the response is indistinguishable from a generic HTTPS
//! reverse proxy.
//!
//! We stand up:
//! 1. A "cover" server that responds to any TCP connection with a
//!    distinct sentinel payload (`HTTP/1.1 200 OK ...`).
//! 2. A Proteus server with cover_endpoint pointed at (1).
//! 3. An attacker that connects to (2), sends garbage, and reads the
//!    response. The response MUST contain the sentinel — proving the
//!    auth-fail path actually forwarded.

use std::sync::Arc;
use std::time::Duration;

use proteus_transport_alpha::server::{self, ServerCtx, ServerKeys};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const SENTINEL: &[u8] = b"HTTP/1.1 200 OK\r\nServer: cover-test\r\n\r\nHELLO_FROM_COVER";
const STEP: Duration = Duration::from_secs(15);

/// One-shot cover server: accept any connection, write the sentinel,
/// stream-pipe the rest, eventually close.
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
                // Read the attacker's garbage so it's drained, then
                // emit the sentinel and close. A real cover would
                // negotiate TLS, but for this test we use plain bytes
                // — the splice path doesn't care about content.
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
async fn auth_fail_forwards_to_cover_endpoint() {
    // 1. Cover server.
    let cover_addr = spawn_cover().await;

    // 2. Proteus server with cover endpoint configured.
    let server_keys = ServerKeys::generate();
    let ctx = Arc::new(ServerCtx::new(server_keys).with_cover(cover_addr.to_string()));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let server_ctx = Arc::clone(&ctx);
    let server_task = tokio::spawn(server::serve(listener, server_ctx, |_session| async {
        // No legitimate sessions expected in this test.
    }));

    // 3. Attacker: open a TCP connection, send garbage that cannot
    //    parse as a Proteus ClientHello frame, read whatever the
    //    server returns.
    let mut stream = timeout(STEP, TcpStream::connect(proxy_addr))
        .await
        .expect("connect timed out")
        .expect("connect ok");

    // Bogus first byte (random non-frame-type) followed by enough
    // bytes to make the wire decoder commit to a parse attempt.
    // `decode_frame` reads kind + varint length + body — sending
    // `0x55` as kind and varint(0) gives a "FRAME_CLIENT_HELLO?
    // no, kind != FRAME_CLIENT_HELLO" rejection path which is the
    // intended cover-forward trigger.
    timeout(STEP, stream.write_all(&[0x55, 0x00]))
        .await
        .unwrap()
        .unwrap();
    timeout(STEP, stream.flush()).await.unwrap().unwrap();

    let mut response = Vec::new();
    let mut chunk = vec![0u8; 4096];
    loop {
        match timeout(Duration::from_secs(3), stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => response.extend_from_slice(&chunk[..n]),
        }
        if response.windows(SENTINEL.len()).any(|w| w == SENTINEL) {
            break;
        }
    }

    assert!(
        response.windows(SENTINEL.len()).any(|w| w == SENTINEL),
        "expected cover sentinel in response; got {} bytes: {:?}",
        response.len(),
        &response[..response.len().min(80)],
    );

    server_task.abort();
}

/// Sanity-check the opposite: with NO cover_endpoint configured, an
/// auth-fail connection MUST be dropped silently (read returns EOF
/// without any sentinel).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auth_fail_without_cover_drops_silently() {
    let server_keys = ServerKeys::generate();
    let ctx = Arc::new(ServerCtx::new(server_keys));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let server_ctx = Arc::clone(&ctx);
    let server_task = tokio::spawn(server::serve(listener, server_ctx, |_session| async {}));

    let mut stream = timeout(STEP, TcpStream::connect(proxy_addr))
        .await
        .expect("connect timed out")
        .expect("connect ok");

    timeout(STEP, stream.write_all(&[0x55, 0x00]))
        .await
        .unwrap()
        .unwrap();
    timeout(STEP, stream.flush()).await.unwrap().unwrap();

    // Without cover, server drops the connection. read() returns 0
    // (EOF) or errors.
    let mut buf = vec![0u8; 4096];
    let n = timeout(Duration::from_secs(3), stream.read(&mut buf))
        .await
        .expect("read should not hang")
        .unwrap_or(0);
    assert_eq!(
        n, 0,
        "without cover_endpoint, server must NOT emit bytes after auth fail"
    );

    server_task.abort();
}
