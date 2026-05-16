//! Regression test for the cover-forward EOF-propagation fix.
//!
//! ## The bug class
//!
//! Same `tokio::join!` → `tokio::select!` family as 53c8dfc (client
//! SOCKS5 pump) and ee85b27 (server relay pump). Pre-fix, the
//! cover-forward `pump` did:
//!
//!     tokio::join!(peer_to_up, up_to_peer);
//!
//! When the peer (the auth-failed attacker) closed their socket,
//! `peer_to_up` exited and FIN'd the cover. But `up_to_peer` kept
//! its `tokio::io::copy(up_r, peer_w)` blocked waiting on data from
//! the cover. A misbehaving cover (or one waiting on a long-poll
//! request body) could keep its write side open indefinitely —
//! `up_to_peer` blocked until the `FORWARD_IDLE_TIMEOUT` (120 s)
//! outer guard fired. Every junk ClientHello from an attacker
//! parked an FD for 2 minutes.
//!
//! ## The test
//!
//! 1. Stand up a "cover" listener that ACCEPTS the forward but
//!    NEVER sends anything back AND NEVER closes — simulates the
//!    pathological cover.
//! 2. Stand up a "peer" — a TcpStream pair we control directly.
//!    Send one byte to the peer side, then close the peer.
//! 3. Call `forward_to_cover(cover, vec![], peer_stream)`. Under
//!    the fix it returns within a few hundred ms (peer_to_up
//!    finishes immediately on peer close → select tears down
//!    up_to_peer → forward returns). Under the bug it would
//!    block for 120 s until FORWARD_IDLE_TIMEOUT.

use std::time::Duration;

use proteus_transport_alpha::cover::forward_to_cover;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cover_forward_returns_promptly_when_peer_closes_and_cover_stalls() {
    // 1. Stalling cover: accepts the connection, then never writes,
    //    never closes. The connection sits open as long as the
    //    forwarder keeps it.
    let cover_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cover_addr = cover_listener.local_addr().unwrap();
    let _cover_task = tokio::spawn(async move {
        // Accept and hold the connection forever (until test scope
        // drops). Read nothing, write nothing.
        let (sock, _) = match cover_listener.accept().await {
            Ok(t) => t,
            Err(_) => return,
        };
        // Keep `sock` alive by sleeping. If we dropped it, the cover
        // would FIN and the test wouldn't actually exercise the
        // pathological "cover stalls" case.
        tokio::time::sleep(Duration::from_secs(60)).await;
        drop(sock);
    });

    // 2. Peer side: a real TCP pair. Server-side will be the
    //    `peer_stream` we hand to forward_to_cover.
    let peer_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer_listener.local_addr().unwrap();
    let client_side = tokio::spawn(async move {
        let mut sock = TcpStream::connect(peer_addr).await.unwrap();
        // Send one byte, then close immediately. The forwarder's
        // peer_to_up half observes EOF.
        let _ = sock.write_all(b"x").await;
        let _ = sock.shutdown().await;
        // Read whatever cover might send (nothing). When the forwarder
        // tears down, this read returns 0.
        let mut buf = [0u8; 64];
        let _ = tokio::io::AsyncReadExt::read(&mut sock, &mut buf).await;
    });

    let (peer_server_side, _) = peer_listener.accept().await.unwrap();

    // 3. Call forward_to_cover. Under the fix it returns within a
    //    few hundred ms. Under the bug it would block for ~120 s
    //    until FORWARD_IDLE_TIMEOUT.
    let elapsed = std::time::Instant::now();
    let fwd_result = timeout(
        Duration::from_secs(5),
        forward_to_cover(&cover_addr.to_string(), Vec::new(), peer_server_side),
    )
    .await;
    let elapsed_ms = elapsed.elapsed().as_millis();

    assert!(
        fwd_result.is_ok(),
        "forward_to_cover hung for >5s when peer closed and cover stalled — \
         tokio::join! → tokio::select! fix regressed"
    );
    let _ = fwd_result.unwrap();
    assert!(
        elapsed_ms < 2000,
        "forward_to_cover took {elapsed_ms}ms — should be <2s under the fix; \
         long elapsed time suggests the select! teardown is slow or absent"
    );

    let _ = client_side.await;
}
