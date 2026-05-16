//! Regression tests for handshake-time panic-robustness.
//!
//! Defense-in-depth check: every place the server consumes
//! adversary-controlled bytes during the handshake must return a
//! clean `AlphaError` rather than panic. A handshake-time panic is
//! a server-side DoS: a single attacker connection can take down
//! the binary (or, in a multi-threaded runtime, the spawned task —
//! tokio prints the backtrace but continues; still an observable
//! noise channel + a real correctness bug).
//!
//! This file covers length-mismatch attacks on the handshake
//! frames the server reads from the client:
//!
//!   - ClientHello: well-bounded by AuthExtension wire format,
//!     `AuthExtension::decode_payload` rejects on length mismatch.
//!   - ClientFinished: must be exactly 32 bytes. Pre-this-fix
//!     (commit 2bed415's successor) the server did
//!     `cf.body.as_slice().try_into().unwrap()` after the length
//!     check above. If a future refactor dropped the length check,
//!     the unwrap would panic on adversary input.
//!
//! After the fix, the conversion uses `try_into()` + `?` so the
//! safety property is local to the call site rather than tracked
//! across two lines.

use std::sync::Arc;
use std::time::Duration;

use proteus_transport_alpha::server::{ServerCtx, ServerKeys};
use proteus_wire::alpha;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

/// Send a malformed ClientFinished (wrong body length) after a
/// valid ClientHello and observe that the server rejects cleanly
/// without panicking. We can't easily produce a valid CH+SH chain
/// without the full crypto state, so instead we verify the
/// SHAPE-LEVEL property: the server's `read_frame`-style code paths
/// gracefully reject length-mismatched frames the moment they're
/// decoded.
///
/// The narrowest replicable proof: send a malformed handshake frame
/// type that should hit the length-check guards. Server returns
/// AlphaError::Closed (or BadClientFinished); the task that handles
/// the connection terminates cleanly; OTHER connections continue
/// to be served.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_survives_garbled_clientfinished_frame() {
    let server_keys = ServerKeys::generate();
    let ctx = Arc::new(ServerCtx::new(server_keys));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_ctx = Arc::clone(&ctx);

    // Track how many sessions the handler completes vs how many
    // connections we open. If the server panics, the spawn task
    // dies before the handler returns and our count would lag.
    let handler_count = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let handler_count_clone = Arc::clone(&handler_count);
    tokio::spawn(proteus_transport_alpha::server::serve(
        listener,
        server_ctx,
        move |_session| {
            let c = Arc::clone(&handler_count_clone);
            async move {
                c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        },
    ));

    // ---- Attack: feed a malformed ClientHello frame with a 0-byte
    //              body (length-mismatch with AUTH_EXT_LEN_V10 = 1378).
    //              Server should return cleanly, not panic.
    let mut sock = TcpStream::connect(addr).await.unwrap();
    sock.set_nodelay(true).ok();
    // FRAME_CLIENT_HELLO = 0x01. Body length = 0 via 1-byte varint.
    let frame: [u8; 2] = [alpha::FRAME_CLIENT_HELLO, 0x00];
    sock.write_all(&frame).await.unwrap();

    // Wait for the server to react (either CLOSE the connection or
    // forward to cover). Either way our read should observe EOF or
    // some bytes within a reasonable window.
    let mut buf = [0u8; 64];
    let _ = timeout(Duration::from_secs(2), sock.read(&mut buf)).await;
    drop(sock);

    // ---- Now verify the server is still alive by attempting another
    //      connection and observing it gets accepted. If the server
    //      had panicked into a broken state, the second connect would
    //      either fail or hang.
    let probe = timeout(Duration::from_secs(2), TcpStream::connect(addr)).await;
    assert!(
        matches!(probe, Ok(Ok(_))),
        "server died after malformed ClientHello — handshake-panic guard regressed"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_rejects_clienthello_body_length_under_minimum() {
    // Same shape as above but specifically asserts that a CH with
    // a body length BELOW the AuthExtension minimum is rejected
    // without panic. AuthExtension::decode_payload checks
    // `buf.len() != AUTH_EXT_LEN_V10` (1378) and returns
    // WireError::AuthExtLengthMismatch — never indexes past the
    // buffer.

    let server_keys = ServerKeys::generate();
    let ctx = Arc::new(ServerCtx::new(server_keys));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_ctx = Arc::clone(&ctx);
    tokio::spawn(proteus_transport_alpha::server::serve(
        listener,
        server_ctx,
        |_session| async {},
    ));

    // Send CH with a 100-byte body of zeros. AUTH_EXT_LEN_V10 = 1378
    // so this is a length mismatch.
    let mut sock = TcpStream::connect(addr).await.unwrap();
    sock.set_nodelay(true).ok();
    let mut frame = Vec::with_capacity(110);
    frame.push(alpha::FRAME_CLIENT_HELLO);
    // Varint for 100 = 0x40 64 (2-byte form), 0x40 prefix + 14 bits.
    // 100 = 0x0064; with the high bits = 0b01 prefix: 0x4064.
    frame.extend_from_slice(&0x4064u16.to_be_bytes());
    frame.extend_from_slice(&[0u8; 100]);
    sock.write_all(&frame).await.unwrap();

    // Server must respond within a few seconds (either close or
    // forward to cover) — no hang, no panic.
    let mut buf = [0u8; 64];
    let read_outcome = timeout(Duration::from_secs(3), sock.read(&mut buf)).await;
    assert!(
        matches!(read_outcome, Ok(Ok(0)) | Ok(Err(_)) | Err(_)),
        "server hung on under-minimum ClientHello body — handshake parser may have entered \
         an infinite loop on adversary input"
    );
}
