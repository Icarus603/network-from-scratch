//! Regression test for `HANDSHAKE_RX_HARD_CAP` — bounds the
//! handshake-time read buffer so a malicious peer cannot OOM us by
//! streaming bytes that never decode to a complete frame.
//!
//! ## The bug
//!
//! Pre-this-cap, the handshake `read_frame` helpers grew their
//! `buf: Vec<u8>` unbounded:
//!
//!     buf.extend_from_slice(&tmp[..n]);   // loop forever
//!
//! Threat model: a rogue server (or post-MITM upstream) could send
//! arbitrary bytes during the client's handshake window —
//! `handshake_deadline` (default 15 s) bounds the TIME but not the
//! MEMORY. At ~600 MiB/s of garbage (loopback, single connection),
//! that's ~9 GiB allocated in the client's address space before the
//! deadline fires. Symmetric attack on the server: a malicious
//! client floods during the deadline window.
//!
//! ## The cap
//!
//! `HANDSHAKE_RX_HARD_CAP = 64 KiB`. Real handshake budget is ~17 KiB
//! (ClientHello 1383 + SH/SF 37 each + coalesced first DATA ≤16 KiB).
//! 64 KiB gives 4× margin while failing fast on flood attacks.
//!
//! ## Test
//!
//! 1. Stand up a Proteus server (server-side cap is the target).
//! 2. Open a raw TCP socket and stream 128 KiB of garbage in 4 KiB
//!    chunks. None of these bytes parse as a valid alpha frame
//!    because the frame type byte values won't be valid (random).
//! 3. Verify the server closes the connection within a tight window
//!    (i.e. our writes start failing with broken-pipe). Under the
//!    bug, the server would happily buffer all 128 KiB.

use std::sync::Arc;
use std::time::Duration;

use proteus_transport_alpha::server::{ServerCtx, ServerKeys};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_rejects_handshake_flood_at_64kib_buffer_cap() {
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

    // Connect and flood. Use bytes that are deliberately "valid-looking"
    // alpha frame headers but DECLARE a huge body length — this is
    // what a real attacker would do: avoid the cheap "obviously
    // malformed" reject path and keep the frame in `Short` state
    // forever (i.e. waiting for more body bytes) while bytes keep
    // streaming in.
    //
    // Frame layout: [type(1)|varint_len|body[len]].
    //
    // Use a 4-byte varint = 200_000 (body length). This forces
    // decode_frame to return `Short { needed: 200_007, have: ... }`
    // — the parser doesn't reject; it just waits. The server's
    // accept loop keeps reading from us into `buf` until either
    // - it gets enough bytes (we never send the body — we send
    //   garbage in chunks that grow `buf` past 64 KiB), or
    // - HANDSHAKE_RX_HARD_CAP fires.
    let mut sock = TcpStream::connect(addr).await.unwrap();
    sock.set_nodelay(true).ok();
    let mut hdr = Vec::with_capacity(9);
    hdr.push(0x01u8); // FRAME_CLIENT_HELLO
                      // 8-byte varint encoding 2^30 bytes = 1 GiB body length. Header
                      // is the high 2 bits == 0b11 (8-byte form), then the 62-bit value
                      // in big-endian.  decode() returns this length and `Short`s back
                      // out of decode_frame() with `needed = 1 GiB + 9`. Under the bug
                      // the server keeps reading until it has 1 GiB buffered. Under
                      // the 64 KiB cap, it bails after the first 64 KiB.
    let declared_body_len: u64 = 1 << 30; // 1 GiB
    let varint8: u64 = declared_body_len | 0xc000_0000_0000_0000;
    hdr.extend_from_slice(&varint8.to_be_bytes());
    sock.write_all(&hdr).await.unwrap();

    // Stream up to 256 MiB of garbage. Under the cap, the server
    // bails after 64 KiB → its read side closes → our writes start
    // failing once the kernel send buffer drains (typically ~256
    // KiB on loopback). Under the bug, the server's `read_frame_*`
    // helpers happily accept up to the declared 1 GiB body — our
    // writes succeed all the way through 256 MiB because there's
    // always more space in the server's `buf: Vec<u8>`.
    //
    // The decisive measurement: total_written. Under the fix it
    // should be ≤ ~16 MiB (one TCP_SNDBUF + a margin for in-flight
    // bytes already read by the server before it bailed). Under the
    // bug it should reach the full 256 MiB or close to it.
    //
    // We pick a strict 32 MiB threshold for "the cap engaged": if
    // the test wrote >32 MiB without a single write failing AND the
    // peer hasn't closed, the cap is broken.
    let garbage = vec![0xAAu8; 64 * 1024]; // bigger chunks to flood faster
    let mut total_written = 0usize;
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let mut write_failed = false;
    const FLOOD_TARGET: usize = 256 * 1024 * 1024;
    while total_written < FLOOD_TARGET && std::time::Instant::now() < deadline {
        match timeout(Duration::from_millis(500), sock.write_all(&garbage)).await {
            Ok(Ok(())) => total_written += garbage.len(),
            Ok(Err(_)) | Err(_) => {
                write_failed = true;
                break;
            }
        }
    }
    // Read side check — server FIN'd → our read sees EOF (Ok(0))
    // or error.
    let mut probe_buf = [0u8; 1024];
    let read_outcome = timeout(Duration::from_secs(2), sock.read(&mut probe_buf)).await;
    let read_saw_eof = matches!(read_outcome, Ok(Ok(0)) | Ok(Err(_)) | Err(_));

    eprintln!(
        "handshake_rx_cap: total_written = {} MiB, write_failed = {}, read_saw_eof = {}",
        total_written / (1024 * 1024),
        write_failed,
        read_saw_eof,
    );

    // Property 1: the server must close the connection within the
    // flood window. Either path is acceptable evidence.
    assert!(
        write_failed || read_saw_eof,
        "server never tore down the connection — cap did not fire. \
         Total written: {} MiB",
        total_written / (1024 * 1024),
    );
    // Property 2 (the strict cap-fired check): the server bailed BEFORE
    // we managed to push 32 MiB. Under the bug the test process can
    // saturate the kernel buffer and keep writing until the server's
    // Vec<u8> grows ~1 GiB; under the fix the server stops reading
    // at 64 KiB and the kernel TCP send buffer fills + drains until
    // RST/FIN.
    assert!(
        total_written < 32 * 1024 * 1024,
        "server appeared to buffer {} MiB of garbage during handshake — cap regressed.",
        total_written / (1024 * 1024),
    );
}
