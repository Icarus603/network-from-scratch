//! Iter-29 regression test: prove the client emits a proper
//! SOCKS5 error reply on upstream-dial failure instead of
//! just dropping TCP.
//!
//! Pre-iter-29: when `try_alpha` / `try_beta` failed (VPS
//! unreachable, TLS handshake refused, etc.), the dispatcher
//! returned Err to `handle_socks5_with_ctx`, which propagated
//! up the stack and dropped the SOCKS5 TCP socket. The
//! downstream cURL / browser saw "SOCKS5 connection closed
//! without a reply" — most SOCKS5 client libraries map this
//! to a generic transport error, hiding the actual cause.
//!
//! Post-iter-29: the dispatcher's error result is intercepted
//! and a 10-byte SOCKS5 reply is written before TCP close,
//! with the REP code mapped from the underlying error
//! (0x03 network unreachable, 0x04 host unreachable, 0x05
//! connection refused, etc.).
//!
//! This test drives the failure path end-to-end:
//!   1. Open a SOCKS5 listener that points at an unreachable
//!      server endpoint (a port that nothing's listening on).
//!   2. Connect via SOCKS5, send a CONNECT for any target.
//!   3. Read the SOCKS5 reply.
//!   4. Verify the reply is 10 bytes long, starts with
//!      `0x05 <non-zero REP>`, and that the REP is one of the
//!      RFC 1928 §6 codes (not 0x00 success).

use std::sync::Arc;

use proteus_client::carrier_health::CarrierHealth;
use proteus_client::config::ClientConfig;
use proteus_client::socks::handle_socks5_with_health_and_pool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Minimal `ClientConfig` that points at an unreachable
/// server endpoint. `127.0.0.1:1` (port 1 — IANA-reserved
/// TCPMUX, almost never running) returns connection-refused
/// almost instantly on every modern OS. Iter-30 update:
/// writes valid placeholder key files so `build_handshake_config`
/// succeeds — the test wants to exercise the TCP-dial-fails
/// path, not the config-parse-fails path.
fn unreachable_cfg() -> Arc<ClientConfig> {
    use std::io::Write;
    let tmp = std::env::temp_dir().join(format!(
        "iter30-socks5-error-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&tmp).unwrap();
    // 32 zero bytes is a structurally-valid Ed25519 seed AND
    // a valid 32-byte X25519 pub AND a 32-byte fingerprint.
    let zero32 = vec![0u8; 32];
    // ML-KEM-768 EK is 1184 bytes per FIPS 203.
    let mlkem = vec![0u8; 1184];
    let p_mlkem = tmp.join("mlkem.bin");
    let p_x25519 = tmp.join("x25519.bin");
    let p_fp = tmp.join("fp.bin");
    let p_sk = tmp.join("sk.bin");
    std::fs::File::create(&p_mlkem)
        .unwrap()
        .write_all(&mlkem)
        .unwrap();
    std::fs::File::create(&p_x25519)
        .unwrap()
        .write_all(&zero32)
        .unwrap();
    std::fs::File::create(&p_fp)
        .unwrap()
        .write_all(&zero32)
        .unwrap();
    std::fs::File::create(&p_sk)
        .unwrap()
        .write_all(&zero32)
        .unwrap();
    let yaml = format!(
        "\
socks_listen: \"127.0.0.1:0\"\n\
server_endpoint: \"127.0.0.1:1\"\n\
user_id: \"test\"\n\
keys:\n  \
  server_mlkem_pk: {}\n  \
  server_x25519_pk: {}\n  \
  server_pq_fingerprint: {}\n  \
  client_ed25519_sk: {}\n\
alpha_dial_timeout_secs: 2\n\
socks_request_timeout_secs: 5\n",
        p_mlkem.display(),
        p_x25519.display(),
        p_fp.display(),
        p_sk.display(),
    );
    let cfg: ClientConfig = serde_yaml::from_str(&yaml).unwrap();
    Arc::new(cfg)
}

#[tokio::test]
async fn socks5_error_reply_emitted_on_upstream_unreachable() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = unreachable_cfg();
    let health = Arc::new(CarrierHealth::new());

    // Server: accept ONE SOCKS5 conn, hand to dispatcher.
    let server_task = tokio::spawn({
        let cfg = Arc::clone(&cfg);
        let health = Arc::clone(&health);
        async move {
            let (sock, _peer) = listener.accept().await.unwrap();
            // Returns Err (upstream unreachable), but the
            // SOCKS5 error reply MUST be written first.
            let _ = handle_socks5_with_health_and_pool(sock, &cfg, &health, None).await;
        }
    });

    // Client: speak SOCKS5, expect an error reply (not a
    // bare TCP close).
    let mut sock = TcpStream::connect(addr).await.unwrap();
    // Greeting: ver=5, nmethods=1, method=0 (no-auth).
    sock.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    // Receive greeting response: 0x05 0x00 (no-auth accepted).
    let mut greet = [0u8; 2];
    sock.read_exact(&mut greet).await.unwrap();
    assert_eq!(greet, [0x05, 0x00]);

    // Request: ver=5, cmd=1 (CONNECT), rsv=0, atyp=1 (IPv4),
    // addr=1.1.1.1, port=443.
    sock.write_all(&[0x05, 0x01, 0x00, 0x01, 1, 1, 1, 1, 0x01, 0xbb])
        .await
        .unwrap();

    // Iter-29: read the 10-byte SOCKS5 reply. The reply MUST
    // arrive — pre-iter-29 the dispatcher just dropped TCP
    // here and this read would return Ok(0) at EOF.
    let mut reply = [0u8; 10];
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        sock.read_exact(&mut reply),
    )
    .await
    .expect("read should not hit the outer timeout — iter-29 sends reply within seconds")
    .expect("read should succeed (post-iter-29 the dispatcher writes the reply before close)");
    let _ = n;

    // Reply structure: VER=5, REP=<error code>, RSV=0, ATYP=1
    // (IPv4), BND.ADDR=0.0.0.0, BND.PORT=0.
    assert_eq!(reply[0], 0x05, "VER must be 5");
    assert_ne!(
        reply[1], 0x00,
        "REP must be non-zero (upstream unreachable, not success)"
    );
    assert!(
        matches!(reply[1], 0x01 | 0x03 | 0x04 | 0x05 | 0x06),
        "REP {:#04x} must be one of RFC 1928 §6 error codes (0x01/03/04/05/06)",
        reply[1]
    );
    // Iter-30: 127.0.0.1:1 (TCPMUX) returns ECONNREFUSED
    // instantly on every modern OS → ErrorKind::
    // ConnectionRefused → REP 0x05 per the iter-30 explicit
    // mapping. If a future refactor wraps the io::Error in
    // io::Error::other() which loses the ErrorKind, this
    // assertion catches it.
    //
    // We allow 0x06 as a fallback for the rare case where
    // the loopback dial races a timeout (slow CI host), but
    // the common case on healthy boxes is 0x05.
    assert!(
        matches!(reply[1], 0x05 | 0x06),
        "REP {:#04x}: 127.0.0.1:1 should map to 0x05 ConnectionRefused (or 0x06 on rare timeout races); iter-30 explicit mapping must hold",
        reply[1]
    );
    assert_eq!(reply[2], 0x00, "RSV must be 0");
    assert_eq!(reply[3], 0x01, "ATYP must be IPv4 (1) on error replies");
    assert_eq!(&reply[4..8], &[0, 0, 0, 0], "BND.ADDR must be 0.0.0.0");
    assert_eq!(&reply[8..10], &[0, 0], "BND.PORT must be 0");

    let _ = server_task.await;
}
