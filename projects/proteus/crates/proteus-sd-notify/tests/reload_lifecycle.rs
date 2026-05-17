//! Integration test for the RELOADING=1 → READY=1 pairing used
//! by the server's SIGHUP handler.
//!
//! The handler MUST emit RELOADING=1 on signal entry and READY=1
//! on exit. Leaving RELOADING=1 hanging pins the systemd unit
//! in the "reloading" state until the next restart — an
//! operator-visible footgun. This test simulates the protocol
//! against a synthetic UnixDatagram listener and verifies both
//! messages are sent in order.

use std::sync::Mutex;
use std::time::Duration;

use tokio::net::UnixDatagram;

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn unique_socket_path(suffix: &str) -> std::path::PathBuf {
    let base = std::env::var("CARGO_TARGET_TMPDIR").unwrap_or_else(|_| "/tmp".to_string());
    let p = std::path::PathBuf::from(format!(
        "{base}/proteus-sd-notify-reload-{suffix}-{}-{}.sock",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_file(&p);
    p
}

async fn recv_one(sock: &UnixDatagram) -> Vec<u8> {
    let mut buf = [0u8; 1024];
    match tokio::time::timeout(Duration::from_secs(1), sock.recv(&mut buf)).await {
        Ok(Ok(n)) => buf[..n].to_vec(),
        Ok(Err(e)) => panic!("recv failed: {e}"),
        Err(_) => panic!("timed out waiting for sd_notify"),
    }
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn reload_lifecycle_emits_reloading_then_ready_in_order() {
    let _g = ENV_LOCK.lock().unwrap();
    let path = unique_socket_path("ok");
    let listener = UnixDatagram::bind(&path).unwrap();
    std::env::set_var("NOTIFY_SOCKET", &path);

    // Simulate the SIGHUP handler shape: notify_reloading + status
    // → do work → notify_ready + status.
    let r1 = proteus_sd_notify::notify_reloading().await;
    let r2 = proteus_sd_notify::notify_status("reloading config (SIGHUP)").await;
    // (work goes here in the real handler — config re-parse, etc.)
    let r3 = proteus_sd_notify::notify_ready().await;
    let r4 = proteus_sd_notify::notify_status("ready (last SIGHUP succeeded)").await;

    let m1 = recv_one(&listener).await;
    let m2 = recv_one(&listener).await;
    let m3 = recv_one(&listener).await;
    let m4 = recv_one(&listener).await;

    std::env::remove_var("NOTIFY_SOCKET");
    let _ = std::fs::remove_file(&path);

    assert_eq!(r1, proteus_sd_notify::NotifyResult::Sent);
    assert_eq!(r2, proteus_sd_notify::NotifyResult::Sent);
    assert_eq!(r3, proteus_sd_notify::NotifyResult::Sent);
    assert_eq!(r4, proteus_sd_notify::NotifyResult::Sent);
    assert_eq!(m1, b"RELOADING=1\n");
    assert!(
        std::str::from_utf8(&m2)
            .unwrap()
            .starts_with("STATUS=reloading"),
        "second message must be STATUS=reloading*: got {:?}",
        std::str::from_utf8(&m2)
    );
    assert_eq!(m3, b"READY=1\n");
    assert!(
        std::str::from_utf8(&m4)
            .unwrap()
            .starts_with("STATUS=ready"),
        "fourth message must be STATUS=ready*: got {:?}",
        std::str::from_utf8(&m4)
    );
}

/// Status refresher pattern: a periodic loop sends STATUS= with
/// fresh metrics every N seconds. Verify that consecutive STATUS
/// lines reach the listener even with different payloads (i.e.
/// we don't accidentally dedupe / cache).
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn periodic_status_refresh_sends_fresh_payloads() {
    let _g = ENV_LOCK.lock().unwrap();
    let path = unique_socket_path("refresh");
    let listener = UnixDatagram::bind(&path).unwrap();
    std::env::set_var("NOTIFY_SOCKET", &path);

    let _ = proteus_sd_notify::notify_status("in_flight=0 handshakes_ok=0").await;
    let _ = proteus_sd_notify::notify_status("in_flight=3 handshakes_ok=42").await;
    let _ = proteus_sd_notify::notify_status("in_flight=1 handshakes_ok=100").await;

    let m1 = recv_one(&listener).await;
    let m2 = recv_one(&listener).await;
    let m3 = recv_one(&listener).await;

    std::env::remove_var("NOTIFY_SOCKET");
    let _ = std::fs::remove_file(&path);

    assert_eq!(m1, b"STATUS=in_flight=0 handshakes_ok=0\n");
    assert_eq!(m2, b"STATUS=in_flight=3 handshakes_ok=42\n");
    assert_eq!(m3, b"STATUS=in_flight=1 handshakes_ok=100\n");
}
