//! Regression test for the server-binary's graceful-drain behavior.
//!
//! Pre-fix, the SIGTERM/SIGINT handler did:
//!
//!     tokio::time::sleep(Duration::from_secs(drain_secs)).await;
//!
//! unconditionally — even when zero sessions were in flight. A
//! rolling-restart sequence with `drain_secs = 30` (default) added
//! 30 seconds of dead-air to every binary restart, regardless of
//! actual session activity.
//!
//! This test pins the contract: when SIGTERM arrives with zero
//! in-flight sessions, the binary MUST exit within a tight window
//! (< 2 seconds, allowing for tokio scheduling + the 100 ms poll
//! tick the drain uses). drain_secs is set to a value much larger
//! than the test's deadline so any regression of the polling logic
//! back to a sleep-the-full-window surfaces as a clear timeout.
//!
//! Production importance: deployments with N replicas behind a load
//! balancer that does graceful rolling restarts (k8s `RollingUpdate`,
//! systemd `Restart=always`) accumulate this delay multiplicatively.
//! 10 replicas × 30s drain = 5 minutes of restart time per release.
//! Fixed: O(actual session time), not O(drain_secs).

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use tokio::net::{TcpListener, TcpStream};

async fn pick_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

fn tempfile_in_target() -> std::path::PathBuf {
    let dir = std::env::var("CARGO_TARGET_TMPDIR").unwrap_or_else(|_| "/tmp".to_string());
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::path::PathBuf::from(format!("{dir}/proteus-drain-test-{pid}-{nanos}"))
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn send_sigterm(child: &std::process::Child) {
    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
    }
}

#[cfg(not(unix))]
fn send_sigterm(_child: &std::process::Child) {
    // No-op on non-Unix; the test gates itself on `cfg(unix)` at the
    // top of the body.
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn binary_exits_promptly_on_sigterm_when_no_sessions_in_flight() {
    let tmp = tempfile_in_target();
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let keys_dir = tmp.join("keys");

    // 1. Generate server keys via the binary.
    let server_bin = env!("CARGO_BIN_EXE_proteus-server");
    let status = Command::new(server_bin)
        .args(["keygen", "--out"])
        .arg(&keys_dir)
        .status()
        .expect("keygen exec");
    assert!(status.success(), "keygen failed");

    // 2. Write a minimal server.yaml with a LONG drain_secs. The
    //    fix should make the binary exit way before this elapses.
    //    Pre-fix the binary would sleep the full 20 seconds.
    let listen_port = pick_free_port().await;
    let server_yaml = tmp.join("server.yaml");
    std::fs::write(
        &server_yaml,
        format!(
            "listen_alpha: \"127.0.0.1:{port}\"\n\
             drain_secs: 20\n\
             outbound_filter:\n  \
                 disabled: true\n\
             keys:\n  \
                 mlkem_pk: {keys_dir}/server_lt.mlkem768.pk\n  \
                 mlkem_sk: {keys_dir}/server_lt.mlkem768.sk\n  \
                 x25519_pk: {keys_dir}/server_lt.x25519.pk\n  \
                 x25519_sk: {keys_dir}/server_lt.x25519.sk\n",
            port = listen_port,
            keys_dir = keys_dir.display(),
        ),
    )
    .unwrap();

    // 3. Spawn the server binary.
    let mut server = Command::new(server_bin)
        .args(["run", "--config"])
        .arg(&server_yaml)
        .env("RUST_LOG", "warn")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("server spawn");

    // 4. Wait for the listener to come up.
    let listen_addr: std::net::SocketAddr = format!("127.0.0.1:{listen_port}").parse().unwrap();
    let mut ready = false;
    for _ in 0..50 {
        if TcpStream::connect(listen_addr).await.is_ok() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ready, "server never bound the listener");

    // 5. Brief settle to ensure no probe-connection state lingers.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 6. SIGTERM with ZERO in-flight sessions. Time how long the
    //    binary takes to exit.
    let sigterm_at = Instant::now();
    send_sigterm(&server);

    // Poll for exit, with a hard cap well below the configured
    // drain_secs (20 s). Fix should exit in <2 s; bug would take
    // ~20 s.
    let mut exited_at: Option<Duration> = None;
    for _ in 0..100 {
        if let Ok(Some(_)) = server.try_wait() {
            exited_at = Some(sigterm_at.elapsed());
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let elapsed = exited_at.unwrap_or_else(|| {
        let _ = server.kill();
        let _ = server.wait();
        panic!("server failed to exit within 10s of SIGTERM (drain_secs=20 would suggest the fix regressed)")
    });

    eprintln!(
        "binary exit elapsed: {:?} (drain_secs configured: 20s)",
        elapsed
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "binary took {elapsed:?} to exit on SIGTERM with zero in-flight sessions. \
         Configured drain_secs=20; fix should exit in <2s. \
         Regression of the in-flight-poll → fixed-sleep behavior?"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

#[cfg(not(unix))]
#[test]
fn graceful_drain_unix_only() {
    // Non-Unix: SIGTERM doesn't exist. Skip.
}
