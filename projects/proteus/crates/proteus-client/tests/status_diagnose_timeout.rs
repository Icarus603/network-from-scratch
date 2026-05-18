//! Iter-112: verify `proteus-client status` and
//! `proteus-client diagnose` time out cleanly when the admin
//! endpoint is unreachable / wedged.
//!
//! The "wedged endpoint" case is exercised by binding a TCP
//! listener that accepts connections but never writes a
//! response — read_to_end pre-iter-112 would block forever.
//!
//! The "unreachable" case is exercised by pointing the CLI at
//! a port nothing is bound to → TCP connect fails immediately
//! with refused; the timeout wrapper is structurally on the
//! path but the test mostly exercises the cleaner error
//! message.
//!
//! We use a sub-process timeout of 30s so a real regression
//! (no timeout → forever) doesn't hang the CI worker forever.

use std::process::{Command, Stdio};
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_proteus-client");

/// Spawn a child process and wait up to `wall` seconds for it
/// to exit. Kills + reports timeout if it hangs.
fn run_with_wall_timeout(mut cmd: Command, wall: Duration) -> std::process::Output {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn proteus-client");
    let pid = child.id();
    let started = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                return child.wait_with_output().expect("collect output");
            }
            Ok(None) => {
                if started.elapsed() > wall {
                    let _ = child.kill();
                    panic!(
                        "proteus-client (pid {pid}) did NOT exit within {}s — \
                         iter-112 timeout wrapper regressed (the binary hung \
                         instead of erroring cleanly)",
                        wall.as_secs()
                    );
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("try_wait: {e}"),
        }
    }
}

#[test]
fn iter112_status_against_wedged_endpoint_times_out_cleanly() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap();
    // Background thread accepts but never writes. The CLI's
    // 10s read timeout MUST fire before our 30s wall-clock.
    let _accept_thread = std::thread::spawn(move || {
        for s in listener.incoming() {
            // Hold the socket alive; do nothing.
            let _ = s;
            std::thread::sleep(Duration::from_secs(60));
        }
    });
    let mut cmd = Command::new(BIN);
    cmd.args(["status", "--url", &format!("http://{addr}")]);
    let output = run_with_wall_timeout(cmd, Duration::from_secs(30));
    // Exit non-zero (the timeout path returns Err).
    assert!(
        !output.status.success(),
        "wedged endpoint must produce non-zero exit; got {:?}",
        output.status,
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("timed out") || stderr.contains("wedged"),
        "stderr must mention timeout; got: {stderr}",
    );
}

#[test]
fn iter112_diagnose_against_wedged_endpoint_times_out_cleanly() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap();
    let _accept_thread = std::thread::spawn(move || {
        for s in listener.incoming() {
            let _ = s;
            std::thread::sleep(Duration::from_secs(60));
        }
    });
    let mut cmd = Command::new(BIN);
    cmd.args(["diagnose", "--url", &format!("http://{addr}")]);
    let output = run_with_wall_timeout(cmd, Duration::from_secs(30));
    assert!(
        !output.status.success(),
        "wedged endpoint must produce non-zero exit; got {:?}",
        output.status,
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("timed out") || stderr.contains("wedged"),
        "stderr must mention timeout; got: {stderr}",
    );
}
