//! Iter-109: integration test that the admin sub-commands
//! reject `--timeout-secs 0` / `--interval-secs 0` with exit
//! 2 + a clean stderr message instead of running through and
//! producing useless deadline-exceeded output.

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_proteus-server");

#[test]
fn iter109_admin_status_rejects_zero_timeout() {
    let output = Command::new(BIN)
        .args([
            "admin",
            "status",
            "--url",
            "http://127.0.0.1:1/metrics",
            "--timeout-secs",
            "0",
        ])
        .output()
        .expect("spawn proteus-server");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("timeout_secs = 0"),
        "stderr must explain why 0 is bad: {stderr}"
    );
}

#[test]
fn iter109_admin_watch_rejects_zero_timeout() {
    let output = Command::new(BIN)
        .args([
            "admin",
            "watch",
            "--url",
            "http://127.0.0.1:1/metrics",
            "--timeout-secs",
            "0",
            "--interval-secs",
            "5",
        ])
        .output()
        .expect("spawn proteus-server");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("timeout_secs = 0"), "{stderr}");
}

#[test]
fn iter109_admin_watch_rejects_zero_interval() {
    let output = Command::new(BIN)
        .args([
            "admin",
            "watch",
            "--url",
            "http://127.0.0.1:1/metrics",
            "--timeout-secs",
            "5",
            "--interval-secs",
            "0",
        ])
        .output()
        .expect("spawn proteus-server");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("interval_secs = 0") && stderr.contains("spin"),
        "stderr must call out CPU-spin behaviour: {stderr}"
    );
}

#[test]
fn iter109_admin_alerts_check_rejects_zero_timeout() {
    let output = Command::new(BIN)
        .args([
            "admin",
            "alerts-check",
            "--url",
            "http://127.0.0.1:1/metrics",
            "--timeout-secs",
            "0",
        ])
        .output()
        .expect("spawn proteus-server");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("timeout_secs = 0"), "{stderr}");
}
