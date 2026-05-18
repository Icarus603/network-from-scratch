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

/// Iter-117: admin diff rejects non-positive interval_secs.
/// Pre-iter-117 the renderer guarded against div-by-zero (≤0 →
/// 1.0) but the JSON output echoed the raw value, breaking
/// scripts that filtered by `interval_secs`.
#[test]
fn iter117_admin_diff_rejects_zero_interval() {
    // Need real files for `before` / `after` to test only the
    // interval gating; touch them.
    let dir = std::env::temp_dir().join(format!(
        "proteus-iter117-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let before = dir.join("before");
    let after = dir.join("after");
    std::fs::write(&before, "proteus_up 1\n").unwrap();
    std::fs::write(&after, "proteus_up 1\n").unwrap();
    let output = Command::new(BIN)
        .args([
            "admin",
            "diff",
            "--before",
        ])
        .arg(&before)
        .args(["--after"])
        .arg(&after)
        .args(["--interval-secs", "0"])
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("interval_secs = 0") && stderr.contains("positive"),
        "stderr must call out positive + finite: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn iter117_admin_diff_rejects_negative_interval() {
    let dir = std::env::temp_dir().join(format!(
        "proteus-iter117-neg-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let before = dir.join("before");
    let after = dir.join("after");
    std::fs::write(&before, "proteus_up 1\n").unwrap();
    std::fs::write(&after, "proteus_up 1\n").unwrap();
    let output = Command::new(BIN)
        .args(["admin", "diff", "--before"])
        .arg(&before)
        .args(["--after"])
        .arg(&after)
        .args(["--interval-secs", "-5"])
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(2));
    let _ = std::fs::remove_dir_all(&dir);
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
