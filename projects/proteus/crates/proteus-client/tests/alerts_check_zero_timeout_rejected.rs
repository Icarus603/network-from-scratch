//! Iter-110: integration test that `proteus-client alerts-check`
//! rejects `--timeout-secs 0` with exit 2 + a clean stderr
//! message. Mirror of iter-108 (connect-test) + iter-109 (server
//! admin) zero-timeout traps.

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_proteus-client");

#[test]
fn iter110_alerts_check_rejects_zero_timeout() {
    let output = Command::new(BIN)
        .args([
            "alerts-check",
            "--url",
            "http://127.0.0.1:1",
            "--timeout-secs",
            "0",
        ])
        .output()
        .expect("spawn proteus-client");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("timeout_secs = 0"),
        "stderr must explain why 0 is bad: {stderr}"
    );
}
