//! End-to-end test for `proteus-server admin diff`.
//!
//! Write two synthetic /metrics bodies to disk, spawn the binary,
//! verify the printed delta contains the expected counter
//! differences AND the per-second rates.

use std::path::PathBuf;
use std::process::Command;

fn tmpdir(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "proteus-admin-diff-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        tag,
    ));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn admin_diff_prints_counter_deltas_with_rates() {
    let dir = tmpdir("rates");
    let before = dir.join("before");
    let after = dir.join("after");

    std::fs::write(
        &before,
        "proteus_up 1\n\
         proteus_ready 1\n\
         proteus_sessions_accepted_total 100\n\
         proteus_handshakes_succeeded_total 95\n\
         proteus_firewall_denied_total 10\n\
         proteus_rate_limited_total 5\n\
         proteus_tx_bytes_total 1048576\n\
         proteus_rx_bytes_total 1048576\n",
    )
    .unwrap();

    // 60 seconds later: 30 new sessions, 5 new firewall denies,
    // 10 new rate-limits = 15 rejected total, 10 MiB transferred.
    std::fs::write(
        &after,
        "proteus_up 1\n\
         proteus_ready 1\n\
         proteus_in_flight_sessions 7\n\
         proteus_sessions_accepted_total 130\n\
         proteus_handshakes_succeeded_total 125\n\
         proteus_firewall_denied_total 15\n\
         proteus_rate_limited_total 15\n\
         proteus_tx_bytes_total 11534336\n\
         proteus_rx_bytes_total 1048576\n",
    )
    .unwrap();

    let bin = env!("CARGO_BIN_EXE_proteus-server");
    let output = Command::new(bin)
        .args(["admin", "diff", "--before"])
        .arg(&before)
        .arg("--after")
        .arg(&after)
        .arg("--interval-secs")
        .arg("60.0")
        .output()
        .expect("spawn proteus-server admin diff");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "exit code != 0\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    // Counter deltas in the output.
    assert!(stdout.contains("delta over 60.0s"));
    assert!(stdout.contains("LIVE / READY"));
    // sessions_accepted delta = 30 over 60s = 0.50/s
    assert!(
        stdout.contains("30") && stdout.contains("0.50/s"),
        "missing sessions_accepted 30 + 0.50/s: {stdout}"
    );
    // firewall_denied delta = 5
    assert!(stdout.contains("firewall_denied"));
    // total_rejected = 5 + 10 = 15, rate 0.25/s
    assert!(
        stdout.contains("total_rejected") && stdout.contains("0.25/s"),
        "missing total_rejected rate: {stdout}"
    );
    // tx delta = 10 MiB over 60s → ~170.67 KiB/s. Don't hard-code,
    // just verify the unit shows up.
    assert!(
        stdout.contains("KiB/s") || stdout.contains("MiB/s"),
        "missing throughput rate: {stdout}"
    );
    // No reset banner.
    assert!(
        !stdout.contains("counter reset"),
        "unexpected reset banner: {stdout}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn admin_diff_detects_counter_reset() {
    let dir = tmpdir("reset");
    let before = dir.join("before");
    let after = dir.join("after");

    std::fs::write(
        &before,
        "proteus_sessions_accepted_total 1000\n\
         proteus_handshakes_succeeded_total 950\n",
    )
    .unwrap();

    // After: counters dropped — simulates a process restart.
    std::fs::write(
        &after,
        "proteus_up 1\n\
         proteus_sessions_accepted_total 5\n\
         proteus_handshakes_succeeded_total 4\n",
    )
    .unwrap();

    let bin = env!("CARGO_BIN_EXE_proteus-server");
    let output = Command::new(bin)
        .args(["admin", "diff", "--before"])
        .arg(&before)
        .arg("--after")
        .arg(&after)
        .arg("--interval-secs")
        .arg("30.0")
        .output()
        .expect("spawn proteus-server admin diff");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("counter reset"),
        "expected reset banner: {stdout}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn admin_diff_fails_on_missing_file() {
    let bin = env!("CARGO_BIN_EXE_proteus-server");
    let output = Command::new(bin)
        .args(["admin", "diff", "--before", "/does/not/exist/a", "--after"])
        .arg("/does/not/exist/b")
        .arg("--interval-secs")
        .arg("1.0")
        .output()
        .expect("spawn proteus-server admin diff");
    assert!(
        !output.status.success(),
        "missing files MUST cause non-zero exit"
    );
}
