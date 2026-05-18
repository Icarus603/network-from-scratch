//! Iter-126: `proteus-bench` zero-valued numeric arg rejection.
//!
//! Pre-iter-126 `proteus-bench beta --connect-timeout-secs 0` ran
//! through to setup and then died with
//! `Error: Connect("handshake timed out after 0ns")`. The same
//! went for `--runs 0` (silently emit nothing), `--clients 0` (no-
//! op summary), `--payload-mib 0` (degenerate report), etc.
//!
//! Symmetric with iter-108/109/110/111/117 on the other binaries:
//! every numeric arg that must be positive is gated at parse time
//! with exit 2 + a clean stderr message that calls out the bad
//! flag by name AND explains WHY zero is wrong (so the operator
//! who tried `--foo 0` understands and doesn't just retry with a
//! different bad value).
//!
//! Why this matters for production-stability: bench scripts get
//! plumbed into CI gates (`proteus-bench soak --min-success-rate
//! 0.99` is the standard "did this commit regress?" check). A
//! soak with `--duration-secs 0` would exit 0 with an empty
//! summary, silently passing the gate while measuring nothing.
//! Iter-126 makes that misconfiguration loud.

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_proteus-bench");

fn expect_exit_2_with(args: &[&str], must_contain: &[&str]) {
    let output = Command::new(BIN)
        .args(args)
        .output()
        .expect("spawn proteus-bench");
    assert_eq!(
        output.status.code(),
        Some(2),
        "expected exit 2 for args {args:?}, got {:?}; stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    for needle in must_contain {
        assert!(
            stderr.contains(needle),
            "stderr must contain {needle:?} for args {args:?}; got: {stderr}"
        );
    }
}

// ─── beta subcommand ───────────────────────────────────────────

#[test]
fn iter126_beta_rejects_zero_connect_timeout() {
    expect_exit_2_with(
        &["beta", "--connect-timeout-secs", "0"],
        &["--connect-timeout-secs = 0", "handshake timed out"],
    );
}

#[test]
fn iter126_beta_rejects_zero_total_timeout() {
    expect_exit_2_with(
        &["beta", "--total-timeout-secs", "0"],
        &["--total-timeout-secs = 0"],
    );
}

#[test]
fn iter126_beta_rejects_zero_runs() {
    expect_exit_2_with(&["beta", "--runs", "0"], &["--runs = 0"]);
}

#[test]
fn iter126_beta_rejects_zero_payload() {
    expect_exit_2_with(&["beta", "--payload-mib", "0"], &["--payload-mib = 0"]);
}

#[test]
fn iter126_beta_rejects_zero_chunk() {
    expect_exit_2_with(&["beta", "--chunk-kib", "0"], &["--chunk-kib = 0"]);
}

// ─── soak subcommand ───────────────────────────────────────────

#[test]
fn iter126_soak_rejects_zero_clients() {
    expect_exit_2_with(&["soak", "--clients", "0"], &["--clients = 0"]);
}

#[test]
fn iter126_soak_rejects_zero_duration() {
    expect_exit_2_with(
        &["soak", "--duration-secs", "0"],
        &["--duration-secs = 0", "summary would always be empty"],
    );
}

#[test]
fn iter126_soak_rejects_zero_users() {
    expect_exit_2_with(&["soak", "--users", "0"], &["--users = 0"]);
}

#[test]
fn iter126_soak_rejects_zero_per_session_payload() {
    expect_exit_2_with(
        &["soak", "--per-session-kib", "0"],
        &["--per-session-kib = 0"],
    );
}

#[test]
fn iter126_soak_rejects_zero_report_interval() {
    expect_exit_2_with(
        &["soak", "--report-interval-secs", "0"],
        &["--report-interval-secs = 0", "spin the CPU"],
    );
}

#[test]
fn iter126_soak_rejects_zero_max_concurrent_dials() {
    expect_exit_2_with(
        &["soak", "--max-concurrent-dials", "0"],
        &["--max-concurrent-dials = 0"],
    );
}

// ─── beta-client subcommand ────────────────────────────────────

#[test]
fn iter126_beta_client_rejects_zero_connect_timeout() {
    expect_exit_2_with(
        &[
            "beta-client",
            "--server-addr",
            "127.0.0.1:1",
            "--server-leaf-cert-hex",
            "00",
            "--server-mlkem-pk-hex",
            "00",
            "--server-x25519-pub-hex",
            "00",
            "--server-pq-fingerprint-hex",
            "00",
            "--connect-timeout-secs",
            "0",
        ],
        &["--connect-timeout-secs = 0"],
    );
}

#[test]
fn iter126_beta_client_rejects_zero_runs() {
    expect_exit_2_with(
        &[
            "beta-client",
            "--server-addr",
            "127.0.0.1:1",
            "--server-leaf-cert-hex",
            "00",
            "--server-mlkem-pk-hex",
            "00",
            "--server-x25519-pub-hex",
            "00",
            "--server-pq-fingerprint-hex",
            "00",
            "--runs",
            "0",
        ],
        &["--runs = 0"],
    );
}

// ─── positive value still works (regression guard) ─────────────

#[test]
fn iter126_beta_positive_args_pass_validation_then_run() {
    // We don't want this test to actually run the full bench (it
    // would take seconds and bind ports). Instead, prove that a
    // positive arg passes the iter-126 gate by checking it doesn't
    // exit 2 — it might exit 1 (bench failed) or 0 (bench passed),
    // but NOT 2 (validation rejected).
    //
    // To keep the test fast we pass `--runs 1` and a 1-second
    // total timeout — the bench will likely run end-to-end on the
    // CI host in well under a second, but if it doesn't we still
    // only see exit 1, not 2.
    let output = Command::new(BIN)
        .args([
            "beta",
            "--runs",
            "1",
            "--payload-mib",
            "1",
            "--total-timeout-secs",
            "30",
            "--connect-timeout-secs",
            "5",
        ])
        .output()
        .expect("spawn proteus-bench");
    assert_ne!(
        output.status.code(),
        Some(2),
        "positive args must NOT be rejected by the iter-126 gate; \
         stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}
