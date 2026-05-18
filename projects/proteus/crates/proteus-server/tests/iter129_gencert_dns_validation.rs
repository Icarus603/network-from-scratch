//! Iter-129: `proteus-server gencert --dns-name <bad>` integration
//! test. The unit tests in `gencert.rs` verify the validator
//! itself; this file verifies the CLI dispatch wires
//! `validate_dns_name` → exit 2 + actionable stderr correctly.
//!
//! Pre-iter-129 rcgen accepted ANY string as a SAN (empty, "...",
//! "Hello World", "vps.example..com" double-dot typo), silently
//! minted a "valid" cert, and the operator's first hint of trouble
//! was rustls's opaque `NotValidForName` error on every subsequent
//! client handshake. This test pins the exit-2-on-validator-error
//! contract so a future refactor can't silently regress.

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_proteus-server");

fn fresh_outdir(suffix: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "proteus-iter129-{suffix}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    p
}

fn expect_exit_2(dns_name: &str, must_contain: &[&str]) {
    let out_dir = fresh_outdir("rejected");
    // Use `--dns-name=...` form to bypass clap's "is this a flag?"
    // parse for values starting with `-`.
    let output = Command::new(BIN)
        .args(["gencert", &format!("--dns-name={dns_name}"), "--out"])
        .arg(&out_dir)
        .output()
        .expect("spawn proteus-server");
    assert_eq!(
        output.status.code(),
        Some(2),
        "expected exit 2 for --dns-name {dns_name:?}; got {:?}; stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    for needle in must_contain {
        assert!(
            stderr.contains(needle),
            "stderr must contain {needle:?} for --dns-name {dns_name:?}; got: {stderr}"
        );
    }
    // Even on rejection, we must NOT have written any cert files.
    // rcgen never ran, so the outdir should not exist (or be empty
    // if a parent dir was pre-created by accident).
    if out_dir.exists() {
        let entries: Vec<_> = std::fs::read_dir(&out_dir).unwrap().collect();
        assert!(
            entries.is_empty(),
            "rejected gencert must NOT write files; found {} entries in {}",
            entries.len(),
            out_dir.display()
        );
        let _ = std::fs::remove_dir_all(&out_dir);
    }
}

#[test]
fn iter129_gencert_rejects_empty_dns_name() {
    expect_exit_2("", &["is empty", "NotValidForName"]);
}

#[test]
fn iter129_gencert_rejects_consecutive_dots() {
    expect_exit_2(
        "vps.example..com",
        &["empty label", "NotValidForName"],
    );
}

#[test]
fn iter129_gencert_rejects_space_in_name() {
    // Case-sensitive match. The validator message says "Spaces"
    // (capital S, plural — "Spaces, underscores, unicode all
    // rejected..."). Keep matching that exact word.
    expect_exit_2("Hello World", &["non-LDH", "Spaces"]);
}

#[test]
fn iter129_gencert_rejects_just_dots() {
    expect_exit_2("...", &["leading or trailing dot"]);
}

#[test]
fn iter129_gencert_rejects_leading_hyphen() {
    expect_exit_2("-foo.example.com", &["starting or ending with a hyphen"]);
}

#[test]
fn iter129_gencert_rejects_underscore() {
    expect_exit_2("internal_vps.example.com", &["non-LDH"]);
}

#[test]
fn iter129_gencert_accepts_valid_hostname_and_writes_files() {
    let out_dir = fresh_outdir("accepted");
    let output = Command::new(BIN)
        .args([
            "gencert",
            "--dns-name",
            "vps.example.com",
            "--out",
        ])
        .arg(&out_dir)
        .output()
        .expect("spawn proteus-server");
    assert_eq!(
        output.status.code(),
        Some(0),
        "valid --dns-name must exit 0; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(out_dir.join("fullchain.pem").exists(), "cert file must be written");
    assert!(out_dir.join("privkey.pem").exists(), "key file must be written");
    let _ = std::fs::remove_dir_all(&out_dir);
}

#[test]
fn iter129_gencert_accepts_ip_literal() {
    let out_dir = fresh_outdir("ip-literal");
    let output = Command::new(BIN)
        .args(["gencert", "--dns-name", "203.0.113.42", "--out"])
        .arg(&out_dir)
        .output()
        .expect("spawn proteus-server");
    assert_eq!(
        output.status.code(),
        Some(0),
        "IP-literal --dns-name must exit 0 (rcgen detects + emits \
         IPAddress SAN); stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let _ = std::fs::remove_dir_all(&out_dir);
}

#[test]
fn iter129_gencert_accepts_wildcard_san() {
    let out_dir = fresh_outdir("wildcard");
    let output = Command::new(BIN)
        .args(["gencert", "--dns-name", "*.example.com", "--out"])
        .arg(&out_dir)
        .output()
        .expect("spawn proteus-server");
    assert_eq!(
        output.status.code(),
        Some(0),
        "wildcard --dns-name must exit 0 (RFC 6125 §6.4.3 allows \
         single leading wildcard label); stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let _ = std::fs::remove_dir_all(&out_dir);
}
