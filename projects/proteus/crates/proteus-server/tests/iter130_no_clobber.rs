//! Iter-130: every key-emitting CLI surface must refuse to
//! overwrite existing files by default. Pre-iter-130:
//!
//! - `proteus-server knock-keygen --out <existing-file>` SILENTLY
//!   CLOBBERED whatever was at the target path with a 32-byte PSK +
//!   mode 0600 lockdown. Fat-finger `--out /etc/passwd` would have
//!   been a real disaster.
//! - `proteus-server keygen --out <existing-bundle-dir>` would have
//!   half-clobbered a production keypair (regenerating mlkem768.pk
//!   but failing partway through on a read-only FS would leave a
//!   bundle in an inconsistent state where mlkem.pk and
//!   pq.fingerprint don't match — every client handshake then fails
//!   with "fingerprint mismatch").
//! - `proteus-server gencert --out <existing-tls-dir>` same shape —
//!   would have replaced one of {fullchain.pem, privkey.pem}
//!   silently mid-handshake.
//!
//! Iter-130 contract: refuse-by-default, require explicit `--force`
//! to deliberately rotate. The error message must explain WHAT
//! would break if the overwrite proceeded (so the operator who
//! genuinely wants to rotate understands the blast radius before
//! re-running with --force).

use std::process::Command;

const SERVER_BIN: &str = env!("CARGO_BIN_EXE_proteus-server");

fn fresh_dir(tag: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "proteus-iter130-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    p
}

// ── knock-keygen ───────────────────────────────────────────────

#[test]
fn iter130_knock_keygen_refuses_to_clobber_existing_file() {
    let dir = fresh_dir("knock");
    std::fs::create_dir_all(&dir).unwrap();
    let target = dir.join("psk");
    // Plant an important-looking file.
    let sentinel = b"DO NOT OVERWRITE - operator's important data\n";
    std::fs::write(&target, sentinel).unwrap();

    let out = Command::new(SERVER_BIN)
        .args(["knock-keygen", "--out"])
        .arg(&target)
        .output()
        .expect("spawn");
    assert_ne!(
        out.status.code(),
        Some(0),
        "knock-keygen must NOT exit 0 when target exists; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to overwrite"),
        "must call out refusal: {stderr}"
    );
    assert!(
        stderr.contains("--force"),
        "must explain how to opt in: {stderr}"
    );
    // Critically: the sentinel file must still be intact.
    let after = std::fs::read(&target).unwrap();
    assert_eq!(
        after, sentinel,
        "knock-keygen must NOT touch the existing file on refusal"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn iter130_knock_keygen_force_overwrites() {
    let dir = fresh_dir("knock-force");
    std::fs::create_dir_all(&dir).unwrap();
    let target = dir.join("psk");
    std::fs::write(&target, b"old\n").unwrap();

    let out = Command::new(SERVER_BIN)
        .args(["knock-keygen", "--out"])
        .arg(&target)
        .arg("--force")
        .output()
        .expect("spawn");
    assert_eq!(
        out.status.code(),
        Some(0),
        "knock-keygen --force must succeed; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let after = std::fs::read(&target).unwrap();
    assert_ne!(after, b"old\n", "--force must actually overwrite");
    // The new file should be longer than "old\n" (it's a base64-
    // encoded 32-byte key plus comment lines).
    assert!(after.len() > 30, "rewritten file should be a real PSK");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn iter130_knock_keygen_writes_to_fresh_path() {
    // Regression: anti-clobber must NOT block legitimate first-run
    // keygen on a fresh path.
    let dir = fresh_dir("knock-fresh");
    std::fs::create_dir_all(&dir).unwrap();
    let target = dir.join("psk-never-existed");

    let out = Command::new(SERVER_BIN)
        .args(["knock-keygen", "--out"])
        .arg(&target)
        .output()
        .expect("spawn");
    assert_eq!(
        out.status.code(),
        Some(0),
        "fresh-path knock-keygen must succeed; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(target.exists(), "PSK file must be written");
    let _ = std::fs::remove_dir_all(&dir);
}

// ── keygen (server long-term bundle) ───────────────────────────

#[test]
fn iter130_keygen_refuses_to_clobber_bundle_dir() {
    let dir = fresh_dir("keygen");
    // First run populates the bundle.
    let out1 = Command::new(SERVER_BIN)
        .args(["keygen", "--out"])
        .arg(&dir)
        .output()
        .expect("spawn");
    assert_eq!(out1.status.code(), Some(0));
    // Capture the original mlkem.pk so we can prove the second run
    // doesn't touch it.
    let pk_path = dir.join("server_lt.mlkem768.pk");
    let pk_before = std::fs::read(&pk_path).unwrap();

    // Second run on the SAME dir must refuse.
    let out2 = Command::new(SERVER_BIN)
        .args(["keygen", "--out"])
        .arg(&dir)
        .output()
        .expect("spawn");
    assert_ne!(
        out2.status.code(),
        Some(0),
        "keygen must refuse to overwrite existing bundle; stderr={}",
        String::from_utf8_lossy(&out2.stderr)
    );
    let stderr = String::from_utf8_lossy(&out2.stderr);
    assert!(
        stderr.contains("refusing to overwrite"),
        "must call out refusal: {stderr}"
    );
    assert!(
        stderr.contains("fingerprint mismatch"),
        "must explain the failure mode operators will see: {stderr}"
    );
    // Bytes must be unchanged.
    let pk_after = std::fs::read(&pk_path).unwrap();
    assert_eq!(
        pk_before, pk_after,
        "keygen must NOT touch existing bundle on refusal"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn iter130_keygen_force_overwrites_bundle() {
    let dir = fresh_dir("keygen-force");
    let out1 = Command::new(SERVER_BIN)
        .args(["keygen", "--out"])
        .arg(&dir)
        .output()
        .expect("spawn");
    assert_eq!(out1.status.code(), Some(0));
    let pk_path = dir.join("server_lt.mlkem768.pk");
    let pk_before = std::fs::read(&pk_path).unwrap();

    let out2 = Command::new(SERVER_BIN)
        .args(["keygen", "--out"])
        .arg(&dir)
        .arg("--force")
        .output()
        .expect("spawn");
    assert_eq!(
        out2.status.code(),
        Some(0),
        "keygen --force must succeed; stderr={}",
        String::from_utf8_lossy(&out2.stderr)
    );
    let pk_after = std::fs::read(&pk_path).unwrap();
    assert_ne!(
        pk_before, pk_after,
        "--force must actually rotate the mlkem.pk"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ── gencert ────────────────────────────────────────────────────

#[test]
fn iter130_gencert_refuses_to_clobber_tls_pair() {
    let dir = fresh_dir("gencert");
    let out1 = Command::new(SERVER_BIN)
        .args([
            "gencert",
            "--dns-name",
            "vps.example.com",
            "--out",
        ])
        .arg(&dir)
        .output()
        .expect("spawn");
    assert_eq!(out1.status.code(), Some(0));
    let cert_before = std::fs::read(dir.join("fullchain.pem")).unwrap();

    let out2 = Command::new(SERVER_BIN)
        .args([
            "gencert",
            "--dns-name",
            "vps.example.com",
            "--out",
        ])
        .arg(&dir)
        .output()
        .expect("spawn");
    assert_ne!(
        out2.status.code(),
        Some(0),
        "gencert must refuse to clobber existing TLS pair; stderr={}",
        String::from_utf8_lossy(&out2.stderr)
    );
    let stderr = String::from_utf8_lossy(&out2.stderr);
    assert!(stderr.contains("refusing to overwrite"), "{stderr}");
    assert!(
        stderr.contains("atomically"),
        "must explain atomic-replacement requirement: {stderr}"
    );
    let cert_after = std::fs::read(dir.join("fullchain.pem")).unwrap();
    assert_eq!(
        cert_before, cert_after,
        "existing cert must NOT be touched on refusal"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn iter130_gencert_refuses_even_if_only_one_of_pair_exists() {
    // Operator removes ONE of {fullchain.pem, privkey.pem} but
    // not the other (rsync interrupted, manual edit). Re-running
    // gencert without --force would silently re-mint the missing
    // half + clobber the surviving half → half-replaced bundle
    // (the cert and key would be cryptographically unrelated to
    // each other). Refuse on either-exists.
    let dir = fresh_dir("gencert-half");
    let out1 = Command::new(SERVER_BIN)
        .args([
            "gencert",
            "--dns-name",
            "vps.example.com",
            "--out",
        ])
        .arg(&dir)
        .output()
        .expect("spawn");
    assert_eq!(out1.status.code(), Some(0));
    // Remove only the cert; leave the key.
    std::fs::remove_file(dir.join("fullchain.pem")).unwrap();

    let out2 = Command::new(SERVER_BIN)
        .args([
            "gencert",
            "--dns-name",
            "vps.example.com",
            "--out",
        ])
        .arg(&dir)
        .output()
        .expect("spawn");
    assert_ne!(
        out2.status.code(),
        Some(0),
        "gencert must refuse when EITHER file in the pair exists; stderr={}",
        String::from_utf8_lossy(&out2.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
}
