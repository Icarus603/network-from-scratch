//! Iter-130 (client side): `proteus-client keygen --out <existing>`
//! must refuse to overwrite without `--force`. Symmetric with the
//! server-side iter-130 contract.
//!
//! Pre-iter-130 a fat-fingered re-keygen would have silently
//! clobbered the client's long-term identity. The new public key
//! would not be on the server allowlist; every handshake would
//! fail with the opaque "unknown client_id" error and the operator
//! would have no way back to the old identity (the SK is gone).

use std::process::Command;

const CLIENT_BIN: &str = env!("CARGO_BIN_EXE_proteus-client");

fn fresh_dir(tag: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "proteus-client-iter130-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    p
}

#[test]
fn iter130_client_keygen_refuses_to_clobber_existing_identity() {
    let dir = fresh_dir("identity");
    let out1 = Command::new(CLIENT_BIN)
        .args(["keygen", "--out"])
        .arg(&dir)
        .output()
        .expect("spawn proteus-client");
    assert_eq!(out1.status.code(), Some(0), "first keygen must succeed");
    let sk_path = dir.join("client.ed25519.sk");
    let sk_before = std::fs::read(&sk_path).unwrap();

    let out2 = Command::new(CLIENT_BIN)
        .args(["keygen", "--out"])
        .arg(&dir)
        .output()
        .expect("spawn proteus-client");
    assert_ne!(
        out2.status.code(),
        Some(0),
        "second keygen on same dir must refuse; stderr={}",
        String::from_utf8_lossy(&out2.stderr)
    );
    let stderr = String::from_utf8_lossy(&out2.stderr);
    assert!(stderr.contains("refusing to overwrite"), "{stderr}");
    assert!(
        stderr.contains("unknown client_id"),
        "must explain the failure mode operators will see: {stderr}"
    );
    assert!(
        stderr.contains("server admin"),
        "must explain the coordination requirement with the operator: {stderr}"
    );
    let sk_after = std::fs::read(&sk_path).unwrap();
    assert_eq!(
        sk_before, sk_after,
        "existing SK must NOT be touched on refusal"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn iter130_client_keygen_force_overwrites() {
    let dir = fresh_dir("force");
    let _ = Command::new(CLIENT_BIN)
        .args(["keygen", "--out"])
        .arg(&dir)
        .output()
        .expect("spawn proteus-client");
    let sk_path = dir.join("client.ed25519.sk");
    let sk_before = std::fs::read(&sk_path).unwrap();

    let out = Command::new(CLIENT_BIN)
        .args(["keygen", "--out"])
        .arg(&dir)
        .arg("--force")
        .output()
        .expect("spawn proteus-client");
    assert_eq!(out.status.code(), Some(0), "--force must succeed");
    let sk_after = std::fs::read(&sk_path).unwrap();
    assert_ne!(sk_before, sk_after, "--force must actually rotate the SK");
    let _ = std::fs::remove_dir_all(&dir);
}
