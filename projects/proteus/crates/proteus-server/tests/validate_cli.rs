//! End-to-end test for the `proteus-server validate` subcommand.
//!
//! Build a real on-disk YAML + key files in a tempdir and run the
//! binary against it. We test both green and red exit codes — the
//! operator's CI gating depends on these being correct.

use std::path::PathBuf;
use std::process::Command;

/// Unique-per-thread tmpdir. Multiple parallel `cargo test` workers
/// hit the nanosecond clock at the same instant; tack on the
/// caller-supplied disambiguator + thread id.
fn tmpdir(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "proteus-validate-cli-{}-{}-{:?}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        std::thread::current().id(),
        tag,
    ));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn touch(dir: &std::path::Path, name: &str) -> PathBuf {
    let p = dir.join(name);
    // Iter-140: ML-KEM EK/DK length is now gated by validate
    // (FIPS-203 §6.1 → 1184 / 2400 bytes). Pad to the correct
    // size for ML-KEM files so the green-validate test still
    // passes; other files keep the small placeholder.
    let bytes: Vec<u8> = if name.contains(".mlkem768.pk") {
        vec![0x42u8; 1184]
    } else if name.contains(".mlkem768.sk") {
        vec![0x42u8; 2400]
    } else {
        b"placeholder".to_vec()
    };
    std::fs::write(&p, bytes).unwrap();
    p
}

#[test]
fn validate_passes_on_minimal_valid_yaml() {
    let dir = tmpdir("pass");
    let mlkem_pk = touch(&dir, "server_lt.mlkem768.pk");
    let mlkem_sk = touch(&dir, "server_lt.mlkem768.sk");
    let x25519_pk = touch(&dir, "server_lt.x25519.pk");
    let x25519_sk = touch(&dir, "server_lt.x25519.sk");
    let yaml = dir.join("server.yaml");
    // Iter-97: bind to a LAN address. The iter-97 catastrophic-
    // open-relay coherence check (wildcard listen + empty
    // allowlist + no firewall → FAIL) would otherwise trip on
    // this minimal-valid fixture, which would defeat the test's
    // intent of "the minimum config validates clean".
    std::fs::write(
        &yaml,
        format!(
            r#"listen_alpha: "192.168.1.100:8443"
keys:
  mlkem_pk: {}
  mlkem_sk: {}
  x25519_pk: {}
  x25519_sk: {}
"#,
            mlkem_pk.display(),
            mlkem_sk.display(),
            x25519_pk.display(),
            x25519_sk.display(),
        ),
    )
    .unwrap();

    let bin = env!("CARGO_BIN_EXE_proteus-server");
    let output = Command::new(bin)
        .args(["validate", "--config"])
        .arg(&yaml)
        .output()
        .expect("spawn proteus-server validate");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "exit code != 0\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("[ok]"), "stdout:\n{stdout}");
    assert!(stdout.contains("YAML parses"), "stdout:\n{stdout}");
    assert!(stdout.contains("passed"), "summary line missing:\n{stdout}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn validate_fails_on_missing_key_file() {
    let dir = tmpdir("missing");
    let yaml = dir.join("server.yaml");
    std::fs::write(
        &yaml,
        r#"listen_alpha: "0.0.0.0:8443"
keys:
  mlkem_pk: /does/not/exist/mlkem.pk
  mlkem_sk: /does/not/exist/mlkem.sk
  x25519_pk: /does/not/exist/x25519.pk
  x25519_sk: /does/not/exist/x25519.sk
"#,
    )
    .unwrap();

    let bin = env!("CARGO_BIN_EXE_proteus-server");
    let output = Command::new(bin)
        .args(["validate", "--config"])
        .arg(&yaml)
        .output()
        .expect("spawn proteus-server validate");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !output.status.success(),
        "missing key files MUST cause exit 1, got success.\nstdout:\n{stdout}"
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(stdout.contains("[FAIL]"), "stdout:\n{stdout}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Iter-48: server-side all-zero key file is a catastrophic
/// security failure (trivially-forgeable server identity). Must
/// FAIL validate even though the file is present + readable +
/// the right size.
#[test]
fn iter48_validate_fails_on_all_zero_server_key_file() {
    let dir = tmpdir("zero-keys");
    let mlkem_pk = dir.join("mlkem.pk");
    let mlkem_sk = dir.join("mlkem.sk");
    let x25519_pk = dir.join("x25519.pk");
    let x25519_sk = dir.join("x25519.sk");
    // Plant an all-zero secret key — the catastrophic case.
    std::fs::write(&mlkem_pk, b"placeholder-content").unwrap();
    std::fs::write(&mlkem_sk, [0u8; 256]).unwrap(); // all zeros
    std::fs::write(&x25519_pk, b"placeholder-content").unwrap();
    std::fs::write(&x25519_sk, b"placeholder-content").unwrap();

    let yaml = dir.join("server.yaml");
    std::fs::write(
        &yaml,
        format!(
            r#"listen_alpha: "0.0.0.0:8443"
keys:
  mlkem_pk: {}
  mlkem_sk: {}
  x25519_pk: {}
  x25519_sk: {}
"#,
            mlkem_pk.display(),
            mlkem_sk.display(),
            x25519_pk.display(),
            x25519_sk.display(),
        ),
    )
    .unwrap();

    let bin = env!("CARGO_BIN_EXE_proteus-server");
    let output = Command::new(bin)
        .args(["validate", "--config"])
        .arg(&yaml)
        .output()
        .expect("spawn proteus-server validate");
    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!("all-zero-sk stdout:\n{stdout}");
    assert!(
        !output.status.success(),
        "all-zero secret key MUST cause exit 1, got success.\nstdout:\n{stdout}"
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stdout.contains("ALL-ZERO"),
        "FAIL message must explicitly mention ALL-ZERO so the operator knows what to fix:\n{stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn validate_fails_on_malformed_yaml() {
    let dir = tmpdir("malformed");
    let yaml = dir.join("server.yaml");
    std::fs::write(&yaml, b"this is: { not valid: yaml::: at all").unwrap();

    let bin = env!("CARGO_BIN_EXE_proteus-server");
    let output = Command::new(bin)
        .args(["validate", "--config"])
        .arg(&yaml)
        .output()
        .expect("spawn proteus-server validate");

    assert!(
        !output.status.success(),
        "malformed YAML MUST cause non-zero exit"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- iter-140: ML-KEM key-length gates ----

/// Pre-iter-140 a truncated ML-KEM EK passed the server's
/// validate cleanly — the only signal was the runtime kex
/// failure when a client first dialed. Iter-140 tightens
/// the gate to the FIPS-203 §6.1 sizes (EK = 1184 bytes,
/// DK = 2400 bytes). Operators running the iter-122
/// mandatory preflight gate now learn the key is wrong
/// BEFORE deploy.
#[test]
fn validate_fails_on_truncated_mlkem_ek() {
    let dir = tmpdir("ek_truncated");
    // 100 bytes — passes pre-iter-140's existence check, fails
    // the iter-140 length gate.
    let mlkem_pk = dir.join("server_lt.mlkem768.pk");
    std::fs::write(&mlkem_pk, [0x42u8; 100]).unwrap();
    // The DK is correctly-sized so we isolate the EK failure.
    let mlkem_sk = dir.join("server_lt.mlkem768.sk");
    std::fs::write(&mlkem_sk, vec![0x42u8; 2400]).unwrap();
    let x25519_pk = touch(&dir, "server_lt.x25519.pk");
    let x25519_sk = touch(&dir, "server_lt.x25519.sk");

    let yaml = dir.join("server.yaml");
    std::fs::write(
        &yaml,
        format!(
            r#"listen_alpha: "192.168.1.100:8443"
keys:
  mlkem_pk: {}
  mlkem_sk: {}
  x25519_pk: {}
  x25519_sk: {}
"#,
            mlkem_pk.display(),
            mlkem_sk.display(),
            x25519_pk.display(),
            x25519_sk.display(),
        ),
    )
    .unwrap();

    let bin = env!("CARGO_BIN_EXE_proteus-server");
    let output = Command::new(bin)
        .args(["validate", "--config"])
        .arg(&yaml)
        .output()
        .expect("spawn proteus-server validate");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !output.status.success(),
        "iter-140: truncated EK MUST fail validate; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("keys.mlkem_pk") && stdout.contains("1184"),
        "iter-140: FAIL message MUST name the field AND the expected length; \
         stdout:\n{stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn validate_fails_on_truncated_mlkem_dk() {
    let dir = tmpdir("dk_truncated");
    let mlkem_pk = dir.join("server_lt.mlkem768.pk");
    std::fs::write(&mlkem_pk, vec![0x42u8; 1184]).unwrap();
    // 100 bytes — passes existence, fails iter-140's 2400-byte gate.
    let mlkem_sk = dir.join("server_lt.mlkem768.sk");
    std::fs::write(&mlkem_sk, [0x42u8; 100]).unwrap();
    let x25519_pk = touch(&dir, "server_lt.x25519.pk");
    let x25519_sk = touch(&dir, "server_lt.x25519.sk");

    let yaml = dir.join("server.yaml");
    std::fs::write(
        &yaml,
        format!(
            r#"listen_alpha: "192.168.1.100:8443"
keys:
  mlkem_pk: {}
  mlkem_sk: {}
  x25519_pk: {}
  x25519_sk: {}
"#,
            mlkem_pk.display(),
            mlkem_sk.display(),
            x25519_pk.display(),
            x25519_sk.display(),
        ),
    )
    .unwrap();

    let bin = env!("CARGO_BIN_EXE_proteus-server");
    let output = Command::new(bin)
        .args(["validate", "--config"])
        .arg(&yaml)
        .output()
        .expect("spawn proteus-server validate");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !output.status.success(),
        "iter-140: truncated DK MUST fail validate; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("keys.mlkem_sk") && stdout.contains("2400"),
        "iter-140: FAIL message MUST name the field AND the expected length; \
         stdout:\n{stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
