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
    std::fs::write(&p, b"placeholder").unwrap();
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
