//! End-to-end coverage for `proteus-server preflight check-ip-reputation`.
//!
//! Spawns the actual binary (no in-process shortcut) and asserts the
//! three classification regimes — PASS / WARN / FAIL — exit with the
//! correct code and surface the expected guidance keywords.
//!
//! The library-level tests in `preflight::tests` cover the logic; this
//! file pins the clap argument parsing + stdout format + process exit
//! code so a future refactor of `main.rs` can't silently break the
//! external CLI contract.

use std::path::PathBuf;
use std::process::Command;

fn tmpdir(suffix: &str) -> PathBuf {
    let base = std::env::var("CARGO_TARGET_TMPDIR").unwrap_or_else(|_| "/tmp".to_string());
    let p = PathBuf::from(format!(
        "{base}/proteus-server-preflight-{suffix}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn preflight_clean_residential_ip_exits_zero() {
    let bin = env!("CARGO_BIN_EXE_proteus-server");
    let output = Command::new(bin)
        .args(["preflight", "check-ip-reputation", "--public-ip", "8.8.8.8"])
        .output()
        .expect("spawn preflight");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "exit != 0\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("LikelyResidential"), "stdout:\n{stdout}");
    assert!(stdout.contains("preflight CLEAN"), "stdout:\n{stdout}");
}

#[test]
fn preflight_digitalocean_ip_warns_but_exits_zero() {
    let bin = env!("CARGO_BIN_EXE_proteus-server");
    let output = Command::new(bin)
        .args([
            "preflight",
            "check-ip-reputation",
            "--public-ip",
            "138.197.42.42",
        ])
        .output()
        .expect("spawn preflight");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "WARN class must not fail the exit code; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("DigitalOcean") && stdout.contains("WARN"),
        "stdout:\n{stdout}"
    );
    // Guidance line must mention IP rotation.
    assert!(
        stdout.contains("rotat") || stdout.contains("rotation"),
        "guidance should mention rotation; stdout:\n{stdout}"
    );
}

#[test]
fn preflight_loopback_ip_fails_exit_one() {
    let bin = env!("CARGO_BIN_EXE_proteus-server");
    let output = Command::new(bin)
        .args([
            "preflight",
            "check-ip-reputation",
            "--public-ip",
            "127.0.0.1",
        ])
        .output()
        .expect("spawn preflight");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !output.status.success(),
        "loopback MUST exit 1; stdout:\n{stdout}"
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(stdout.contains("Special") && stdout.contains("loopback"));
    assert!(
        stdout.contains("config error"),
        "actionable guidance missing; stdout:\n{stdout}"
    );
}

#[test]
fn preflight_no_ip_no_config_fails_with_guidance() {
    let bin = env!("CARGO_BIN_EXE_proteus-server");
    let output = Command::new(bin)
        .args(["preflight", "check-ip-reputation"])
        .output()
        .expect("spawn preflight");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!output.status.success());
    assert!(
        stdout.contains("--public-ip") && stdout.contains("--config"),
        "FAIL guidance must point at both knobs; stdout:\n{stdout}"
    );
}

#[test]
fn preflight_with_watchlist_blocks_otherwise_clean_ip() {
    let dir = tmpdir("watchlist");
    let wl = dir.join("watch.txt");
    std::fs::write(
        &wl,
        "# operator's burned-IP record\n\
         8.8.8.0/24  burned 2026-04 batch\n",
    )
    .unwrap();

    let bin = env!("CARGO_BIN_EXE_proteus-server");
    let output = Command::new(bin)
        .args([
            "preflight",
            "check-ip-reputation",
            "--public-ip",
            "8.8.8.8",
            "--watchlist",
        ])
        .arg(&wl)
        .output()
        .expect("spawn preflight");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !output.status.success(),
        "watchlist hit MUST exit 1; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("OperatorBlocked") && stdout.contains("burned 2026-04 batch"),
        "OperatorBlocked classification missing or reason elided; stdout:\n{stdout}",
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_reads_listen_alpha_from_config() {
    let dir = tmpdir("config-listen");
    let yaml = dir.join("server.yaml");
    // 138.197.x.x = DigitalOcean → WARN, exit 0.
    std::fs::write(
        &yaml,
        "listen_alpha: \"138.197.99.99:8443\"\n\
         keys:\n  \
             mlkem_pk: ./k.pk\n  \
             mlkem_sk: ./k.sk\n  \
             x25519_pk: ./x.pk\n  \
             x25519_sk: ./x.sk\n",
    )
    .unwrap();

    let bin = env!("CARGO_BIN_EXE_proteus-server");
    let output = Command::new(bin)
        .args(["preflight", "check-ip-reputation", "--config"])
        .arg(&yaml)
        .output()
        .expect("spawn preflight");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "WARN from cloud match must not fail; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("config listen_alpha") && stdout.contains("DigitalOcean"),
        "stdout:\n{stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_wildcard_bind_needs_explicit_public_ip() {
    let dir = tmpdir("wildcard");
    let yaml = dir.join("server.yaml");
    std::fs::write(
        &yaml,
        "listen_alpha: \"0.0.0.0:8443\"\n\
         keys:\n  \
             mlkem_pk: ./k.pk\n  \
             mlkem_sk: ./k.sk\n  \
             x25519_pk: ./x.pk\n  \
             x25519_sk: ./x.sk\n",
    )
    .unwrap();

    let bin = env!("CARGO_BIN_EXE_proteus-server");
    let output = Command::new(bin)
        .args(["preflight", "check-ip-reputation", "--config"])
        .arg(&yaml)
        .output()
        .expect("spawn preflight");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!output.status.success(), "stdout:\n{stdout}");
    assert!(
        stdout.contains("wildcard") && stdout.contains("--public-ip"),
        "must point operator at --public-ip; stdout:\n{stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
