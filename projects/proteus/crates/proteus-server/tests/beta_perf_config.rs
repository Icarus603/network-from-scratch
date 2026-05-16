//! Round-trip test for the β QUIC perf-tunable YAML knobs added in
//! the production-config exposure commit:
//!
//!   - beta_initial_mtu: Option<u16>
//!   - beta_pad_quic_to_mtu: Option<bool>
//!
//! These fields gate access to `PerfProfile::pad_quic_datagrams_to_mtu`
//! and `initial_mtu` without recompiling the binary. Without YAML
//! exposure (the prior state), operators could not enable UDP-layer
//! padding even though the underlying β crate supported it.
//!
//! This test loads a YAML doc containing both new fields and asserts:
//!   1. serde_yaml parses them into the right types.
//!   2. The values land in the parsed ServerConfig fields.
//!   3. Defaults are `None` when fields are absent.

use proteus_server::config::ServerConfig;

#[tokio::test]
async fn yaml_round_trips_beta_perf_fields_when_set() {
    // tmpfs YAML with all the β-perf knobs at non-default values.
    let dir = tempfile_in_target("round_trips");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Touch the key files so the loader doesn't reject them in
    // future strict-validation modes.
    for name in ["mlkem.pk", "mlkem.sk", "x25519.pk", "x25519.sk"] {
        std::fs::write(dir.join(name), b"placeholder").unwrap();
    }
    let yaml_path = dir.join("server.yaml");
    std::fs::write(
        &yaml_path,
        format!(
            "listen_alpha: \"127.0.0.1:0\"\n\
             listen_beta: \"127.0.0.1:0\"\n\
             beta_initial_mtu: 1452\n\
             beta_pad_quic_to_mtu: true\n\
             keys:\n  \
                 mlkem_pk: {dir}/mlkem.pk\n  \
                 mlkem_sk: {dir}/mlkem.sk\n  \
                 x25519_pk: {dir}/x25519.pk\n  \
                 x25519_sk: {dir}/x25519.sk\n",
            dir = dir.display(),
        ),
    )
    .unwrap();

    let cfg = ServerConfig::load(&yaml_path).await.expect("load");
    assert_eq!(cfg.beta_initial_mtu, Some(1452));
    assert_eq!(cfg.beta_pad_quic_to_mtu, Some(true));

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn yaml_defaults_beta_perf_fields_to_none_when_absent() {
    let dir = tempfile_in_target("defaults_none");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    for name in ["mlkem.pk", "mlkem.sk", "x25519.pk", "x25519.sk"] {
        std::fs::write(dir.join(name), b"placeholder").unwrap();
    }
    let yaml_path = dir.join("server.yaml");
    std::fs::write(
        &yaml_path,
        format!(
            "listen_alpha: \"127.0.0.1:0\"\n\
             keys:\n  \
                 mlkem_pk: {dir}/mlkem.pk\n  \
                 mlkem_sk: {dir}/mlkem.sk\n  \
                 x25519_pk: {dir}/x25519.pk\n  \
                 x25519_sk: {dir}/x25519.sk\n",
            dir = dir.display(),
        ),
    )
    .unwrap();

    let cfg = ServerConfig::load(&yaml_path).await.expect("load");
    assert_eq!(cfg.beta_initial_mtu, None);
    assert_eq!(cfg.beta_pad_quic_to_mtu, None);

    let _ = std::fs::remove_dir_all(&dir);
}

fn tempfile_in_target(suffix: &str) -> std::path::PathBuf {
    // Per-test suffix is REQUIRED — without it, two tests in this file
    // racing to UNIX_EPOCH within the same nanosecond pick the same
    // tempdir and one trashes the other's YAML mid-flight. We saw this
    // flake locally: `assertion left == right failed` with `left: None`
    // intermittently. Adding the test name to the path eliminates the
    // collision.
    let dir = std::env::var("CARGO_TARGET_TMPDIR").unwrap_or_else(|_| "/tmp".to_string());
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::path::PathBuf::from(format!("{dir}/proteus-beta-perf-{suffix}-{pid}-{nanos}"))
}
