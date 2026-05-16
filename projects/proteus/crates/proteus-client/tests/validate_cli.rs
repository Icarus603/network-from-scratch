//! End-to-end coverage for `proteus-client validate <path>`.
//!
//! Companion to the server-side `validate_cli` test. Critical
//! property: a green YAML (parses + all key files the right size)
//! exits 0; a YAML with any FAIL exits 1; the report's PASS/WARN/
//! FAIL counts match the expected shape.
//!
//! These tests rely on the library API (`proteus_client::validate::run`)
//! so they don't need the `proteus-client` binary to be on PATH.

use std::path::PathBuf;

use proteus_client::validate;

fn tempdir(suffix: &str) -> PathBuf {
    let dir = std::env::var("CARGO_TARGET_TMPDIR").unwrap_or_else(|_| "/tmp".to_string());
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let p = PathBuf::from(format!(
        "{dir}/proteus-client-validate-{suffix}-{pid}-{nanos}"
    ));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn write_32b_key(dir: &std::path::Path, name: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, [0u8; 32]).unwrap();
    p
}

fn write_mlkem_pk(dir: &std::path::Path, name: &str) -> PathBuf {
    // ML-KEM-768 EK is 1184 bytes — well above the ≥32 sanity threshold.
    let p = dir.join(name);
    std::fs::write(&p, vec![0u8; 1184]).unwrap();
    p
}

#[tokio::test]
async fn green_yaml_validates_with_zero_failures() {
    let dir = tempdir("green");
    let mlkem_pk = write_mlkem_pk(&dir, "server.mlkem.pk");
    let x25519_pk = write_32b_key(&dir, "server.x25519.pk");
    let fp = write_32b_key(&dir, "server.fp");
    let ed_sk = write_32b_key(&dir, "client.ed25519.sk");

    let yaml = dir.join("client.yaml");
    std::fs::write(
        &yaml,
        format!(
            "server_endpoint: \"vps.example.com:8443\"\n\
             socks_listen: \"127.0.0.1:1080\"\n\
             user_id: \"alice001\"\n\
             tls:\n  server_name: vps.example.com\n\
             keys:\n  \
                 server_mlkem_pk: {mlkem}\n  \
                 server_x25519_pk: {x25519}\n  \
                 server_pq_fingerprint: {fp}\n  \
                 client_ed25519_sk: {ed}\n",
            mlkem = mlkem_pk.display(),
            x25519 = x25519_pk.display(),
            fp = fp.display(),
            ed = ed_sk.display(),
        ),
    )
    .unwrap();

    let report = validate::run(&yaml).await;
    let (p, _w, f) = report.counts();
    eprintln!("green yaml report:\n{report}");
    assert_eq!(f, 0, "expected zero FAIL; got {f}: {report}");
    assert!(p >= 8, "expected many PASS; got {p}");
    assert!(!report.has_failures());

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn missing_key_file_fires_fail() {
    let dir = tempdir("missing_key");
    let mlkem_pk = write_mlkem_pk(&dir, "server.mlkem.pk");
    let x25519_pk = write_32b_key(&dir, "server.x25519.pk");
    let fp = write_32b_key(&dir, "server.fp");
    // Deliberately DON'T create client_ed25519_sk.

    let yaml = dir.join("client.yaml");
    std::fs::write(
        &yaml,
        format!(
            "server_endpoint: \"vps.example.com:8443\"\n\
             socks_listen: \"127.0.0.1:1080\"\n\
             user_id: \"alice001\"\n\
             tls:\n  server_name: vps.example.com\n\
             keys:\n  \
                 server_mlkem_pk: {mlkem}\n  \
                 server_x25519_pk: {x25519}\n  \
                 server_pq_fingerprint: {fp}\n  \
                 client_ed25519_sk: {dir}/missing.ed25519.sk\n",
            mlkem = mlkem_pk.display(),
            x25519 = x25519_pk.display(),
            fp = fp.display(),
            dir = dir.display(),
        ),
    )
    .unwrap();

    let report = validate::run(&yaml).await;
    eprintln!("missing-key report:\n{report}");
    assert!(report.has_failures(), "missing key file MUST fire FAIL");

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn wrong_size_x25519_pk_fires_fail() {
    let dir = tempdir("bad_x25519");
    let mlkem_pk = write_mlkem_pk(&dir, "server.mlkem.pk");
    let fp = write_32b_key(&dir, "server.fp");
    let ed_sk = write_32b_key(&dir, "client.ed25519.sk");
    // 31 bytes — one short.
    let x25519_pk = dir.join("server.x25519.pk");
    std::fs::write(&x25519_pk, [0u8; 31]).unwrap();

    let yaml = dir.join("client.yaml");
    std::fs::write(
        &yaml,
        format!(
            "server_endpoint: \"vps.example.com:8443\"\n\
             socks_listen: \"127.0.0.1:1080\"\n\
             user_id: \"alice001\"\n\
             tls:\n  server_name: vps.example.com\n\
             keys:\n  \
                 server_mlkem_pk: {mlkem}\n  \
                 server_x25519_pk: {x25519}\n  \
                 server_pq_fingerprint: {fp}\n  \
                 client_ed25519_sk: {ed}\n",
            mlkem = mlkem_pk.display(),
            x25519 = x25519_pk.display(),
            fp = fp.display(),
            ed = ed_sk.display(),
        ),
    )
    .unwrap();

    let report = validate::run(&yaml).await;
    eprintln!("bad-x25519 report:\n{report}");
    assert!(report.has_failures());
    let any_complains_x25519 = report.checks.iter().any(|c| match c {
        validate::Check::Fail(s) => s.contains("server_x25519_pk"),
        _ => false,
    });
    assert!(
        any_complains_x25519,
        "FAIL message should mention server_x25519_pk"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn user_id_too_long_fires_fail() {
    let dir = tempdir("long_user_id");
    let mlkem_pk = write_mlkem_pk(&dir, "server.mlkem.pk");
    let x25519_pk = write_32b_key(&dir, "server.x25519.pk");
    let fp = write_32b_key(&dir, "server.fp");
    let ed_sk = write_32b_key(&dir, "client.ed25519.sk");

    let yaml = dir.join("client.yaml");
    // "alice_does_not_fit" is 18 bytes > 8 cap.
    std::fs::write(
        &yaml,
        format!(
            "server_endpoint: \"vps.example.com:8443\"\n\
             socks_listen: \"127.0.0.1:1080\"\n\
             user_id: \"alice_does_not_fit\"\n\
             tls:\n  server_name: vps.example.com\n\
             keys:\n  \
                 server_mlkem_pk: {mlkem}\n  \
                 server_x25519_pk: {x25519}\n  \
                 server_pq_fingerprint: {fp}\n  \
                 client_ed25519_sk: {ed}\n",
            mlkem = mlkem_pk.display(),
            x25519 = x25519_pk.display(),
            fp = fp.display(),
            ed = ed_sk.display(),
        ),
    )
    .unwrap();

    let report = validate::run(&yaml).await;
    eprintln!("long-user_id report:\n{report}");
    assert!(report.has_failures());

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn beta_endpoint_without_sni_fires_fail() {
    let dir = tempdir("beta_no_sni");
    let mlkem_pk = write_mlkem_pk(&dir, "server.mlkem.pk");
    let x25519_pk = write_32b_key(&dir, "server.x25519.pk");
    let fp = write_32b_key(&dir, "server.fp");
    let ed_sk = write_32b_key(&dir, "client.ed25519.sk");

    let yaml = dir.join("client.yaml");
    // server_endpoint_beta set, but no tls.server_name or beta_server_name.
    std::fs::write(
        &yaml,
        format!(
            "server_endpoint: \"vps.example.com:8443\"\n\
             server_endpoint_beta: \"vps.example.com:8443\"\n\
             socks_listen: \"127.0.0.1:1080\"\n\
             user_id: \"alice001\"\n\
             keys:\n  \
                 server_mlkem_pk: {mlkem}\n  \
                 server_x25519_pk: {x25519}\n  \
                 server_pq_fingerprint: {fp}\n  \
                 client_ed25519_sk: {ed}\n",
            mlkem = mlkem_pk.display(),
            x25519 = x25519_pk.display(),
            fp = fp.display(),
            ed = ed_sk.display(),
        ),
    )
    .unwrap();

    let report = validate::run(&yaml).await;
    eprintln!("beta-no-sni report:\n{report}");
    assert!(report.has_failures());
    let sni_mentioned = report.checks.iter().any(|c| match c {
        validate::Check::Fail(s) => s.contains("SNI") || s.contains("server_name"),
        _ => false,
    });
    assert!(
        sni_mentioned,
        "FAIL should mention SNI / server_name when β is enabled without one"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn out_of_range_initial_mtu_fires_fail() {
    let dir = tempdir("bad_mtu");
    let mlkem_pk = write_mlkem_pk(&dir, "server.mlkem.pk");
    let x25519_pk = write_32b_key(&dir, "server.x25519.pk");
    let fp = write_32b_key(&dir, "server.fp");
    let ed_sk = write_32b_key(&dir, "client.ed25519.sk");

    let yaml = dir.join("client.yaml");
    std::fs::write(
        &yaml,
        format!(
            "server_endpoint: \"vps.example.com:8443\"\n\
             server_endpoint_beta: \"vps.example.com:8443\"\n\
             beta_initial_mtu: 9000\n\
             socks_listen: \"127.0.0.1:1080\"\n\
             user_id: \"alice001\"\n\
             tls:\n  server_name: vps.example.com\n\
             keys:\n  \
                 server_mlkem_pk: {mlkem}\n  \
                 server_x25519_pk: {x25519}\n  \
                 server_pq_fingerprint: {fp}\n  \
                 client_ed25519_sk: {ed}\n",
            mlkem = mlkem_pk.display(),
            x25519 = x25519_pk.display(),
            fp = fp.display(),
            ed = ed_sk.display(),
        ),
    )
    .unwrap();

    let report = validate::run(&yaml).await;
    eprintln!("bad-mtu report:\n{report}");
    assert!(report.has_failures());

    let _ = std::fs::remove_dir_all(&dir);
}
