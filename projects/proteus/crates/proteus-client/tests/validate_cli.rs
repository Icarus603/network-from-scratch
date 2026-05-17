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

// ---------- Bootstrap-DNS posture coverage ----------
//
// These tests pin the validate-time guidance for the 2026 P0
// item: when the operator leaves `server_endpoint` as a hostname
// + uses the OS resolver, validate MUST surface a WARN pointing
// at `bootstrap_dns: direct_ip`. When the operator picks the
// production-recommended path (literal IP OR pinned direct_ip),
// validate MUST report PASS without warning.
//
// Regression target: a future refactor that silently drops the
// bootstrap-DNS section from validate.rs would let operators
// deploy a DoH-vulnerable client without any deploy-time signal.

fn write_minimal_green_yaml(dir: &std::path::Path, extra: &str) -> PathBuf {
    let mlkem_pk = write_mlkem_pk(dir, "server.mlkem.pk");
    let x25519_pk = write_32b_key(dir, "server.x25519.pk");
    let fp = write_32b_key(dir, "server.fp");
    let ed_sk = write_32b_key(dir, "client.ed25519.sk");

    let yaml = dir.join("client.yaml");
    std::fs::write(
        &yaml,
        format!(
            "{extra}\
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
    yaml
}

/// Operator config with a HOSTNAME endpoint and no bootstrap_dns
/// override — the dangerous default. validate MUST surface a WARN
/// pointing at `bootstrap_dns: direct_ip`.
#[tokio::test]
async fn bootstrap_dns_hostname_with_system_resolver_warns() {
    let dir = tempdir("bootstrap_hostname_system");
    let yaml = write_minimal_green_yaml(&dir, "server_endpoint: \"vps.example.com:8443\"\n");

    let report = validate::run(&yaml).await;
    eprintln!("hostname+system report:\n{report}");
    assert!(
        !report.has_failures(),
        "this config has no FAIL — only a WARN about bootstrap_dns; report: {report}"
    );
    let bootstrap_warn = report.checks.iter().any(|c| match c {
        validate::Check::Warn(s) => {
            s.contains("server_endpoint") && s.contains("OS resolver") && s.contains("direct_ip")
        }
        _ => false,
    });
    assert!(
        bootstrap_warn,
        "validate MUST WARN about hostname+system-resolver bootstrap (2026 GFW DoH \
         identification, threat-intel main line 6); report: {report}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Operator config with a LITERAL IPv4 in server_endpoint. validate
/// MUST report PASS for the bootstrap row, NOT a WARN — this is the
/// production-recommended posture for a clean personal VPS.
#[tokio::test]
async fn bootstrap_dns_ip_literal_endpoint_passes() {
    let dir = tempdir("bootstrap_ip_literal");
    let yaml = write_minimal_green_yaml(&dir, "server_endpoint: \"198.51.100.42:8443\"\n");

    let report = validate::run(&yaml).await;
    eprintln!("ip-literal report:\n{report}");
    assert!(!report.has_failures());
    let bootstrap_pass = report.checks.iter().any(|c| match c {
        validate::Check::Pass(s) => {
            s.contains("server_endpoint") && s.contains("IP literal") && s.contains("DNS skipped")
        }
        _ => false,
    });
    assert!(
        bootstrap_pass,
        "validate MUST PASS the bootstrap row when server_endpoint is an IP literal; \
         report: {report}"
    );
    let bootstrap_warn = report.checks.iter().any(|c| match c {
        validate::Check::Warn(s) => s.contains("OS resolver"),
        _ => false,
    });
    assert!(
        !bootstrap_warn,
        "validate MUST NOT warn about OS resolver when the endpoint is an IP literal; \
         report: {report}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Operator config with a HOSTNAME endpoint + `bootstrap_dns:
/// direct_ip: <ipv4>`. validate MUST report PASS for the bootstrap
/// row indicating the hostname is pinned, NOT a WARN.
#[tokio::test]
async fn bootstrap_dns_hostname_with_direct_ip_passes() {
    let dir = tempdir("bootstrap_pinned");
    let yaml = write_minimal_green_yaml(
        &dir,
        "server_endpoint: \"vps.example.com:8443\"\n\
         bootstrap_dns:\n  direct_ip: 198.51.100.42\n",
    );

    let report = validate::run(&yaml).await;
    eprintln!("pinned report:\n{report}");
    assert!(!report.has_failures(), "report: {report}");
    let pinned_pass = report.checks.iter().any(|c| match c {
        validate::Check::Pass(s) => s.contains("pinned via bootstrap_dns.direct_ip"),
        _ => false,
    });
    assert!(
        pinned_pass,
        "validate MUST PASS+acknowledge the direct_ip pin; report: {report}"
    );
    let bootstrap_warn = report.checks.iter().any(|c| match c {
        validate::Check::Warn(s) => s.contains("OS resolver"),
        _ => false,
    });
    assert!(
        !bootstrap_warn,
        "validate MUST NOT warn about OS resolver when bootstrap_dns.direct_ip is set; \
         report: {report}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// β endpoint set as hostname under system resolver MUST also warn
/// (separate row from α). Regression: if a future refactor only walks
/// `server_endpoint` and forgets `server_endpoint_beta`, the β
/// carrier silently regains a DoH-identification window.
#[tokio::test]
async fn bootstrap_dns_beta_hostname_under_system_warns_independently() {
    let dir = tempdir("bootstrap_beta_hostname");
    // α endpoint already pinned (PASS), β still hostname (WARN).
    let yaml = write_minimal_green_yaml(
        &dir,
        "server_endpoint: \"198.51.100.42:8443\"\n\
         server_endpoint_beta: \"vps.example.com:8443\"\n",
    );

    let report = validate::run(&yaml).await;
    eprintln!("beta hostname+system report:\n{report}");
    assert!(!report.has_failures(), "report: {report}");
    let beta_warn = report.checks.iter().any(|c| match c {
        validate::Check::Warn(s) => {
            s.contains("server_endpoint_beta")
                && s.contains("OS resolver")
                && s.contains("direct_ip")
        }
        _ => false,
    });
    assert!(
        beta_warn,
        "validate MUST emit an INDEPENDENT WARN for server_endpoint_beta when α is \
         already pinned but β is still hostname+system-resolver; report: {report}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
