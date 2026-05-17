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
    // Iter-48: random non-zero bytes. The validate-time all-zeros
    // sentinel check (FAIL on uniformly-zero keys) means we can no
    // longer use [0u8; 32] as a test fixture — every operator who
    // hand-wrote a placeholder would also trip it, but in fixtures
    // we want validate to pass.
    use rand_core::RngCore;
    let mut buf = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut buf);
    let p = dir.join(name);
    std::fs::write(&p, buf).unwrap();
    p
}

fn write_mlkem_pk(dir: &std::path::Path, name: &str) -> PathBuf {
    // ML-KEM-768 EK is 1184 bytes — well above the ≥32 sanity threshold.
    // Iter-48: random non-zero bytes (see write_32b_key rationale).
    use rand_core::RngCore;
    let mut buf = vec![0u8; 1184];
    rand_core::OsRng.fill_bytes(&mut buf);
    let p = dir.join(name);
    std::fs::write(&p, buf).unwrap();
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

// ---------- server_endpoints multi-VPS HA pool ----------

/// Pool of 3 entries with primary as entry[0] — the recommended
/// shape. Validate MUST PASS, no warnings about split-brain or
/// single-entry-pool or SNI divergence.
///
/// Iter-43 update: backup entries are IP literals (the recommended
/// production shape — operator decouples routing-address from
/// cert-identity). Pre-iter-43 the fixture used divergent
/// HOSTNAMES (`vps-backup.example.com`), which iter-43's new SNI
/// consistency check correctly flags as a misconfig (the
/// dispatcher uses `tls.server_name=vps.example.com` as SNI for
/// EVERY entry — divergent backup hostnames would all fail cert
/// verification at dispatch time).
#[tokio::test]
async fn server_endpoints_well_formed_pool_passes() {
    let dir = tempdir("endpoints_good");
    let yaml = write_minimal_green_yaml(
        &dir,
        "server_endpoint: \"vps.example.com:8443\"\n\
         server_endpoints:\n  \
             - \"vps.example.com:8443\"\n  \
             - \"198.51.100.10:8443\"\n  \
             - \"198.51.100.20:8443\"\n",
    );
    let report = validate::run(&yaml).await;
    eprintln!("good pool report:\n{report}");
    assert!(!report.has_failures(), "{report}");
    let pool_pass = report.checks.iter().any(|c| match c {
        validate::Check::Pass(s) => s.contains("server_endpoints pool") && s.contains("3 entries"),
        _ => false,
    });
    assert!(pool_pass, "PASS row for 3-entry pool missing: {report}");
    // No single-entry warn.
    let single_warn = report.checks.iter().any(|c| match c {
        validate::Check::Warn(s) => s.contains("only one entry"),
        _ => false,
    });
    assert!(!single_warn);
    // No split-brain warn (primary IS in the pool).
    let split_warn = report.checks.iter().any(|c| match c {
        validate::Check::Warn(s) => s.contains("split-brain"),
        _ => false,
    });
    assert!(!split_warn);
    // Iter-43: no SNI-divergence warn (IP literals are correctly
    // skipped; primary entry's hostname matches tls.server_name).
    let sni_warn = report.checks.iter().any(|c| match c {
        validate::Check::Warn(s) => s.contains("tls.server_name") && s.contains("don't match"),
        _ => false,
    });
    assert!(
        !sni_warn,
        "SNI-divergence warn must NOT fire when pool uses IP literals + matching primary hostname: {report}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Single-entry pool → WARN (equivalent to no pool at all,
/// operator probably meant more).
#[tokio::test]
async fn server_endpoints_single_entry_warns() {
    let dir = tempdir("endpoints_single");
    let yaml = write_minimal_green_yaml(
        &dir,
        "server_endpoint: \"vps.example.com:8443\"\n\
         server_endpoints:\n  - \"vps.example.com:8443\"\n",
    );
    let report = validate::run(&yaml).await;
    eprintln!("single-entry pool report:\n{report}");
    assert!(!report.has_failures(), "{report}");
    let single_warn = report.checks.iter().any(|c| match c {
        validate::Check::Warn(s) => s.contains("only one entry"),
        _ => false,
    });
    assert!(single_warn, "single-entry WARN missing: {report}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Primary not in the pool list → split-brain WARN.
#[tokio::test]
async fn server_endpoints_split_brain_warns() {
    let dir = tempdir("endpoints_split");
    let yaml = write_minimal_green_yaml(
        &dir,
        "server_endpoint: \"vps.example.com:8443\"\n\
         server_endpoints:\n  \
             - \"vps-backup.example.com:8443\"\n  \
             - \"vps-cn2.example.com:8443\"\n",
    );
    let report = validate::run(&yaml).await;
    eprintln!("split-brain pool report:\n{report}");
    assert!(!report.has_failures(), "{report}");
    let split_warn = report.checks.iter().any(|c| match c {
        validate::Check::Warn(s) => s.contains("split-brain"),
        _ => false,
    });
    assert!(split_warn, "split-brain WARN missing: {report}");
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------- iter-43: pool ↔ tls.server_name SNI consistency ----------

/// Operator-trap: a pool entry is a HOSTNAME that doesn't match
/// tls.server_name. The dispatcher uses tls.server_name as SNI
/// for cert verification regardless of which pool entry the
/// connection lands on — so every dial of the divergent entry
/// would fail at TLS verification with no obvious cause.
#[tokio::test]
async fn iter43_server_endpoints_hostname_diverging_from_sni_warns() {
    let dir = tempdir("endpoints_sni_diverging");
    let yaml = write_minimal_green_yaml(
        &dir,
        "server_endpoint: \"vps.example.com:8443\"\n\
         server_endpoints:\n  \
             - \"vps.example.com:8443\"\n  \
             - \"backup.different.example.com:8443\"\n",
    );
    let report = validate::run(&yaml).await;
    eprintln!("sni-diverging report:\n{report}");
    let sni_warn = report.checks.iter().any(|c| match c {
        validate::Check::Warn(s) => {
            s.contains("backup.different.example.com")
                && s.contains("tls.server_name")
                && s.contains("don't match")
        }
        _ => false,
    });
    assert!(
        sni_warn,
        "SNI-divergence WARN must fire for divergent hostname: {report}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// IP literals in the pool are CORRECTLY skipped by the
/// SNI-divergence check — the operator deliberately decoupled
/// routing-address from cert-identity, which is the recommended
/// production shape.
#[tokio::test]
async fn iter43_server_endpoints_ip_literals_do_not_trigger_sni_warn() {
    let dir = tempdir("endpoints_ip_literals");
    let yaml = write_minimal_green_yaml(
        &dir,
        "server_endpoint: \"vps.example.com:8443\"\n\
         server_endpoints:\n  \
             - \"vps.example.com:8443\"\n  \
             - \"198.51.100.42:8443\"\n  \
             - \"203.0.113.99:8443\"\n  \
             - \"2001:db8::1:8443\"\n",
    );
    let report = validate::run(&yaml).await;
    eprintln!("ip-literals report:\n{report}");
    let sni_warn = report.checks.iter().any(|c| match c {
        validate::Check::Warn(s) => s.contains("tls.server_name") && s.contains("don't match"),
        _ => false,
    });
    assert!(
        !sni_warn,
        "IP literal pool entries must NOT trigger SNI-divergence warn: {report}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Multiple divergent hostnames → the warn lists every offender,
/// not just the first one. Operators want one fix-cycle, not N.
#[tokio::test]
async fn iter43_server_endpoints_multiple_diverging_all_listed() {
    let dir = tempdir("endpoints_multi_diverging");
    let yaml = write_minimal_green_yaml(
        &dir,
        "server_endpoint: \"vps.example.com:8443\"\n\
         server_endpoints:\n  \
             - \"vps.example.com:8443\"\n  \
             - \"a.bad.example.com:8443\"\n  \
             - \"b.bad.example.com:8443\"\n  \
             - \"c.bad.example.com:8443\"\n",
    );
    let report = validate::run(&yaml).await;
    eprintln!("multi-diverging report:\n{report}");
    let warn_msg = report.checks.iter().find_map(|c| match c {
        validate::Check::Warn(s) if s.contains("don't match") => Some(s.clone()),
        _ => None,
    });
    let msg = warn_msg.expect("SNI-divergence warn must fire");
    for needle in ["a.bad.example.com", "b.bad.example.com", "c.bad.example.com"] {
        assert!(
            msg.contains(needle),
            "all 3 divergent hostnames must be listed; missing {needle:?} in:\n{msg}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Hostname matches SNI case-insensitively → no warn. Operators
/// who type `VPS.Example.Com` should NOT see false-positives.
#[tokio::test]
async fn iter43_server_endpoints_case_insensitive_hostname_no_warn() {
    let dir = tempdir("endpoints_case_insensitive");
    let yaml = write_minimal_green_yaml(
        &dir,
        "server_endpoint: \"vps.example.com:8443\"\n\
         server_endpoints:\n  \
             - \"VPS.Example.COM:8443\"\n  \
             - \"vps.example.com:8443\"\n",
    );
    let report = validate::run(&yaml).await;
    eprintln!("case-insensitive report:\n{report}");
    let sni_warn = report.checks.iter().any(|c| match c {
        validate::Check::Warn(s) => s.contains("tls.server_name") && s.contains("don't match"),
        _ => false,
    });
    assert!(
        !sni_warn,
        "case-insensitive hostname match must NOT trigger SNI warn: {report}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------- iter-56: user_id whitespace + non-ASCII checks ----------

/// Operator-trap: YAML quoted user_id with trailing whitespace.
/// `user_id: "alice "` becomes the 6-byte string "alice "; the
/// server allowlist (no space) never matches and every dial
/// fails with no obvious cause.
#[tokio::test]
async fn iter56_user_id_with_trailing_whitespace_fails() {
    let dir = tempdir("user-id-ws");
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
             user_id: \"alice \"\n\
             keys:\n  \
                 server_mlkem_pk: {}\n  \
                 server_x25519_pk: {}\n  \
                 server_pq_fingerprint: {}\n  \
                 client_ed25519_sk: {}\n",
            mlkem_pk.display(),
            x25519_pk.display(),
            fp.display(),
            ed_sk.display(),
        ),
    )
    .unwrap();
    let report = validate::run(&yaml).await;
    eprintln!("trailing-ws report:\n{report}");
    let ws_fail = report.checks.iter().any(|c| match c {
        validate::Check::Fail(s) => {
            s.contains("user_id") && s.contains("whitespace")
        }
        _ => false,
    });
    assert!(
        ws_fail,
        "trailing-whitespace user_id MUST FAIL with whitespace diagnostic: {report}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn iter56_user_id_with_leading_whitespace_fails() {
    let dir = tempdir("user-id-leading-ws");
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
             user_id: \" bob\"\n\
             keys:\n  \
                 server_mlkem_pk: {}\n  \
                 server_x25519_pk: {}\n  \
                 server_pq_fingerprint: {}\n  \
                 client_ed25519_sk: {}\n",
            mlkem_pk.display(),
            x25519_pk.display(),
            fp.display(),
            ed_sk.display(),
        ),
    )
    .unwrap();
    let report = validate::run(&yaml).await;
    let ws_fail = report.checks.iter().any(|c| match c {
        validate::Check::Fail(s) => s.contains("user_id") && s.contains("whitespace"),
        _ => false,
    });
    assert!(ws_fail, "leading-whitespace MUST FAIL: {report}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Iter-56: non-ASCII user_id → WARN (not FAIL). Operators
/// who deliberately use Unicode IDs get the paste-not-retype
/// reminder; operators who didn't mean to see "fix this".
#[tokio::test]
async fn iter56_user_id_with_non_ascii_warns_not_fails() {
    let dir = tempdir("user-id-unicode");
    let mlkem_pk = write_mlkem_pk(&dir, "server.mlkem.pk");
    let x25519_pk = write_32b_key(&dir, "server.x25519.pk");
    let fp = write_32b_key(&dir, "server.fp");
    let ed_sk = write_32b_key(&dir, "client.ed25519.sk");
    let yaml = dir.join("client.yaml");
    // "アリ" is 6 UTF-8 bytes — fits the 8-byte budget AND is non-ASCII.
    std::fs::write(
        &yaml,
        format!(
            "server_endpoint: \"vps.example.com:8443\"\n\
             socks_listen: \"127.0.0.1:1080\"\n\
             user_id: \"アリ\"\n\
             keys:\n  \
                 server_mlkem_pk: {}\n  \
                 server_x25519_pk: {}\n  \
                 server_pq_fingerprint: {}\n  \
                 client_ed25519_sk: {}\n",
            mlkem_pk.display(),
            x25519_pk.display(),
            fp.display(),
            ed_sk.display(),
        ),
    )
    .unwrap();
    let report = validate::run(&yaml).await;
    eprintln!("unicode-id report:\n{report}");
    let warn = report.checks.iter().any(|c| match c {
        validate::Check::Warn(s) => s.contains("user_id") && s.contains("non-ASCII"),
        _ => false,
    });
    assert!(warn, "non-ASCII user_id must WARN: {report}");
    assert!(
        !report.has_failures(),
        "non-ASCII must NOT escalate to FAIL: {report}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------- iter-48: all-zero key sentinel check ----------

/// Helper: write an all-zero key file (placeholder / corrupted /
/// dd-from-/dev/zero scenario).
fn write_32b_zero_key(dir: &std::path::Path, name: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, [0u8; 32]).unwrap();
    p
}

/// An all-zero secret key is a catastrophic security failure
/// (trivially-forgeable identity). Validate MUST FAIL.
#[tokio::test]
async fn iter48_all_zero_client_sk_fails_validate() {
    let dir = tempdir("zero-sk");
    let mlkem_pk = write_mlkem_pk(&dir, "server.mlkem.pk");
    let x25519_pk = write_32b_key(&dir, "server.x25519.pk");
    let fp = write_32b_key(&dir, "server.fp");
    // The secret key is all zeros — placeholder forgotten / script crashed.
    let ed_sk = write_32b_zero_key(&dir, "client.ed25519.sk");

    let yaml = dir.join("client.yaml");
    std::fs::write(
        &yaml,
        format!(
            "server_endpoint: \"vps.example.com:8443\"\n\
             socks_listen: \"127.0.0.1:1080\"\n\
             user_id: \"alice\"\n\
             keys:\n  \
                 server_mlkem_pk: {}\n  \
                 server_x25519_pk: {}\n  \
                 server_pq_fingerprint: {}\n  \
                 client_ed25519_sk: {}\n",
            mlkem_pk.display(),
            x25519_pk.display(),
            fp.display(),
            ed_sk.display(),
        ),
    )
    .unwrap();
    let report = validate::run(&yaml).await;
    eprintln!("all-zero-sk report:\n{report}");
    assert!(
        report.has_failures(),
        "all-zero secret key MUST FAIL validate: {report}"
    );
    let zero_fail = report.checks.iter().any(|c| match c {
        validate::Check::Fail(s) => {
            s.contains("client_ed25519_sk") && s.contains("ALL-ZERO")
        }
        _ => false,
    });
    assert!(
        zero_fail,
        "FAIL row must specifically call out ALL-ZERO + the affected key: {report}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// All-zero PUBLIC keys are also FAIL — every handshake would
/// verify against an attacker-controlled trivial key.
#[tokio::test]
async fn iter48_all_zero_server_x25519_pk_fails_validate() {
    let dir = tempdir("zero-x25519");
    let mlkem_pk = write_mlkem_pk(&dir, "server.mlkem.pk");
    let x25519_pk = write_32b_zero_key(&dir, "server.x25519.pk"); // zero
    let fp = write_32b_key(&dir, "server.fp");
    let ed_sk = write_32b_key(&dir, "client.ed25519.sk");

    let yaml = dir.join("client.yaml");
    std::fs::write(
        &yaml,
        format!(
            "server_endpoint: \"vps.example.com:8443\"\n\
             socks_listen: \"127.0.0.1:1080\"\n\
             user_id: \"alice\"\n\
             keys:\n  \
                 server_mlkem_pk: {}\n  \
                 server_x25519_pk: {}\n  \
                 server_pq_fingerprint: {}\n  \
                 client_ed25519_sk: {}\n",
            mlkem_pk.display(),
            x25519_pk.display(),
            fp.display(),
            ed_sk.display(),
        ),
    )
    .unwrap();
    let report = validate::run(&yaml).await;
    eprintln!("zero-x25519 report:\n{report}");
    assert!(report.has_failures(), "{report}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Base64-encoded all-zero key is ALSO detected (the validator
/// decodes base64 before the zero check). Pre-iter-48 this would
/// have slipped through either way; post-iter-48 both forms are
/// caught.
#[tokio::test]
async fn iter48_base64_encoded_all_zero_key_fails_validate() {
    use base64::Engine;
    let dir = tempdir("zero-base64");
    let zeros = [0u8; 32];
    let b64 = base64::engine::general_purpose::STANDARD.encode(zeros);
    let sk_path = dir.join("client.ed25519.sk");
    std::fs::write(&sk_path, format!("{b64}\n")).unwrap();

    let mlkem_pk = write_mlkem_pk(&dir, "server.mlkem.pk");
    let x25519_pk = write_32b_key(&dir, "server.x25519.pk");
    let fp = write_32b_key(&dir, "server.fp");
    let yaml = dir.join("client.yaml");
    std::fs::write(
        &yaml,
        format!(
            "server_endpoint: \"vps.example.com:8443\"\n\
             socks_listen: \"127.0.0.1:1080\"\n\
             user_id: \"alice\"\n\
             keys:\n  \
                 server_mlkem_pk: {}\n  \
                 server_x25519_pk: {}\n  \
                 server_pq_fingerprint: {}\n  \
                 client_ed25519_sk: {}\n",
            mlkem_pk.display(),
            x25519_pk.display(),
            fp.display(),
            sk_path.display(),
        ),
    )
    .unwrap();
    let report = validate::run(&yaml).await;
    eprintln!("base64-zero report:\n{report}");
    let zero_fail = report.checks.iter().any(|c| match c {
        validate::Check::Fail(s) => s.contains("ALL-ZERO"),
        _ => false,
    });
    assert!(
        zero_fail,
        "base64-encoded all-zero key MUST be detected after decode: {report}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Bad host:port in pool → FAIL.
#[tokio::test]
async fn server_endpoints_bad_entry_fails() {
    let dir = tempdir("endpoints_bad");
    let yaml = write_minimal_green_yaml(
        &dir,
        "server_endpoint: \"vps.example.com:8443\"\n\
         server_endpoints:\n  \
             - \"vps.example.com:8443\"\n  \
             - \"this-is-not-a-valid-endpoint\"\n  \
             - \"vps-cn2.example.com:8443\"\n",
    );
    let report = validate::run(&yaml).await;
    eprintln!("bad-entry pool report:\n{report}");
    assert!(report.has_failures(), "{report}");
    let bad_fail = report.checks.iter().any(|c| match c {
        validate::Check::Fail(s) => {
            s.contains("server_endpoints has bad host:port") && s.contains("[1]")
        }
        _ => false,
    });
    assert!(bad_fail, "FAIL row for bad entry missing: {report}");
    let _ = std::fs::remove_dir_all(&dir);
}
