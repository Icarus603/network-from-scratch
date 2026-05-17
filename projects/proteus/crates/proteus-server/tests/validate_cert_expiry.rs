//! Iter-46: `proteus-server validate` cert-expiry coverage.
//!
//! The runtime surfaces `proteus_tls_cert_not_after_unix_seconds`
//! and the bundled Prometheus alerts
//! `ProteusTlsCertExpired` / `ProteusTlsCertExpiringSoon` flag
//! expired-or-close-to-expired leaf certs. But those signals only
//! fire AFTER the binary starts. Operators running `validate` on a
//! fresh deploy (or in CI before a config push) deserved the same
//! warning BEFORE the cert reached production.
//!
//! Pre-iter-46 `validate` only confirmed the chain parses (`rustls`
//! does NOT reject expired certs at load time — it just makes the
//! handshake fail at use-time). An operator could put an
//! already-expired cert in `tls.cert_chain`, run `validate`, see
//! green output, deploy it, and watch every TLS handshake fail
//! with no obvious trace back to the cert.
//!
//! This file pins the three new branches:
//!   - EXPIRED leaf → FAIL
//!   - <14 days left → WARN
//!   - ≥14 days left → PASS with days-remaining
//!
//! We use rcgen to mint certs with deterministic notAfter values
//! controlled by the test (time::OffsetDateTime arithmetic).

use std::path::PathBuf;
use std::time::SystemTime;

use proteus_server::config::ServerConfig;
use proteus_server::validate::{self, Check};

fn tmpdir(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "proteus-validate-cert-{}-{}-{:?}-{}",
        std::process::id(),
        SystemTime::now()
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

/// Mint a self-signed cert + PKCS8 key whose validity window is
/// `[now - 30d, not_after)`. Writes them as `cert.pem` + `key.pem`
/// inside `dir` and returns the paths.
fn mint_cert_with_not_after(dir: &std::path::Path, not_after: time::OffsetDateTime) -> (PathBuf, PathBuf) {
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "localhost");
    params.subject_alt_names = vec![rcgen::SanType::DnsName(
        rcgen::Ia5String::try_from("localhost").unwrap(),
    )];
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(30);
    params.not_after = not_after;
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key_pair).unwrap();

    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key_pair.serialize_pem()).unwrap();
    (cert_path, key_path)
}

/// Write a minimum-shape server.yaml that points at the supplied
/// cert + key paths. The other fields are tied to placeholder
/// touched files because validate doesn't care about their content
/// for the cert-expiry check (any FAIL on those is on a different
/// rule).
fn write_yaml(dir: &std::path::Path, cert: &std::path::Path, key: &std::path::Path) -> PathBuf {
    let mlkem_pk = touch(dir, "mlkem.pk");
    let mlkem_sk = touch(dir, "mlkem.sk");
    let x25519_pk = touch(dir, "x25519.pk");
    let x25519_sk = touch(dir, "x25519.sk");
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
tls:
  cert_chain: {}
  private_key: {}
"#,
            mlkem_pk.display(),
            mlkem_sk.display(),
            x25519_pk.display(),
            x25519_sk.display(),
            cert.display(),
            key.display(),
        ),
    )
    .unwrap();
    yaml
}

#[tokio::test]
async fn iter46_expired_leaf_cert_fails_validate() {
    let dir = tmpdir("expired");
    // notAfter = 7 days ago. Cert is firmly expired.
    let not_after = time::OffsetDateTime::now_utc() - time::Duration::days(7);
    let (cert, key) = mint_cert_with_not_after(&dir, not_after);
    let yaml = write_yaml(&dir, &cert, &key);

    let cfg = ServerConfig::load(&yaml).await.expect("config loads");
    let report = validate::preflight(&cfg);
    eprintln!("expired-cert report:\n{report}");

    // The cert-expiry FAIL must fire.
    let expired_fail = report.checks.iter().any(|c| match c {
        Check::Fail(s) => s.contains("EXPIRED") && s.contains("tls.cert_chain"),
        _ => false,
    });
    assert!(
        expired_fail,
        "expired cert MUST produce a FAIL row mentioning EXPIRED: {report}"
    );
    assert!(report.has_failures());
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn iter46_cert_in_renewal_window_warns() {
    let dir = tmpdir("renewal-window");
    // notAfter = 7 days from now. Within the 14-day window.
    let not_after = time::OffsetDateTime::now_utc() + time::Duration::days(7);
    let (cert, key) = mint_cert_with_not_after(&dir, not_after);
    let yaml = write_yaml(&dir, &cert, &key);

    let cfg = ServerConfig::load(&yaml).await.expect("config loads");
    let report = validate::preflight(&cfg);
    eprintln!("renewal-window report:\n{report}");

    let warn = report.checks.iter().any(|c| match c {
        Check::Warn(s) => s.contains("expires in") && s.contains("day"),
        _ => false,
    });
    assert!(
        warn,
        "cert with <14 days left MUST produce a WARN row: {report}"
    );
    // WARN is not a FAIL — overall exit stays 0.
    assert!(
        !report.has_failures(),
        "renewal-window WARN must not escalate to FAIL: {report}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Iter-49: β cert path (independent of α) is checked for expiry
/// when set. Symmetric with iter-46 α check. Operators who run
/// dual-stack with a SEPARATE β cert (e.g., HTTPS for α, QUIC
/// for β with different CAs) get expiry surveillance on both.
#[tokio::test]
async fn iter49_beta_cert_expired_fails_validate() {
    let dir = tmpdir("beta-expired");
    // Fresh α cert (so the α check passes) and an EXPIRED β cert.
    let alpha_not_after = time::OffsetDateTime::now_utc() + time::Duration::days(180);
    let beta_not_after = time::OffsetDateTime::now_utc() - time::Duration::days(2);
    let (alpha_cert, alpha_key) = mint_cert_with_not_after(&dir, alpha_not_after);
    // Mint β separately in a sub-dir so paths are distinct.
    let beta_dir = dir.join("beta");
    std::fs::create_dir_all(&beta_dir).unwrap();
    let (beta_cert, beta_key) = mint_cert_with_not_after(&beta_dir, beta_not_after);
    // Touch the key placeholders.
    let mlkem_pk = touch(&dir, "mlkem.pk");
    let mlkem_sk = touch(&dir, "mlkem.sk");
    let x25519_pk = touch(&dir, "x25519.pk");
    let x25519_sk = touch(&dir, "x25519.sk");

    let yaml = dir.join("server.yaml");
    std::fs::write(
        &yaml,
        format!(
            r#"listen_alpha: "0.0.0.0:8443"
listen_beta: "0.0.0.0:8443"
beta_cert_chain: {}
beta_private_key: {}
keys:
  mlkem_pk: {}
  mlkem_sk: {}
  x25519_pk: {}
  x25519_sk: {}
tls:
  cert_chain: {}
  private_key: {}
"#,
            beta_cert.display(),
            beta_key.display(),
            mlkem_pk.display(),
            mlkem_sk.display(),
            x25519_pk.display(),
            x25519_sk.display(),
            alpha_cert.display(),
            alpha_key.display(),
        ),
    )
    .unwrap();
    let cfg = ServerConfig::load(&yaml).await.expect("config loads");
    let report = validate::preflight(&cfg);
    eprintln!("beta-expired report:\n{report}");

    let beta_fail = report.checks.iter().any(|c| match c {
        Check::Fail(s) => s.contains("β cert") && s.contains("EXPIRED"),
        _ => false,
    });
    assert!(
        beta_fail,
        "expired β cert MUST FAIL validate independently of α: {report}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Iter-49: when β shares the α tls path (no separate
/// beta_cert_chain), the β check is suppressed to avoid
/// duplicate FAIL/WARN noise. The α check already covers the
/// shared file.
#[tokio::test]
async fn iter49_beta_using_shared_alpha_tls_does_not_emit_duplicate() {
    let dir = tmpdir("beta-shared");
    let not_after = time::OffsetDateTime::now_utc() + time::Duration::days(180);
    let (cert, key) = mint_cert_with_not_after(&dir, not_after);
    let yaml = write_yaml(&dir, &cert, &key);
    // Add listen_beta to the same YAML so the β-section validation
    // runs, but DON'T set beta_cert_chain — so the β path resolves
    // to the shared tls block.
    let body = std::fs::read_to_string(&yaml).unwrap();
    let extended = format!("{body}listen_beta: \"0.0.0.0:8443\"\n");
    std::fs::write(&yaml, extended).unwrap();
    let cfg = ServerConfig::load(&yaml).await.expect("config loads");
    let report = validate::preflight(&cfg);
    eprintln!("beta-shared report:\n{report}");

    // The α "leaf valid for N day(s)" PASS appears exactly once.
    let leaf_passes = report
        .checks
        .iter()
        .filter(|c| matches!(c, Check::Pass(s) if s.contains("leaf cert valid for") || s.contains("leaf valid for")))
        .count();
    assert!(
        leaf_passes <= 1,
        "shared-cert dual-stack must NOT double-count cert expiry: {report}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn iter46_cert_with_plenty_of_lifetime_passes() {
    let dir = tmpdir("healthy");
    // notAfter = 180 days from now. Well outside the renewal window.
    let not_after = time::OffsetDateTime::now_utc() + time::Duration::days(180);
    let (cert, key) = mint_cert_with_not_after(&dir, not_after);
    let yaml = write_yaml(&dir, &cert, &key);

    let cfg = ServerConfig::load(&yaml).await.expect("config loads");
    let report = validate::preflight(&cfg);
    eprintln!("healthy-cert report:\n{report}");

    let pass = report.checks.iter().any(|c| match c {
        Check::Pass(s) => s.contains("leaf cert valid for") && s.contains("day"),
        _ => false,
    });
    assert!(
        pass,
        "cert with ≥14 days left MUST produce a PASS row with days-remaining: {report}"
    );
    // No expiry-related WARN/FAIL.
    let any_warn = report.checks.iter().any(|c| matches!(c, Check::Warn(s) if s.contains("expires in")));
    let any_fail = report.checks.iter().any(|c| matches!(c, Check::Fail(s) if s.contains("EXPIRED")));
    assert!(!any_warn, "healthy cert must not WARN: {report}");
    assert!(!any_fail, "healthy cert must not FAIL: {report}");
    let _ = std::fs::remove_dir_all(&dir);
}
