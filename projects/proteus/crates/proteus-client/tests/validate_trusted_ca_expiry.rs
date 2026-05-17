//! Iter-47: client `validate` cert-expiry coverage for the
//! `tls.trusted_ca` pinning bundle.
//!
//! Symmetric with iter-46's server-side leaf-cert check. The
//! client uses `tls.trusted_ca` as the trust anchor on every
//! dial; an expired CA breaks every connection silently. Unlike
//! Let's Encrypt leaf certs, operator-managed pinning CAs do
//! NOT auto-renew — the operator is the only line of defense,
//! and `validate` is where they get to see the warning before
//! the cert hits production.
//!
//! The earliest-notAfter-across-the-bundle policy is used (any
//! expiring entry is the actionable signal):
//!   - earliest notAfter < now           → FAIL
//!   - <14 days remaining                → WARN
//!   - ≥14 days remaining                → PASS
//!
//! Tests use rcgen to mint CA-style certs with controlled
//! notAfter, write them as PEM bundles, point `tls.trusted_ca`
//! at the bundle, then run `validate::run` and inspect the
//! report.

use std::path::PathBuf;
use std::time::SystemTime;

use proteus_client::validate::{self, Check};

fn tmpdir(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "proteus-client-trusted-ca-{}-{}-{:?}-{}",
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

fn touch(dir: &std::path::Path, name: &str, content: &[u8]) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, content).unwrap();
    p
}

/// Mint a single CA cert (self-signed, basic_constraints=is_ca) with
/// the supplied notAfter. Returns its PEM bytes.
fn mint_ca(not_after: time::OffsetDateTime) -> String {
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Test Trust Anchor");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(30);
    params.not_after = not_after;
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    cert.pem()
}

fn write_keys(dir: &std::path::Path) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    use base64::Engine;
    let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    let mlkem = touch(dir, "mlkem.pk", format!("{}\n", b64(&vec![0u8; 1184])).as_bytes());
    let x = touch(dir, "x25519.pk", format!("{}\n", b64(&[0u8; 32])).as_bytes());
    let fp = touch(dir, "fp", format!("{}\n", b64(&[0u8; 32])).as_bytes());
    let sk = touch(dir, "sk", format!("{}\n", b64(&[0u8; 32])).as_bytes());
    (mlkem, x, fp, sk)
}

fn write_yaml_with_ca(dir: &std::path::Path, ca_path: &std::path::Path) -> PathBuf {
    let (mlkem, x, fp, sk) = write_keys(dir);
    let yaml = dir.join("client.yaml");
    std::fs::write(
        &yaml,
        format!(
            r#"server_endpoint: "vps.example.com:8443"
socks_listen: "127.0.0.1:1080"
user_id: "alice"
keys:
  server_mlkem_pk: {}
  server_x25519_pk: {}
  server_pq_fingerprint: {}
  client_ed25519_sk: {}
tls:
  server_name: vps.example.com
  trusted_ca: {}
"#,
            mlkem.display(),
            x.display(),
            fp.display(),
            sk.display(),
            ca_path.display(),
        ),
    )
    .unwrap();
    yaml
}

#[tokio::test]
async fn iter47_expired_ca_in_trusted_bundle_fails_validate() {
    let dir = tmpdir("expired-ca");
    let pem = mint_ca(time::OffsetDateTime::now_utc() - time::Duration::days(3));
    let ca_path = touch(&dir, "trusted_ca.pem", pem.as_bytes());
    let yaml = write_yaml_with_ca(&dir, &ca_path);

    let report = validate::run(&yaml).await;
    eprintln!("expired-ca report:\n{report}");

    let fail = report.checks.iter().any(|c| match c {
        Check::Fail(s) => s.contains("tls.trusted_ca") && s.contains("EXPIRED"),
        _ => false,
    });
    assert!(
        fail,
        "expired CA in trust bundle MUST FAIL validate: {report}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn iter47_ca_near_expiry_warns() {
    let dir = tmpdir("near-expiry-ca");
    let pem = mint_ca(time::OffsetDateTime::now_utc() + time::Duration::days(7));
    let ca_path = touch(&dir, "trusted_ca.pem", pem.as_bytes());
    let yaml = write_yaml_with_ca(&dir, &ca_path);

    let report = validate::run(&yaml).await;
    eprintln!("near-expiry-ca report:\n{report}");

    let warn = report.checks.iter().any(|c| match c {
        Check::Warn(s) => s.contains("tls.trusted_ca") && s.contains("notAfter in"),
        _ => false,
    });
    assert!(
        warn,
        "CA with <14 days left MUST WARN at validate: {report}"
    );
    // WARN must not become a FAIL — keep exit 0 for "fix this soon" semantics.
    assert!(
        !report.has_failures(),
        "near-expiry CA WARN must not escalate to FAIL: {report}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn iter47_healthy_ca_passes_with_days_remaining() {
    let dir = tmpdir("healthy-ca");
    let pem = mint_ca(time::OffsetDateTime::now_utc() + time::Duration::days(365));
    let ca_path = touch(&dir, "trusted_ca.pem", pem.as_bytes());
    let yaml = write_yaml_with_ca(&dir, &ca_path);

    let report = validate::run(&yaml).await;
    eprintln!("healthy-ca report:\n{report}");

    let pass = report.checks.iter().any(|c| match c {
        Check::Pass(s) => s.contains("tls.trusted_ca") && s.contains("valid for") && s.contains("day"),
        _ => false,
    });
    assert!(
        pass,
        "healthy CA MUST emit PASS with days-remaining note: {report}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Multi-cert bundle: earliest notAfter dominates. If the bundle
/// has one healthy CA + one near-expiry CA, the warning fires
/// on the earliest entry — the operator can't ignore it just
/// because some entries are fine.
#[tokio::test]
async fn iter47_multi_ca_bundle_earliest_wins() {
    let dir = tmpdir("multi-ca");
    let healthy = mint_ca(time::OffsetDateTime::now_utc() + time::Duration::days(365));
    let near = mint_ca(time::OffsetDateTime::now_utc() + time::Duration::days(5));
    let combined = format!("{healthy}{near}");
    let ca_path = touch(&dir, "trusted_ca.pem", combined.as_bytes());
    let yaml = write_yaml_with_ca(&dir, &ca_path);

    let report = validate::run(&yaml).await;
    eprintln!("multi-ca report:\n{report}");

    let warn = report.checks.iter().any(|c| match c {
        Check::Warn(s) => s.contains("tls.trusted_ca") && s.contains("notAfter in"),
        _ => false,
    });
    assert!(
        warn,
        "multi-CA bundle with earliest <14d MUST WARN (operator can't ignore the worst entry): {report}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
