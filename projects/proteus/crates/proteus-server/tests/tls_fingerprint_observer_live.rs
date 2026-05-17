//! Integration test for the live TLS ClientHello fingerprint
//! observer.
//!
//! Drives a real `observe_live_ja4` call against the production
//! TLS connector (Chrome-shaped CryptoProvider, ALPN h2+http/1.1)
//! and asserts the captured JA4 string equals the locked baseline.
//!
//! This is the runtime counterpart to the CI-time regression test
//! in `crates/proteus-fingerprint/tests/proteus_alpha_ja4_baseline.rs`.
//! Together they guarantee the wire fingerprint stays stable
//! across both the build-from-source path (CI) and the
//! built-binary-runs path (live observation).

use proteus_server::tls_fingerprint_observer::{observe_live_ja4, EXPECTED_BASELINE};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_observer_captures_expected_baseline_ja4() {
    // Mint a fresh self-signed cert. The cert content is
    // irrelevant — JA4 is computed entirely from the
    // CLIENT-side ClientHello.
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "localhost");
    params.subject_alt_names = vec![rcgen::SanType::DnsName(
        rcgen::Ia5String::try_from("localhost").unwrap(),
    )];
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    let leaf = rustls::pki_types::CertificateDer::from(cert.der().to_vec());

    let observed = observe_live_ja4(leaf).await;
    // Surface the captured value for debugging if it ever
    // drifts — the operator gets the same eprint as the
    // baseline test gives.
    eprintln!("Live JA4: {}", observed.ja4);
    eprintln!("Expected: {}", EXPECTED_BASELINE);
    assert_eq!(
        observed.ja4, EXPECTED_BASELINE,
        "Live observer captured JA4 that does NOT match the locked baseline. \
         Either the rustls config drifted (regression — investigate) OR uTLS \
         work landed (update EXPECTED_BASELINE in tls_fingerprint_observer.rs \
         AND in proteus_alpha_ja4_baseline.rs)."
    );
    assert!(observed.matches_baseline());
}
