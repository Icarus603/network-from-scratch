//! **Baseline measurement** of the JA4 fingerprint that the Proteus
//! α-profile client currently emits.
//!
//! This is the **measurement infrastructure** for the uTLS-grade
//! ClientHello replay work that has NOT YET shipped. The test does
//! three things:
//!
//! 1. Stand up a TCP listener that records the FIRST N bytes the
//!    client transmits (= the ClientHello, since rustls fires it
//!    immediately after the TCP handshake completes).
//! 2. Drive a real tokio-rustls TLS connector at the listener using
//!    the EXACT same `build_connector_webpki_roots()` Proteus α
//!    uses in production (ALPN `h2`/`http/1.1`, TLS 1.3 only). This
//!    way the ClientHello we capture is bit-identical to what
//!    Proteus emits on the wire.
//! 3. Parse the captured ClientHello, compute its JA4 fingerprint,
//!    print it, and assert it matches a baseline we record here.
//!
//! ## Why the baseline assertion is a SOFT regression guard
//!
//! The baseline JA4 is what rustls emits TODAY with the current
//! workspace dep versions. If rustls upgrades and changes its
//! cipher / extension order, this test will fail with a clear
//! "fingerprint changed from X to Y" message — and that's exactly
//! what we want: any change to the TLS shape must be audited.
//!
//! ## What the printed JA4 tells us
//!
//! Compare against published browser JA4s (curated by FoxIO):
//!
//!   Chrome 124 TLS:      t13d1517h2_8daaf6152771_b0da82dd1658
//!   Firefox 124 TLS:     t13d1714h2_5b57614c22b0_3d5424432f57
//!   Safari 17.4 TLS:     t13d1716h2_5b57614c22b0_3d5424432f57
//!
//! Proteus α (rustls 0.23): a distinct fingerprint that DOES NOT
//! match any major browser. The test eprints the value so the
//! operator can see exactly what the gap to a browser baseline
//! looks like.

use proteus_fingerprint::ja4::parse_client_hello;
use rustls::pki_types::ServerName;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

/// Build the exact same TLS connector Proteus α uses in production.
fn build_proteus_alpha_connector() -> tokio_rustls::TlsConnector {
    // Install the default crypto provider exactly once.
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });

    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config =
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(roots)
            .with_no_client_auth();
    // EXACT same ALPN list Proteus α uses (see crates/proteus-transport-
    // alpha/src/tls.rs::build_connector_webpki_roots).
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    tokio_rustls::TlsConnector::from(Arc::new(config))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proteus_alpha_clienthello_ja4_baseline() {
    // 1. Listener that records the first 4 KiB of bytes the client
    //    transmits, then drops the connection. We don't bother
    //    completing the TLS handshake — we only need the
    //    ClientHello.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let recorder = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        // Read whatever ClientHello bytes the client sends.
        let n = sock.read(&mut buf).await.unwrap_or(0);
        buf.truncate(n);
        buf
    });

    // 2. Dial the listener with the Proteus α connector.
    let connector = build_proteus_alpha_connector();
    let tcp = TcpStream::connect(addr).await.unwrap();
    let sn = ServerName::try_from("example.com").unwrap();
    // We expect this to fail (recorder drops the connection without
    // responding); just need to know rustls SENT the ClientHello.
    let _ = timeout(Duration::from_secs(3), connector.connect(sn, tcp)).await;

    let raw = timeout(Duration::from_secs(3), recorder)
        .await
        .expect("recorder timeout")
        .expect("recorder panicked");

    assert!(
        raw.len() >= 5,
        "did not capture any bytes — TCP layer broken?"
    );
    assert_eq!(
        raw[0], 0x16,
        "first captured byte should be TLS record type 0x16 (handshake), got {:#04x}",
        raw[0]
    );

    let ja4 = parse_client_hello(&raw, 't').expect("parse ClientHello");

    eprintln!("=== Proteus α (rustls 0.23) ClientHello JA4 baseline ===");
    eprintln!("  {ja4}");
    eprintln!("  cipher_count = {}", ja4.cipher_count);
    eprintln!("  ext_count    = {}", ja4.ext_count);
    eprintln!("  version      = {}", ja4.version);
    eprintln!("  sni present  = {}", ja4.sni == 'd');
    eprintln!("  alpn_tag     = {}", ja4.alpn_tag);
    eprintln!();
    eprintln!("Compare against published browser baselines:");
    eprintln!("  Chrome 124:  t13d1517h2_8daaf6152771_b0da82dd1658");
    eprintln!("  Firefox 124: t13d1714h2_5b57614c22b0_3d5424432f57");
    eprintln!();
    eprintln!("If this fingerprint differs, the uTLS replay work has");
    eprintln!("not yet landed — Proteus is detectable by JA4 alone.");

    // ----- Property assertions on the SHAPE, not the exact value -----
    //
    // The exact JA4 will change if rustls bumps cipher/extension
    // orderings — those are stable enough that we test only the
    // invariants that MUST hold for ANY TLS 1.3 ClientHello, plus
    // the ALPN we control.
    assert_eq!(ja4.transport, 't', "transport must be TCP for α");
    assert_eq!(
        ja4.version, "13",
        "Proteus α negotiates TLS 1.3 only; supported_versions must advertise 0x0304"
    );
    assert_eq!(ja4.sni, 'd', "Proteus α always sends SNI");
    assert_eq!(
        ja4.alpn_tag, "h2",
        "Proteus α ALPN list starts with 'h2' (matching browsers)"
    );
    assert!(
        ja4.cipher_count >= 3,
        "TLS 1.3 mandates AES-128-GCM, AES-256-GCM, CHACHA20-POLY1305 — at least 3 ciphers"
    );
    assert!(
        ja4.cipher_count < 30,
        "rustls should not be advertising >30 ciphers — got {}",
        ja4.cipher_count
    );
    assert!(
        ja4.ext_count >= 5,
        "minimum TLS 1.3 extension set is supported_versions + key_share + signature_algorithms + server_name + supported_groups (5)"
    );
    // Hashes are 12 lowercase hex chars.
    assert_eq!(ja4.cipher_hash.len(), 12);
    assert!(
        ja4.cipher_hash.chars().all(|c| c.is_ascii_hexdigit()),
        "cipher_hash must be hex"
    );
    assert_eq!(ja4.ext_hash.len(), 12);
    assert!(
        ja4.ext_hash.chars().all(|c| c.is_ascii_hexdigit()),
        "ext_hash must be hex"
    );

    // ----- EXACT baseline assertion (regression guardrail) -----
    //
    // This locks the JA4 fingerprint that rustls 0.23 emits today
    // with our exact ClientConfig (TLS 1.3 only, ALPN = h2,http/1.1,
    // webpki-roots, ring crypto provider, ed25519+ECDSA signature
    // algs). A change here means either:
    //   (a) the workspace bumped rustls and rustls altered its
    //       cipher / extension ordering — operators should audit
    //       that the new shape is intentional;
    //   (b) the uTLS-grade ClientHello replay work just landed —
    //       update this baseline to match the new fingerprint
    //       (which should match a real browser, e.g. Chrome 124).
    //
    // Either way the change MUST be intentional. The test catches
    // accidental TLS-shape regressions in CI.
    const EXPECTED_BASELINE: &str = "t13d0910h2_f91f431d341e_6a7d638fc319";
    assert_eq!(
        ja4.to_string(),
        EXPECTED_BASELINE,
        "JA4 baseline drift detected.\n\
         Current:  {}\n\
         Expected: {}\n\
         If this is intentional (rustls upgrade, uTLS replay landed,\n\
         etc.) update EXPECTED_BASELINE in this test.",
        ja4,
        EXPECTED_BASELINE,
    );
}
