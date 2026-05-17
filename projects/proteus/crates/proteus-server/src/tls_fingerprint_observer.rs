//! Capture and surface the LIVE TLS ClientHello JA4 fingerprint.
//!
//! ## Why this exists
//!
//! The proteus-fingerprint crate ships a JA4 baseline regression
//! test that locks the EXACT JA4 string Proteus α emits today
//! (`t13d0911h2_f91f431d341e_165ef185bad8` with the current
//! rustls 0.23 + Chrome-shaped CryptoProvider). That test catches
//! changes at CI time.
//!
//! Operators in production also want to KNOW what JA4 their
//! running binary emits, without having to capture pcaps. Three
//! reasons:
//!
//!   1. **Drift detection at deploy time.** A `cargo update` on
//!      rustls that shifts a single byte in the ClientHello will
//!      shift the JA4 hash. The CI test catches it before merge —
//!      but only if the operator's release pipeline ran the test.
//!      For deployments built outside the canonical release flow
//!      (operator built from main, custom fork, etc.), the live
//!      JA4 gauge surfaces drift immediately.
//!   2. **Censor-evolution diffing.** When operators read
//!      GFW.report posts about new ML classifiers, they want to
//!      diff "what JA4 am I emitting today" against the classifier
//!      training data. A `curl :9090/metrics | grep tls_clienthello_ja4`
//!      answers that in one line.
//!   3. **uTLS milestone gating.** When the eventual rustls-fork /
//!      BoringSSL-swap lands and the JA4 changes to a Chrome
//!      bit-perfect value, operators can verify the deploy by
//!      reading the gauge. No tshark required.
//!
//! ## How it works
//!
//! Called once at startup. Stands up a one-shot loopback TCP
//! listener. The server-side task accepts the connection and
//! reads up to 2 KiB — the ClientHello fits comfortably. We
//! then drop the connection (the client side fails its
//! handshake, which is fine — we already have what we wanted).
//! Parse the captured bytes via
//! `proteus_fingerprint::parse_client_hello` and return the
//! computed JA4 string.
//!
//! Failure modes (rare; loopback bind / accept failures) are
//! surfaced as a sentinel `"capture_failed:<err>"` string on
//! the gauge — operators see the gauge present but with a clear
//! "we couldn't measure" marker instead of an absent series.
//! This matches the operator-visibility pattern used by
//! `startup_self_test_passed` (0 vs 1).

use proteus_transport_alpha::tls::{build_connector_with_ca_der, TlsError};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

/// Captured fingerprint state. Built once at startup; read by
/// `/metrics` + `/diagnose` for the lifetime of the process.
#[derive(Debug, Clone)]
pub struct LiveJa4 {
    /// The full JA4 string the binary's TLS stack emits on the
    /// wire. Sentinel `"capture_failed:<err>"` when the observer
    /// couldn't complete a self-handshake (extremely rare — would
    /// mean loopback TCP is broken).
    pub ja4: String,
    /// Operator-visible reference baseline the regression test
    /// locks against. Read at /metrics scrape time so operators
    /// can diff live vs expected without leaving the dashboard.
    pub expected_baseline: &'static str,
}

/// The reference baseline JA4 string Proteus α should be emitting
/// with the CURRENT (rustls 0.23 + Chrome-shaped CryptoProvider)
/// configuration. MUST stay equal to
/// `proteus-fingerprint::tests::proteus_alpha_ja4_baseline::EXPECTED_BASELINE`
/// — see the unit test below that fails the build if they ever
/// drift.
pub const EXPECTED_BASELINE: &str = "t13d0911h2_f91f431d341e_165ef185bad8";

impl LiveJa4 {
    /// `true` when the observed JA4 matches the locked-in baseline.
    /// Operators alert on `match == false`: it means a rustls /
    /// dep / build change drifted the wire fingerprint and may
    /// have moved the binary further FROM Chrome (regression) or
    /// CLOSER to Chrome (uTLS work landed — update the baseline).
    #[must_use]
    pub fn matches_baseline(&self) -> bool {
        self.ja4 == self.expected_baseline
    }

    /// Emit the JA4 block as Prometheus exposition. Three series:
    ///
    /// - `proteus_tls_clienthello_ja4{value="..."}` (gauge=1) —
    ///   labeled value carries the JA4 string. Operators
    ///   `topk(1, proteus_tls_clienthello_ja4)` to read it.
    /// - `proteus_tls_clienthello_ja4_expected{value="..."}` (gauge=1)
    ///   — the operator-visible reference baseline.
    /// - `proteus_tls_clienthello_ja4_baseline_match` (gauge 0/1)
    ///   — alert on `== 0` to spot wire-fingerprint drift.
    #[must_use]
    pub fn prometheus(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(384);
        let escaped_live = escape_label(&self.ja4);
        let escaped_baseline = escape_label(self.expected_baseline);
        let _ = writeln!(
            s,
            "# HELP proteus_tls_clienthello_ja4 Live JA4 fingerprint of the binary's ClientHello (label = the JA4 string itself)."
        );
        let _ = writeln!(s, "# TYPE proteus_tls_clienthello_ja4 gauge");
        let _ = writeln!(
            s,
            r#"proteus_tls_clienthello_ja4{{value="{escaped_live}"}} 1"#
        );
        let _ = writeln!(
            s,
            "# HELP proteus_tls_clienthello_ja4_expected Reference baseline JA4 the regression test locks against."
        );
        let _ = writeln!(s, "# TYPE proteus_tls_clienthello_ja4_expected gauge");
        let _ = writeln!(
            s,
            r#"proteus_tls_clienthello_ja4_expected{{value="{escaped_baseline}"}} 1"#
        );
        let _ = writeln!(
            s,
            "# HELP proteus_tls_clienthello_ja4_baseline_match 1 if the live ClientHello JA4 equals the locked baseline; 0 = drifted (rustls upgrade, dep change, OR uTLS work landed — investigate which)."
        );
        let _ = writeln!(s, "# TYPE proteus_tls_clienthello_ja4_baseline_match gauge");
        let _ = writeln!(
            s,
            "proteus_tls_clienthello_ja4_baseline_match {}",
            u64::from(self.matches_baseline())
        );
        s
    }
}

/// Stand up a loopback listener, drive a TLS client handshake
/// against it (which will FAIL because the loopback server
/// doesn't complete the handshake — that's fine), capture the
/// ClientHello bytes, parse JA4, return.
///
/// The capture path is deliberately one-shot: bind 127.0.0.1:0,
/// accept exactly one connection, read up to 2 KiB (the
/// ClientHello fits comfortably under 1 KiB for our
/// Chrome-shaped variant), drop the connection. The client's
/// rustls connect future returns Err — we don't care.
///
/// `leaf` is the operator's actual server cert leaf, used to
/// build a pin-trusting client connector so the connector
/// matches what production traffic uses. Without this, a
/// connector built with `webpki_roots` would refuse to send a
/// ClientHello to our loopback because the SNI wouldn't match
/// any anchor.
pub async fn observe_live_ja4(leaf: rustls::pki_types::CertificateDer<'static>) -> LiveJa4 {
    match observe_live_ja4_inner(leaf).await {
        Ok(s) => LiveJa4 {
            ja4: s,
            expected_baseline: EXPECTED_BASELINE,
        },
        Err(e) => {
            tracing::warn!(
                error = %e,
                "tls_fingerprint_observer: capture failed — operator gauge will read \
                 'capture_failed' instead of the live JA4 string. Self-test passing \
                 but observer failing is a programming error (file a bug)."
            );
            LiveJa4 {
                ja4: format!("capture_failed:{e}"),
                expected_baseline: EXPECTED_BASELINE,
            }
        }
    }
}

/// Capture the live ClientHello AND parse it into both `Ja4` and
/// `Ja4Components`. Used by `proteus-server fingerprint --target
/// chrome-124` to surface a byte-level diff vs Chrome — the JA4
/// hash alone tells you "they differ"; the components diff tells
/// you "ADD extension 0x4469, REMOVE cipher 0x1303 from position
/// 2, swap sig_alg positions 0↔2".
///
/// Returns `None` on observer-internal failure (loopback bind
/// fails, capture times out). Callers fall back to the JA4-only
/// path in that case.
pub async fn observe_live_ja4_with_components(
    leaf: rustls::pki_types::CertificateDer<'static>,
) -> Option<(proteus_fingerprint::Ja4, proteus_fingerprint::Ja4Components)> {
    let raw = observe_raw_client_hello(leaf).await.ok()?;
    proteus_fingerprint::ja4::parse_client_hello_with_components(&raw, 't').ok()
}

/// Internal: capture just the raw ClientHello bytes (without
/// computing JA4). Both `observe_live_ja4_inner` and
/// `observe_live_ja4_with_components` share this so the loopback
/// dance is only spelled out once.
async fn observe_raw_client_hello(
    leaf: rustls::pki_types::CertificateDer<'static>,
) -> Result<Vec<u8>, String> {
    let connector =
        build_connector_with_ca_der(leaf).map_err(|e: TlsError| format!("build_connector: {e}"))?;
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("bind: {e}"))?;
    let addr = listener
        .local_addr()
        .map_err(|e| format!("local_addr: {e}"))?;
    let (tx, rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
    let server_task = tokio::spawn(async move {
        let (mut stream, _peer) = match listener.accept().await {
            Ok(p) => p,
            Err(_) => return,
        };
        let mut buf = vec![0u8; 2048];
        let mut total = 0usize;
        let read_fut = async {
            loop {
                let n = stream.read(&mut buf[total..]).await.ok()?;
                if n == 0 {
                    return Some(total);
                }
                total += n;
                if total >= 5 {
                    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize + 5;
                    if total >= record_len {
                        return Some(record_len);
                    }
                }
                if total >= buf.len() {
                    return Some(total);
                }
            }
        };
        let n = match tokio::time::timeout(std::time::Duration::from_secs(3), read_fut).await {
            Ok(Some(n)) => n,
            _ => return,
        };
        buf.truncate(n);
        let _ = tx.send(buf);
    });
    let sn = rustls::pki_types::ServerName::try_from("localhost")
        .map_err(|e| format!("server_name: {e}"))?
        .to_owned();
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        connector.connect(sn, tcp),
    )
    .await;
    let raw = tokio::time::timeout(std::time::Duration::from_secs(2), rx)
        .await
        .map_err(|_| "capture timeout".to_string())?
        .map_err(|_| "capture channel dropped".to_string())?;
    server_task.abort();
    Ok(raw)
}

async fn observe_live_ja4_inner(
    leaf: rustls::pki_types::CertificateDer<'static>,
) -> Result<String, String> {
    let connector =
        build_connector_with_ca_der(leaf).map_err(|e: TlsError| format!("build_connector: {e}"))?;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("bind: {e}"))?;
    let addr = listener
        .local_addr()
        .map_err(|e| format!("local_addr: {e}"))?;

    let (tx, rx) = tokio::sync::oneshot::channel::<Vec<u8>>();

    // Server-side capture task: accept ONE connection, read up
    // to 2 KiB of incoming bytes (the ClientHello fits well
    // under 1 KiB for our config), ship to the channel, drop
    // the connection. We never complete the TLS handshake on
    // this side — we only need the ClientHello.
    let server_task = tokio::spawn(async move {
        let (mut stream, _peer) = match listener.accept().await {
            Ok(p) => p,
            Err(_) => return,
        };
        let mut buf = vec![0u8; 2048];
        let mut total = 0usize;
        // Loop briefly until we have a TLS record or we time out.
        // rustls writes the ClientHello in a single send so the
        // first read returns the full record; we still loop in
        // case the kernel splits it.
        let read_fut = async {
            loop {
                let n = stream.read(&mut buf[total..]).await.ok()?;
                if n == 0 {
                    return Some(total);
                }
                total += n;
                // Record header parsed enough?
                if total >= 5 {
                    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize + 5;
                    if total >= record_len {
                        return Some(record_len);
                    }
                }
                if total >= buf.len() {
                    return Some(total);
                }
            }
        };
        let n = match tokio::time::timeout(std::time::Duration::from_secs(3), read_fut).await {
            Ok(Some(n)) => n,
            _ => return,
        };
        buf.truncate(n);
        let _ = tx.send(buf);
        // stream drops here → client side sees EOF + reports
        // handshake error. That's intended.
    });

    // Client-side: drive rustls to send a ClientHello. We don't
    // care about handshake completion.
    let sn = rustls::pki_types::ServerName::try_from("localhost")
        .map_err(|e| format!("server_name: {e}"))?
        .to_owned();
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        connector.connect(sn, tcp),
    )
    .await;

    let raw = tokio::time::timeout(std::time::Duration::from_secs(2), rx)
        .await
        .map_err(|_| "capture timeout".to_string())?
        .map_err(|_| "capture channel dropped".to_string())?;
    // Server task already finished + the JoinHandle is just an
    // observation handle here; the task itself is gone the
    // moment its accept-then-capture-then-drop logic returned.
    server_task.abort();

    let ja4 = proteus_fingerprint::ja4::parse_client_hello(&raw, 't')
        .map_err(|e| format!("parse_client_hello: {e}"))?;
    Ok(ja4.to_string())
}

/// Prometheus 0.0.4 label-value escape.
fn escape_label(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '\\' => out.push_str(r"\\"),
            '"' => out.push_str(r#"\""#),
            '\n' => out.push_str(r"\n"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_ja4_struct_matches_baseline_helper_works() {
        let m = LiveJa4 {
            ja4: EXPECTED_BASELINE.to_string(),
            expected_baseline: EXPECTED_BASELINE,
        };
        assert!(m.matches_baseline());

        let d = LiveJa4 {
            ja4: "t13d9999h2_deadbeef9999_cafef00d9999".to_string(),
            expected_baseline: EXPECTED_BASELINE,
        };
        assert!(!d.matches_baseline());
    }

    #[test]
    fn prometheus_emits_three_series_with_value_labels() {
        let m = LiveJa4 {
            ja4: EXPECTED_BASELINE.to_string(),
            expected_baseline: EXPECTED_BASELINE,
        };
        let s = m.prometheus();
        assert!(s.contains(r#"proteus_tls_clienthello_ja4{value=""#));
        assert!(s.contains(r#"proteus_tls_clienthello_ja4_expected{value=""#));
        assert!(s.contains("proteus_tls_clienthello_ja4_baseline_match 1"));
    }

    #[test]
    fn prometheus_baseline_match_is_zero_when_drifted() {
        let d = LiveJa4 {
            ja4: "t13d9999h2_deadbeef9999_cafef00d9999".to_string(),
            expected_baseline: EXPECTED_BASELINE,
        };
        let s = d.prometheus();
        assert!(s.contains("proteus_tls_clienthello_ja4_baseline_match 0"));
        assert!(s.contains(r#"value="t13d9999h2_deadbeef9999_cafef00d9999""#));
    }

    #[test]
    fn capture_failed_sentinel_is_obvious_in_prometheus() {
        let f = LiveJa4 {
            ja4: "capture_failed:bind: address in use".to_string(),
            expected_baseline: EXPECTED_BASELINE,
        };
        let s = f.prometheus();
        assert!(s.contains("capture_failed"));
        assert!(s.contains("proteus_tls_clienthello_ja4_baseline_match 0"));
    }

    #[test]
    fn escape_label_handles_quote_backslash_newline() {
        assert_eq!(escape_label("plain"), "plain");
        assert_eq!(escape_label(r#"a"b"#), r#"a\"b"#);
        assert_eq!(escape_label(r"a\b"), r"a\\b");
        assert_eq!(escape_label("a\nb"), r"a\nb");
    }

    #[test]
    fn baseline_constant_matches_fingerprint_crate_baseline() {
        // Drift detector: if `proteus-fingerprint`'s baseline
        // test updates its EXPECTED_BASELINE without updating
        // ours, this test fails — forces operators to keep the
        // two literals in sync.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("proteus-fingerprint")
            .join("tests")
            .join("proteus_alpha_ja4_baseline.rs");
        let src = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
        let needle = format!(r#"const EXPECTED_BASELINE: &str = "{EXPECTED_BASELINE}""#);
        assert!(
            src.contains(&needle),
            "EXPECTED_BASELINE drift: tls_fingerprint_observer.rs has {EXPECTED_BASELINE:?} \
             but proteus_alpha_ja4_baseline.rs does not contain that exact literal. \
             Update one or the other so they stay in sync."
        );
    }
}
