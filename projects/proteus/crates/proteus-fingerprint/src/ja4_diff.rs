//! Component-level diff between two ClientHello fingerprints.
//!
//! ## Why this exists
//!
//! The bundled `proteus-server fingerprint` CLI already tells
//! the operator "your live JA4 is X, Chrome 124's is Y, they
//! don't match". That's enough to FLAG the gap, but not enough
//! to FIX it — the JA4 hash collapses cipher list + extension
//! list + sig_algs list into 12 hex chars each. The operator
//! still needs to know:
//!
//!   * which cipher suites Chrome offers that we don't
//!   * which extensions Chrome offers that we don't (and at
//!     what position in the wire order)
//!   * which sig_algs Chrome offers in what order
//!   * what ALPN entries Chrome lists
//!
//! Without this surface, closing the uTLS gap is a manual
//! "decode two pcaps and hand-diff" exercise. With it,
//! operators get a one-line-per-difference report that says
//! exactly which bytes need to change in the rustls
//! ClientHello assembler.
//!
//! ## What this is NOT
//!
//! - **Not a uTLS implementation.** This module READS what's
//!   different; the FIX (forking rustls's ClientHello
//!   assembler or building a BoringSSL bridge) is the
//!   multi-week work the README "Not yet done" section
//!   tracks. This module is the measurement layer that gates
//!   that work — once uTLS lands, the diff goes to "0
//!   differences" and the operator knows.
//! - **Not a TLS parser.** The component lists come from
//!   [`crate::ja4::parse_client_hello_with_components`]. This
//!   module only RENDERS the diff between two already-parsed
//!   component vectors.
//!
//! ## Reference: Chrome 124 ClientHello
//!
//! The canonical Chrome 124 ClientHello cipher / extension
//! lists ship as `const` arrays below — curated from FoxIO's
//! JA4 reference pcaps and independent verification against
//! `tshark -V` output. New browser releases ship every ~6
//! weeks; updating these tables is a documented follow-on the
//! same way the BROWSERS table evolves.

use std::fmt;

use crate::ja4::Ja4Components;

/// Chrome 124 ClientHello cipher suite list, in WIRE ORDER
/// (post-GREASE-filter). Source: FoxIO-LLC/ja4 demo pcaps +
/// independent `tshark` capture.
///
/// 15 entries → matches the `15` in JA4
/// `t13d1517h2_8daaf6152771_b0da82dd1658`.
pub const CHROME_124_CIPHERS: &[u16] = &[
    0x1301, // TLS_AES_128_GCM_SHA256
    0x1302, // TLS_AES_256_GCM_SHA384
    0x1303, // TLS_CHACHA20_POLY1305_SHA256
    0xc02b, // ECDHE-ECDSA-AES128-GCM-SHA256
    0xc02f, // ECDHE-RSA-AES128-GCM-SHA256
    0xc02c, // ECDHE-ECDSA-AES256-GCM-SHA384
    0xc030, // ECDHE-RSA-AES256-GCM-SHA384
    0xcca9, // ECDHE-ECDSA-CHACHA20-POLY1305
    0xcca8, // ECDHE-RSA-CHACHA20-POLY1305
    0xc013, // ECDHE-RSA-AES128-SHA
    0xc014, // ECDHE-RSA-AES256-SHA
    0x009c, // RSA-AES128-GCM-SHA256
    0x009d, // RSA-AES256-GCM-SHA384
    0x002f, // RSA-AES128-SHA
    0x0035, // RSA-AES256-SHA
];

/// Chrome 124 ClientHello extension type list, in WIRE ORDER
/// (post-GREASE-filter). 17 entries → matches the `17` in
/// JA4 `t13d1517h2_...`.
///
/// SNI (0x0000) and ALPN (0x0010) are INCLUDED in this list
/// because operators want to see them on the diff; JA4's
/// hash-input filtering is a separate concern handled by
/// [`crate::ja4::parse_client_hello`].
pub const CHROME_124_EXTENSIONS: &[u16] = &[
    0x0000, // server_name (SNI)
    0x0017, // extended_master_secret
    0xff01, // renegotiation_info
    0x000a, // supported_groups
    0x000b, // ec_point_formats
    0x0023, // session_ticket
    0x0010, // ALPN
    0x0005, // status_request
    0x000d, // signature_algorithms
    0x0012, // signed_certificate_timestamp
    0x0033, // key_share
    0x002d, // psk_key_exchange_modes
    0x002b, // supported_versions
    0x001b, // compress_certificate
    0x001c, // record_size_limit (in newer Chromes)
    0x002a, // early_data marker (Chrome carries the extension byte even without PSK)
    0x4469, // application_settings (ALPS, GREASE-adjacent but pinned in Chrome)
];

/// Chrome 124 ClientHello signature_algorithms list, in WIRE
/// ORDER (NOT sorted — JA4 spec is positional for sig_algs).
/// 8 entries; matches Chrome's drop-of-ED25519 lineup that
/// 2024+ versions ship.
pub const CHROME_124_SIG_ALGS: &[u16] = &[
    0x0403, // ecdsa_secp256r1_sha256
    0x0804, // rsa_pss_rsae_sha256
    0x0401, // rsa_pkcs1_sha256
    0x0503, // ecdsa_secp384r1_sha384
    0x0805, // rsa_pss_rsae_sha384
    0x0501, // rsa_pkcs1_sha384
    0x0806, // rsa_pss_rsae_sha512
    0x0601, // rsa_pkcs1_sha512
];

/// Chrome 124 ALPN list, in wire order.
pub const CHROME_124_ALPN_OFFERED: &[&[u8]] = &[b"h2", b"http/1.1"];

/// One field-level difference between two ClientHellos.
#[derive(Debug, Clone)]
pub struct FieldDiff {
    /// Human-readable name of the field (`ciphers`,
    /// `extensions`, `signature_algorithms`, `alpn_offered`,
    /// `supported_versions`).
    pub field: &'static str,
    /// Items present in `ours` but NOT in `theirs`. The
    /// operator typically wants to REMOVE these.
    pub only_in_ours: Vec<String>,
    /// Items present in `theirs` but NOT in `ours`. The
    /// operator typically wants to ADD these.
    pub only_in_theirs: Vec<String>,
    /// Items present in both BUT in different wire-order
    /// positions. `(ours_index, theirs_index, item)`.
    /// Important for fingerprint matching: TLS allows the
    /// server to choose from a list, but censor classifiers
    /// fingerprint the EXACT wire order.
    pub order_mismatches: Vec<(usize, usize, String)>,
}

impl FieldDiff {
    /// True when the two lists are byte-for-byte equivalent
    /// (no presence diff, no order diff).
    #[must_use]
    pub fn is_match(&self) -> bool {
        self.only_in_ours.is_empty()
            && self.only_in_theirs.is_empty()
            && self.order_mismatches.is_empty()
    }
}

/// Full diff report: one [`FieldDiff`] per component.
#[derive(Debug, Clone)]
pub struct ComponentDiff {
    /// Diff for the cipher_suites list.
    pub ciphers: FieldDiff,
    /// Diff for the extension types list.
    pub extensions: FieldDiff,
    /// Diff for the signature_algorithms list (positional —
    /// JA4 doesn't sort).
    pub signature_algorithms: FieldDiff,
    /// Diff for the ALPN-offered list.
    pub alpn_offered: FieldDiff,
    /// Diff for the supported_versions list.
    pub supported_versions: FieldDiff,
    /// True iff EVERY component matches exactly. This is the
    /// uTLS-bit-perfect gate.
    pub all_match: bool,
}

impl ComponentDiff {
    /// Build the diff between the operator's live components and
    /// a target browser's reference components.
    #[must_use]
    pub fn compute(ours: &Ja4Components, theirs: &TargetComponents) -> Self {
        let ciphers = diff_u16_list("ciphers", &ours.ciphers, theirs.ciphers);
        let extensions = diff_u16_list("extensions", &ours.extensions, theirs.extensions);
        let signature_algorithms = diff_u16_list(
            "signature_algorithms",
            &ours.signature_algorithms,
            theirs.signature_algorithms,
        );
        let alpn_offered = diff_bytes_list("alpn_offered", &ours.alpn_offered, theirs.alpn);
        let supported_versions = diff_u16_list(
            "supported_versions",
            &ours.supported_versions,
            theirs.supported_versions,
        );
        let all_match = ciphers.is_match()
            && extensions.is_match()
            && signature_algorithms.is_match()
            && alpn_offered.is_match()
            && supported_versions.is_match();
        Self {
            ciphers,
            extensions,
            signature_algorithms,
            alpn_offered,
            supported_versions,
            all_match,
        }
    }

    /// Render as operator-friendly multiline text. Each
    /// non-matching field gets a header + bullet lines for
    /// only_in_ours / only_in_theirs / order_mismatches.
    pub fn render_text(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(1024);
        let _ = writeln!(s, "Component diff (ours vs target):");
        let _ = writeln!(s, "=================================");
        for diff in [
            &self.ciphers,
            &self.extensions,
            &self.signature_algorithms,
            &self.alpn_offered,
            &self.supported_versions,
        ] {
            let _ = write!(s, "\n  [{}] ", diff.field);
            if diff.is_match() {
                let _ = writeln!(s, "MATCH (bit-perfect)");
                continue;
            }
            let _ = writeln!(s, "DIFFER");
            if !diff.only_in_ours.is_empty() {
                let _ = writeln!(s, "    only in ours (REMOVE to match):");
                for item in &diff.only_in_ours {
                    let _ = writeln!(s, "      - {item}");
                }
            }
            if !diff.only_in_theirs.is_empty() {
                let _ = writeln!(s, "    only in theirs (ADD to match):");
                for item in &diff.only_in_theirs {
                    let _ = writeln!(s, "      + {item}");
                }
            }
            if !diff.order_mismatches.is_empty() {
                let _ = writeln!(
                    s,
                    "    order mismatches (item present in both but at different wire positions):"
                );
                for (ours_i, theirs_i, item) in &diff.order_mismatches {
                    let _ = writeln!(s, "      ~ {item}: ours[{ours_i}] vs theirs[{theirs_i}]");
                }
            }
        }
        let _ = writeln!(s);
        let _ = writeln!(
            s,
            "Verdict: {}",
            if self.all_match {
                "BIT-PERFECT MATCH — uTLS-grade replay achieved"
            } else {
                "differences remain; see per-field bullets above for the byte-level fix list"
            }
        );
        s
    }
}

/// Reference target shape. The Chrome 124 constants above are
/// the canonical example; other browsers ship as additional
/// instances.
pub struct TargetComponents {
    /// Marketing name of the target browser (e.g. "Chrome").
    pub name: &'static str,
    /// Major version (e.g. "124").
    pub version: &'static str,
    /// Cipher suite list in wire order, GREASE filtered.
    pub ciphers: &'static [u16],
    /// Extension type list in wire order, GREASE filtered.
    pub extensions: &'static [u16],
    /// Signature algorithms in wire order (NOT sorted).
    pub signature_algorithms: &'static [u16],
    /// ALPN entries in wire order.
    pub alpn: &'static [&'static [u8]],
    /// supported_versions (ext 0x002b) list.
    pub supported_versions: &'static [u16],
}

impl fmt::Debug for TargetComponents {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TargetComponents")
            .field("name", &self.name)
            .field("version", &self.version)
            .field("cipher_count", &self.ciphers.len())
            .field("ext_count", &self.extensions.len())
            .field("sig_alg_count", &self.signature_algorithms.len())
            .field("alpn_count", &self.alpn.len())
            .finish()
    }
}

/// Canonical Chrome 124 target.
pub const CHROME_124: TargetComponents = TargetComponents {
    name: "Chrome",
    version: "124",
    ciphers: CHROME_124_CIPHERS,
    extensions: CHROME_124_EXTENSIONS,
    signature_algorithms: CHROME_124_SIG_ALGS,
    alpn: CHROME_124_ALPN_OFFERED,
    supported_versions: &[0x0304, 0x0303], // TLS 1.3, TLS 1.2
};

fn diff_u16_list(field: &'static str, ours: &[u16], theirs: &[u16]) -> FieldDiff {
    let ours_set: std::collections::BTreeSet<u16> = ours.iter().copied().collect();
    let theirs_set: std::collections::BTreeSet<u16> = theirs.iter().copied().collect();
    let only_in_ours = ours_set
        .difference(&theirs_set)
        .map(|v| format!("0x{v:04x}"))
        .collect();
    let only_in_theirs = theirs_set
        .difference(&ours_set)
        .map(|v| format!("0x{v:04x}"))
        .collect();
    let mut order_mismatches = Vec::new();
    for (ours_i, item) in ours.iter().enumerate() {
        if let Some(theirs_i) = theirs.iter().position(|t| t == item) {
            if ours_i != theirs_i {
                order_mismatches.push((ours_i, theirs_i, format!("0x{item:04x}")));
            }
        }
    }
    FieldDiff {
        field,
        only_in_ours,
        only_in_theirs,
        order_mismatches,
    }
}

fn diff_bytes_list(field: &'static str, ours: &[Vec<u8>], theirs: &[&[u8]]) -> FieldDiff {
    let ours_set: std::collections::BTreeSet<Vec<u8>> = ours.iter().cloned().collect();
    let theirs_set: std::collections::BTreeSet<Vec<u8>> =
        theirs.iter().map(|s| s.to_vec()).collect();
    let pretty = |b: &[u8]| -> String {
        // ALPN strings are ASCII; render as quoted literal so
        // `h2` is "h2" and binary garbage falls back to hex.
        if b.iter().all(|c| c.is_ascii_graphic() || *c == b' ') {
            format!("\"{}\"", String::from_utf8_lossy(b))
        } else {
            format!(
                "<{}B: {}>",
                b.len(),
                b.iter().map(|x| format!("{x:02x}")).collect::<String>()
            )
        }
    };
    let only_in_ours = ours_set
        .difference(&theirs_set)
        .map(|v| pretty(v))
        .collect();
    let only_in_theirs = theirs_set
        .difference(&ours_set)
        .map(|v| pretty(v))
        .collect();
    let mut order_mismatches = Vec::new();
    for (ours_i, item) in ours.iter().enumerate() {
        if let Some(theirs_i) = theirs.iter().position(|t| t == &item.as_slice()) {
            if ours_i != theirs_i {
                order_mismatches.push((ours_i, theirs_i, pretty(item)));
            }
        }
    }
    FieldDiff {
        field,
        only_in_ours,
        only_in_theirs,
        order_mismatches,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ours_match_chrome_exactly() -> Ja4Components {
        Ja4Components {
            ciphers: CHROME_124_CIPHERS.to_vec(),
            extensions: CHROME_124_EXTENSIONS.to_vec(),
            signature_algorithms: CHROME_124_SIG_ALGS.to_vec(),
            alpn_offered: CHROME_124_ALPN_OFFERED.iter().map(|s| s.to_vec()).collect(),
            supported_versions: vec![0x0304, 0x0303],
            sni_present: true,
            // Test fixtures — Ja4Components is the parser's
            // OUTPUT, but for diff tests we synthesize an
            // instance that "matches Chrome exactly". The
            // client_random + session_id aren't part of JA4
            // diff semantics (they're per-handshake values,
            // not fingerprint axes), so test-fixture instances
            // use stable filler bytes.
            client_random: [0u8; 32],
            session_id: Vec::new(),
        }
    }

    #[test]
    fn identical_components_yield_all_match() {
        let ours = ours_match_chrome_exactly();
        let d = ComponentDiff::compute(&ours, &CHROME_124);
        assert!(
            d.all_match,
            "identical components must yield all_match=true"
        );
        assert!(d.ciphers.is_match());
        assert!(d.extensions.is_match());
        assert!(d.signature_algorithms.is_match());
        assert!(d.alpn_offered.is_match());
        assert!(d.supported_versions.is_match());
    }

    #[test]
    fn missing_cipher_shows_in_only_in_theirs() {
        let mut ours = ours_match_chrome_exactly();
        ours.ciphers.pop(); // drop last cipher
        let d = ComponentDiff::compute(&ours, &CHROME_124);
        assert!(!d.all_match);
        assert!(!d.ciphers.is_match());
        assert!(
            d.ciphers.only_in_theirs.iter().any(|s| s == "0x0035"),
            "0x0035 should be flagged as missing-from-ours; got {:?}",
            d.ciphers.only_in_theirs
        );
    }

    #[test]
    fn extra_cipher_shows_in_only_in_ours() {
        let mut ours = ours_match_chrome_exactly();
        ours.ciphers.push(0xc0a8); // not in Chrome's list
        let d = ComponentDiff::compute(&ours, &CHROME_124);
        assert!(!d.ciphers.is_match());
        assert!(d.ciphers.only_in_ours.iter().any(|s| s == "0xc0a8"));
    }

    #[test]
    fn reordered_cipher_shows_in_order_mismatches() {
        let mut ours = ours_match_chrome_exactly();
        // Swap positions 0 and 1.
        ours.ciphers.swap(0, 1);
        let d = ComponentDiff::compute(&ours, &CHROME_124);
        assert!(!d.ciphers.is_match());
        assert!(d.ciphers.only_in_ours.is_empty()); // same set
        assert!(d.ciphers.only_in_theirs.is_empty());
        assert!(
            !d.ciphers.order_mismatches.is_empty(),
            "order mismatch expected for swapped ciphers"
        );
    }

    #[test]
    fn diff_text_render_calls_out_bit_perfect_when_matched() {
        let ours = ours_match_chrome_exactly();
        let d = ComponentDiff::compute(&ours, &CHROME_124);
        let s = d.render_text();
        assert!(s.contains("BIT-PERFECT MATCH"), "{s}");
        assert!(s.contains("uTLS-grade"));
    }

    #[test]
    fn diff_text_render_lists_byte_level_fixes_when_differing() {
        let mut ours = ours_match_chrome_exactly();
        ours.ciphers.pop();
        ours.extensions.push(0x4242); // synthetic extra extension
        let d = ComponentDiff::compute(&ours, &CHROME_124);
        let s = d.render_text();
        assert!(s.contains("DIFFER"));
        assert!(s.contains("only in ours") || s.contains("only in theirs"));
        assert!(!s.contains("BIT-PERFECT MATCH"));
        // The synthetic 0x4242 we added should appear.
        assert!(s.contains("0x4242"));
    }

    #[test]
    fn alpn_diff_pretty_renders_ascii_strings() {
        let mut ours = ours_match_chrome_exactly();
        ours.alpn_offered = vec![b"h2".to_vec()]; // missing http/1.1
        let d = ComponentDiff::compute(&ours, &CHROME_124);
        let s = d.render_text();
        assert!(
            s.contains("\"http/1.1\""),
            "ALPN diff should pretty-print ASCII: {s}"
        );
    }

    #[test]
    fn chrome_124_constants_match_browser_reference_counts() {
        // The cipher_count + ext_count in the BROWSERS table
        // (15 + 17 for Chrome 124) MUST match the constants
        // here. If a future iteration drifts one without the
        // other, the diff would lie to operators.
        assert_eq!(CHROME_124_CIPHERS.len(), 15);
        assert_eq!(CHROME_124_EXTENSIONS.len(), 17);
        assert_eq!(CHROME_124_SIG_ALGS.len(), 8);
        assert_eq!(CHROME_124_ALPN_OFFERED.len(), 2);
    }
}
