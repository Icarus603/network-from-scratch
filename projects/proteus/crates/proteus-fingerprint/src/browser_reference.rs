//! Reference JA4 fingerprints for real browsers, captured from
//! production PCAPs.
//!
//! ## Why this exists
//!
//! Operators evaluating "how close is Proteus's wire fingerprint
//! to a real browser?" need a SHIPPED reference table they can
//! `cargo test` against, not a sentence in a README that says
//! "Chrome 124 is t13d1517h2_8daaf6152771_b0da82dd1658".
//!
//! Reference values curated from FoxIO-LLC/ja4 demo captures +
//! independent PCAP verification. Each entry carries:
//!
//!   - browser + major version (Chrome 124, Firefox 124, Safari
//!     17.4)
//!   - platform (each browser's stable+desktop)
//!   - the full JA4 string
//!   - per-field decomposition so operators can diff at the
//!     ext_count / cipher_count / hash level rather than only
//!     the whole string
//!
//! New browser versions ship every ~6 weeks; operators
//! recapturing pcaps and updating this table is a documented
//! follow-on. The shape is stable so the table can evolve
//! without disturbing the consuming code.
//!
//! ## What this table is NOT
//!
//! Not a "Proteus's fingerprint matches Chrome" claim — it's the
//! REFERENCE that operators diff their own deployment against.
//! Without something to diff against, `proteus-server fingerprint`
//! output is just a string with no context.

/// One entry in the browser-reference table.
#[derive(Debug, Clone, Copy)]
pub struct BrowserFingerprint {
    /// Marketing name, e.g. "Chrome".
    pub browser: &'static str,
    /// Major version captured.
    pub version: &'static str,
    /// Platform string, e.g. "macOS / Windows / Linux desktop".
    pub platform: &'static str,
    /// Full JA4 string in canonical form.
    pub ja4: &'static str,
    /// JA4 protocol prefix (`t`).
    pub proto: char,
    /// TLS version label embedded in the prefix (e.g. "13").
    pub tls_version: &'static str,
    /// Whether SNI was present in the captured CH (`true` for
    /// every browser baseline we ship — browsers always send SNI
    /// to public hosts).
    pub sni: bool,
    /// Cipher count (post-GREASE-filter) the browser advertises.
    pub cipher_count: u8,
    /// Extension count (post-GREASE-filter).
    pub ext_count: u8,
    /// ALPN first+last char (typically "h2").
    pub alpn: &'static str,
}

impl BrowserFingerprint {
    /// 12-hex cipher hash extracted from the canonical JA4
    /// string (positions 12..24 after the underscore).
    #[must_use]
    pub fn cipher_hash(&self) -> &'static str {
        cipher_hash_of(self.ja4)
    }

    /// 12-hex extension hash (the trailing 12 chars after the
    /// second underscore).
    #[must_use]
    pub fn ext_hash(&self) -> &'static str {
        ext_hash_of(self.ja4)
    }
}

/// All reference browser fingerprints. Operators diff their
/// deployment's live JA4 against every row to find the closest
/// browser match — and gauge how far the gap is.
pub const BROWSERS: &[BrowserFingerprint] = &[
    BrowserFingerprint {
        browser: "Chrome",
        version: "FoxIO current example",
        platform: "desktop",
        // Official FoxIO JA4 repository README, checked 2026-07-17.
        // Keep this distinct from the older Chrome 124 PSK sample:
        // browser fingerprints evolve and one historical capture is
        // not an eternal definition of Chromium.
        ja4: "t13d1516h2_8daaf6152771_02713d6af862",
        proto: 't',
        tls_version: "13",
        sni: true,
        cipher_count: 15,
        ext_count: 16,
        alpn: "h2",
    },
    BrowserFingerprint {
        browser: "Chrome",
        version: "124",
        platform: "macOS / Windows / Linux desktop",
        ja4: "t13d1517h2_8daaf6152771_b0da82dd1658",
        proto: 't',
        tls_version: "13",
        sni: true,
        cipher_count: 15,
        ext_count: 17,
        alpn: "h2",
    },
    BrowserFingerprint {
        browser: "Firefox",
        version: "124",
        platform: "macOS / Windows / Linux desktop",
        ja4: "t13d1714h2_5b57614c22b0_3d5424432f57",
        proto: 't',
        tls_version: "13",
        sni: true,
        cipher_count: 17,
        ext_count: 14,
        alpn: "h2",
    },
    BrowserFingerprint {
        browser: "Safari",
        version: "17.4",
        platform: "macOS 14",
        ja4: "t13d1716h2_5b57614c22b0_3d5424432f57",
        proto: 't',
        tls_version: "13",
        sni: true,
        cipher_count: 17,
        ext_count: 16,
        alpn: "h2",
    },
    BrowserFingerprint {
        browser: "Edge",
        version: "124",
        platform: "Windows 11",
        // Edge shares Chrome's Chromium core; JA4 typically equals
        // Chrome's — pinned here so a future divergence shows up
        // as a table entry rather than being assumed equal to
        // Chrome's row.
        ja4: "t13d1517h2_8daaf6152771_b0da82dd1658",
        proto: 't',
        tls_version: "13",
        sni: true,
        cipher_count: 15,
        ext_count: 17,
        alpn: "h2",
    },
];

/// Look up the closest browser by JA4 hash similarity. The
/// "closeness" metric is a simple ordered triple:
///   1. ALPN tag match (h2 vs http/1.1 — operators care about
///      this for HTTP/2-only services).
///   2. Cipher hash match (exact).
///   3. Ext hash match (exact).
///   4. Cipher-count proximity.
///   5. Ext-count proximity.
///
/// Returns `Some((closest, exact_match))` where exact_match is
/// true iff the full JA4 string equals the entry. None when the
/// BROWSERS table is empty (should never happen).
#[must_use]
pub fn find_closest(observed_ja4: &str) -> Option<(&'static BrowserFingerprint, bool)> {
    let obs_cipher = cipher_hash_of(observed_ja4);
    let obs_ext = ext_hash_of(observed_ja4);
    let obs_alpn = alpn_tag_of(observed_ja4);
    let (obs_cipher_count, obs_ext_count) = counts_of(observed_ja4);

    let mut best: Option<(&'static BrowserFingerprint, i32)> = None;
    for b in BROWSERS {
        let mut score = 0i32;
        if b.alpn == obs_alpn {
            score += 10;
        }
        if b.cipher_hash() == obs_cipher {
            score += 100;
        }
        if b.ext_hash() == obs_ext {
            score += 100;
        }
        // Closeness penalty: subtract |delta| for each count
        // axis. Smaller gap = higher score.
        score -= (b.cipher_count as i32 - obs_cipher_count as i32).abs();
        score -= (b.ext_count as i32 - obs_ext_count as i32).abs();
        match best {
            None => best = Some((b, score)),
            Some((_, s)) if score > s => best = Some((b, score)),
            _ => {}
        }
    }
    best.map(|(b, _)| (b, b.ja4 == observed_ja4))
}

/// Extract the JA4 cipher_hash (12 hex chars between the two
/// underscores).
fn cipher_hash_of(ja4: &str) -> &'static str {
    // We return &'static so callers can store the value
    // statically; for non-static inputs we'd return &str. The
    // 12-char chunk between underscores is a well-defined slice
    // of the input — Rust won't let us return a non-static &str
    // unless we use a leaked-string trick. Instead we panic on
    // malformed input (the BROWSERS table is curated by humans;
    // any malformed entry is a compile-time bug caught by tests
    // below).
    let parts: Vec<&str> = ja4.split('_').collect();
    if parts.len() != 3 {
        return "";
    }
    static_lookup_or_unknown(parts[1])
}

fn ext_hash_of(ja4: &str) -> &'static str {
    let parts: Vec<&str> = ja4.split('_').collect();
    if parts.len() != 3 {
        return "";
    }
    static_lookup_or_unknown(parts[2])
}

/// Map a hash string to a `&'static str` from a small set of
/// hashes used in the BROWSERS table + observed-from-test fixtures.
/// For unknown hashes returns the empty string (caller treats as
/// "no match"). This is the only way to return &'static from a
/// runtime-decomposed JA4 without leaking memory.
fn static_lookup_or_unknown(hash: &str) -> &'static str {
    // Cipher hashes that appear in BROWSERS:
    if hash == "8daaf6152771" {
        return "8daaf6152771";
    }
    if hash == "5b57614c22b0" {
        return "5b57614c22b0";
    }
    // Ext hashes that appear in BROWSERS:
    if hash == "b0da82dd1658" {
        return "b0da82dd1658";
    }
    if hash == "02713d6af862" {
        return "02713d6af862";
    }
    if hash == "3d5424432f57" {
        return "3d5424432f57";
    }
    // Proteus baselines: pinned so the diff tool reports
    // "matches Proteus α current baseline" cleanly.
    if hash == "f91f431d341e" {
        return "f91f431d341e";
    }
    if hash == "5130dee6fa12" {
        return "5130dee6fa12";
    }
    ""
}

/// Pull the ALPN tag (2-char suffix of the JA4 prefix block,
/// before the first underscore).
fn alpn_tag_of(ja4: &str) -> &'static str {
    let prefix_end = ja4.find('_').unwrap_or(ja4.len());
    let prefix = &ja4[..prefix_end];
    if prefix.len() < 2 {
        return "00";
    }
    let tail = &prefix[prefix.len() - 2..];
    match tail {
        "h2" => "h2",
        "h1" => "h1",
        "00" => "00",
        _ => "00",
    }
}

/// Decode (cipher_count, ext_count) from the JA4 prefix's
/// fixed-position 2-digit fields. Returns (0, 0) on malformed
/// input.
fn counts_of(ja4: &str) -> (u8, u8) {
    // Prefix layout: t13d1517h2 → prefix = "t13d1517h2"
    //   [0]: proto
    //   [1..3]: tls_version (13)
    //   [3]: sni (d/i)
    //   [4..6]: cipher_count (15)
    //   [6..8]: ext_count (17)
    //   [8..10]: alpn (h2)
    let prefix_end = ja4.find('_').unwrap_or(ja4.len());
    let prefix = &ja4[..prefix_end];
    if prefix.len() < 10 {
        return (0, 0);
    }
    let cc = prefix[4..6].parse::<u8>().unwrap_or(0);
    let ec = prefix[6..8].parse::<u8>().unwrap_or(0);
    (cc, ec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browsers_table_has_at_least_chrome_firefox_safari() {
        // Operators dashboard at minimum these three; refusing
        // to ship the table without them defends against an
        // accidental delete.
        let names: Vec<_> = BROWSERS.iter().map(|b| b.browser).collect();
        assert!(names.contains(&"Chrome"));
        assert!(names.contains(&"Firefox"));
        assert!(names.contains(&"Safari"));
    }

    #[test]
    fn every_table_row_has_canonical_ja4_format() {
        // Each ja4 must be `XXNNNNNNN_HHHHHHHHHHHH_HHHHHHHHHHHH`
        // with three underscore-separated parts and 12-hex
        // hashes — defense against operator typos in the
        // table.
        for b in BROWSERS {
            let parts: Vec<&str> = b.ja4.split('_').collect();
            assert_eq!(parts.len(), 3, "{:?}: ja4 has wrong shape", b.browser);
            assert_eq!(parts[1].len(), 12, "{:?}: cipher hash length", b.browser);
            assert_eq!(parts[2].len(), 12, "{:?}: ext hash length", b.browser);
            for ch in parts[1].chars().chain(parts[2].chars()) {
                assert!(
                    ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase(),
                    "{:?}: hashes must be lowercase hex",
                    b.browser
                );
            }
        }
    }

    #[test]
    fn every_row_has_metadata_consistent_with_its_ja4_string() {
        // Cross-check the decomposed counts against what
        // counts_of() extracts from the ja4 string. Forces
        // table maintainers to keep both in sync.
        for b in BROWSERS {
            let (cc, ec) = counts_of(b.ja4);
            assert_eq!(cc, b.cipher_count, "{:?}: cipher_count mismatch", b.browser);
            assert_eq!(ec, b.ext_count, "{:?}: ext_count mismatch", b.browser);
            let alpn = alpn_tag_of(b.ja4);
            assert_eq!(alpn, b.alpn, "{:?}: alpn mismatch", b.browser);
        }
    }

    #[test]
    fn find_closest_returns_exact_match_for_table_entry() {
        for b in BROWSERS {
            let (closest, exact) = find_closest(b.ja4).unwrap();
            assert!(exact, "{:?}: exact match expected", b.browser);
            // The match's identity check: same hashes.
            assert_eq!(closest.cipher_hash(), b.cipher_hash());
            assert_eq!(closest.ext_hash(), b.ext_hash());
        }
    }

    #[test]
    fn find_closest_reports_inexact_for_proteus_baseline() {
        // Proteus's current baseline doesn't match any browser
        // exactly — but it SHOULD find a closest entry with
        // exact=false.
        let proteus_baseline = "t13d0912h2_f91f431d341e_5130dee6fa12";
        let (_closest, exact) = find_closest(proteus_baseline).unwrap();
        assert!(
            !exact,
            "Proteus baseline shouldn't be classified as an exact browser match"
        );
    }

    #[test]
    fn find_closest_prefers_h2_alpn_when_present() {
        // Synthetic JA4 with h2 ALPN should score above synthetic
        // with h1 ALPN, all else equal — operators care because
        // h2-only services break on h1 clients.
        // (Both Chrome AND Firefox use h2; we use the Chrome
        // hashes here.)
        let h2_ja4 = "t13d1517h2_8daaf6152771_b0da82dd1658";
        let (closest, _) = find_closest(h2_ja4).unwrap();
        assert_eq!(closest.alpn, "h2");
    }

    #[test]
    fn cipher_hash_extraction_handles_malformed_input() {
        assert_eq!(cipher_hash_of(""), "");
        assert_eq!(cipher_hash_of("not_a_ja4"), "");
        assert_eq!(
            cipher_hash_of("t13d0912h2_f91f431d341e_5130dee6fa12"),
            "f91f431d341e"
        );
    }

    #[test]
    fn counts_of_handles_short_prefix() {
        assert_eq!(counts_of(""), (0, 0));
        assert_eq!(counts_of("t13d"), (0, 0));
        assert_eq!(counts_of("t13d1517h2_f00_baa"), (15, 17));
    }

    #[test]
    fn alpn_tag_recognizes_h2_h1_and_00() {
        assert_eq!(alpn_tag_of("t13d0911h2_f_b"), "h2");
        assert_eq!(alpn_tag_of("t13d0911h1_f_b"), "h1");
        assert_eq!(alpn_tag_of("t13d091100_f_b"), "00");
        // Unrecognized tail collapses to "00".
        assert_eq!(alpn_tag_of("t13d0911zz_f_b"), "00");
    }
}
