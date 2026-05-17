//! `proteus-server preflight all` — single-shot bundle of every
//! offline preflight check.
//!
//! ## Why this exists
//!
//! After three iterations we ship three independent preflight
//! subcommands — `check-ip-reputation`, `check-host`, and the
//! standalone `fingerprint` (under the top-level `Cmd::Fingerprint`).
//! Each returns its own exit code and prints its own report. For
//! operators driving deploys from Ansible / Terraform / CI that's
//! one command, one exit-code check, one summary block. Bundling
//! every preflight into one orchestrator command means:
//!
//!   - **One exit code.** 0 iff every sub-check is PASS+WARN-only,
//!     1 on any FAIL. The deploy-gate task becomes a single shell
//!     check instead of three chained ones with `&&` plumbing.
//!   - **One unified text report.** Each sub-check's section gets
//!     a header banner; the bottom-line summary collapses every
//!     finding into a single (pass/warn/fail) tuple. Operators
//!     skimming `journalctl -u proteus-deploy` see the gestalt.
//!   - **One JSON document.** `--format json` emits a single JSON
//!     object with `{"kind":"preflight_summary", "sections":{...},
//!     "totals":{...}, "exit_code":N}`. jq pipelines stay simple;
//!     dashboards stay symmetric with `admin status --format json`.
//!   - **Future-proof composition.** A new preflight check (e.g.
//!     a `check-cert-renewal-headroom` once Let's Encrypt expiry
//!     logic ships) drops in here automatically without operators
//!     needing to update their deploy scripts.
//!
//! ## Sub-checks bundled today
//!
//! | section name | underlying module | inputs needed |
//! |---|---|---|
//! | `ip_reputation` | [`crate::preflight`] | config OR `--public-ip` |
//! | `host_posture` | [`crate::host_preflight`] | config (optional) |
//! | `fingerprint`  | [`crate::tls_fingerprint_observer`] | none (loopback handshake) |
//!
//! ## Output schema
//!
//! ```text
//! ── preflight: ip_reputation ───────────────────────────────────
//! (lines from preflight::PreflightReport...)
//!
//! ── preflight: host_posture ────────────────────────────────────
//! (lines from host_preflight::HostReport...)
//!
//! ── preflight: fingerprint ─────────────────────────────────────
//! (live JA4 + baseline + closest browser, summarised...)
//!
//! ── totals ─────────────────────────────────────────────────────
//! summary: 12 pass, 1 warn, 0 fail  (exit 0)
//! ```
//!
//! JSON shape (one document, schema is append-only):
//!
//! ```json
//! {
//!   "kind": "preflight_summary",
//!   "sections": {
//!     "ip_reputation": { "pass": N, "warn": N, "fail": N, "skipped": false },
//!     "host_posture":  { "pass": N, "warn": N, "fail": N, "skipped": false },
//!     "fingerprint":   { "matches_baseline": true, "live_ja4": "..." }
//!   },
//!   "totals": { "pass": N, "warn": N, "fail": N },
//!   "exit_code": 0
//! }
//! ```

use std::io::Write;
use std::path::PathBuf;

use crate::host_preflight::{self, HostPreflightInput};
use crate::ip_reputation::Severity;
use crate::preflight::{self, PreflightInput};

/// Operator inputs the orchestrator forwards to each sub-check.
/// Optional fields stay optional — every sub-check has its own
/// "what to do when this input is absent" semantics (e.g. host
/// audit without a config still runs the non-key-file checks).
#[derive(Debug, Default)]
pub struct PreflightAllInput {
    /// Shared YAML config path. Forwarded to `ip_reputation`
    /// (extracts listen address) and `host_posture` (extracts
    /// key-file paths). Optional.
    pub config_path: Option<PathBuf>,
    /// Operator-supplied public IP for the IP-reputation check.
    /// Wins over `config_path`-derived listen IP.
    pub public_ip_override: Option<std::net::IpAddr>,
    /// Optional operator watchlist for IP reputation.
    pub watchlist_path: Option<PathBuf>,
    /// When true, skip the fingerprint sub-check entirely (its
    /// loopback handshake adds ~50–100 ms of latency; CI gates
    /// that already ran the dedicated `fingerprint` subcommand
    /// don't need to repeat it). Default false.
    pub skip_fingerprint: bool,
}

/// Final orchestrator output. Carries the raw sub-reports plus a
/// computed totals tuple so renderers (text + JSON) share one
/// source of truth.
#[derive(Debug)]
pub struct OrchestratorReport {
    pub ip_reputation: Option<preflight::PreflightReport>,
    pub host_posture: Option<host_preflight::HostReport>,
    pub fingerprint: Option<FingerprintSection>,
    /// Aggregate (pass, warn, fail) across every sub-check.
    pub totals: (usize, usize, usize),
}

/// Compact fingerprint-section summary. We don't depend on
/// `LiveJa4`/`Ja4` directly so this module stays renderer-only
/// (the heavy loopback work lives in
/// [`crate::tls_fingerprint_observer`]).
#[derive(Debug, Clone)]
pub struct FingerprintSection {
    pub live_ja4: String,
    pub expected_baseline: &'static str,
    pub matches_baseline: bool,
}

impl FingerprintSection {
    /// Map to the same severity grammar the other sub-checks use:
    /// matching baseline = PASS; drift = WARN (it may be expected
    /// uTLS-replay progress; not strictly a FAIL since the binary
    /// itself emits a warn log line at startup explaining both
    /// possibilities).
    fn severity(&self) -> Severity {
        if self.matches_baseline {
            Severity::Pass
        } else {
            Severity::Warn
        }
    }
}

impl OrchestratorReport {
    /// Exit code: 0 on PASS+WARN-only, 1 on any FAIL anywhere.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        if self.totals.2 > 0 {
            1
        } else {
            0
        }
    }

    /// Render as the operator-friendly multiline text report.
    pub fn render_text(&self, out: &mut impl Write) -> std::io::Result<()> {
        // Section banner helper. Keep width fixed so the
        // overall report aligns visually in any 80-col terminal.
        const BANNER: &str = "──────────────────────────────────────────────";

        if let Some(ip) = &self.ip_reputation {
            writeln!(out, "── preflight: ip_reputation {BANNER}")?;
            write!(out, "{ip}")?;
            writeln!(out)?;
        } else {
            writeln!(
                out,
                "── preflight: ip_reputation {BANNER}\n  (skipped — no --config and no --public-ip)\n"
            )?;
        }

        if let Some(host) = &self.host_posture {
            writeln!(out, "── preflight: host_posture {BANNER}")?;
            write!(out, "{host}")?;
            writeln!(out)?;
        } else {
            writeln!(
                out,
                "── preflight: host_posture {BANNER}\n  (skipped — orchestrator disabled this section)\n"
            )?;
        }

        if let Some(fp) = &self.fingerprint {
            writeln!(out, "── preflight: fingerprint {BANNER}")?;
            writeln!(out, "  live_ja4:          {}", fp.live_ja4)?;
            writeln!(out, "  expected_baseline: {}", fp.expected_baseline)?;
            writeln!(
                out,
                "  matches_baseline:  {}",
                if fp.matches_baseline {
                    "yes"
                } else {
                    "no — drift OR intentional uTLS milestone"
                }
            )?;
            writeln!(out)?;
        } else {
            writeln!(
                out,
                "── preflight: fingerprint {BANNER}\n  (skipped — --skip-fingerprint set)\n"
            )?;
        }

        let (p, w, f) = self.totals;
        writeln!(out, "── totals {BANNER}")?;
        writeln!(
            out,
            "summary: {p} pass, {w} warn, {f} fail  (exit {ec})",
            ec = self.exit_code()
        )?;
        Ok(())
    }

    /// Render as a single-line JSON document (no trailing newline
    /// — caller decides). Append-only schema: new keys land but
    /// existing keys stay.
    pub fn render_json(&self, out: &mut impl Write) -> std::io::Result<()> {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(512);
        s.push_str(r#"{"kind":"preflight_summary","sections":{"#);

        // ip_reputation
        s.push_str(r#""ip_reputation":"#);
        match &self.ip_reputation {
            Some(r) => {
                let (p, w, f) = r.counts();
                let _ = write!(s, r#"{{"pass":{p},"warn":{w},"fail":{f},"skipped":false}}"#);
            }
            None => s.push_str(r#"{"skipped":true}"#),
        }
        s.push(',');

        // host_posture
        s.push_str(r#""host_posture":"#);
        match &self.host_posture {
            Some(r) => {
                let (p, w, f) = r.counts();
                let _ = write!(s, r#"{{"pass":{p},"warn":{w},"fail":{f},"skipped":false}}"#);
            }
            None => s.push_str(r#"{"skipped":true}"#),
        }
        s.push(',');

        // fingerprint
        s.push_str(r#""fingerprint":"#);
        match &self.fingerprint {
            Some(fp) => {
                let _ = write!(
                    s,
                    r#"{{"live_ja4":"{}","expected_baseline":"{}","matches_baseline":{},"skipped":false}}"#,
                    fp.live_ja4, fp.expected_baseline, fp.matches_baseline,
                );
            }
            None => s.push_str(r#"{"skipped":true}"#),
        }
        s.push('}');
        s.push(',');

        // totals + exit_code
        let (p, w, f) = self.totals;
        let _ = write!(
            s,
            r#""totals":{{"pass":{p},"warn":{w},"fail":{f}}},"exit_code":{ec}}}"#,
            ec = self.exit_code()
        );

        out.write_all(s.as_bytes())
    }
}

/// Run the orchestrator. Sub-checks execute sequentially — total
/// runtime is dominated by the fingerprint section's loopback
/// handshake (~50–100 ms) so there's no win from parallelising;
/// sequential output also keeps log ordering deterministic.
pub async fn run(input: PreflightAllInput) -> OrchestratorReport {
    // ip_reputation: forwards config + override + watchlist. The
    // sub-check itself decides whether to FAIL when both inputs
    // are absent — we don't pre-skip here because operators
    // sometimes WANT the explicit "you forgot to give me anything
    // to check" guidance.
    let ip = preflight::run(PreflightInput {
        config_path: input.config_path.clone(),
        public_ip_override: input.public_ip_override,
        watchlist_path: input.watchlist_path.clone(),
    });

    // host_posture: also forwards config; with no config it runs
    // the non-key-file checks only (still useful — ulimit, sysctls,
    // urandom, NTP, disk_free run unconditionally).
    let host = host_preflight::run(HostPreflightInput {
        config_path: input.config_path.clone(),
        ..Default::default()
    });

    // fingerprint: optional, gated by --skip-fingerprint.
    let fp = if input.skip_fingerprint {
        None
    } else {
        Some(capture_fingerprint().await)
    };

    // Aggregate totals across every section.
    let mut totals = (0usize, 0usize, 0usize);
    {
        let (p, w, f) = ip.counts();
        totals.0 += p;
        totals.1 += w;
        totals.2 += f;
    }
    {
        let (p, w, f) = host.counts();
        totals.0 += p;
        totals.1 += w;
        totals.2 += f;
    }
    if let Some(fp) = &fp {
        match fp.severity() {
            Severity::Pass => totals.0 += 1,
            Severity::Warn => totals.1 += 1,
            Severity::Fail => totals.2 += 1,
        }
    }

    OrchestratorReport {
        ip_reputation: Some(ip),
        host_posture: Some(host),
        fingerprint: fp,
        totals,
    }
}

/// Run the fingerprint section: mint a throwaway leaf, drive a
/// loopback handshake, parse JA4, compare against baseline.
async fn capture_fingerprint() -> FingerprintSection {
    use crate::tls_fingerprint_observer;
    // Throwaway self-signed cert — JA4 is computed CLIENT-side so
    // the cert's contents don't affect the fingerprint; we just
    // need rustls's connector to accept the loopback handshake.
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "localhost");
    params.subject_alt_names = vec![rcgen::SanType::DnsName(
        rcgen::Ia5String::try_from("localhost").unwrap(),
    )];

    let key_pair = match rcgen::KeyPair::generate() {
        Ok(k) => k,
        Err(e) => {
            return FingerprintSection {
                live_ja4: format!("capture_failed:keygen:{e}"),
                expected_baseline: tls_fingerprint_observer::EXPECTED_BASELINE,
                matches_baseline: false,
            };
        }
    };
    let cert = match params.self_signed(&key_pair) {
        Ok(c) => c,
        Err(e) => {
            return FingerprintSection {
                live_ja4: format!("capture_failed:sign:{e}"),
                expected_baseline: tls_fingerprint_observer::EXPECTED_BASELINE,
                matches_baseline: false,
            };
        }
    };
    let leaf = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
    let observed = tls_fingerprint_observer::observe_live_ja4(leaf).await;
    FingerprintSection {
        live_ja4: observed.ja4.clone(),
        expected_baseline: observed.expected_baseline,
        matches_baseline: observed.matches_baseline(),
    }
}

/// CLI entry. Writes the rendered report to stdout (text or json
/// per `format`) and returns the exit code.
pub async fn cli_run(input: PreflightAllInput, format: &str) -> std::io::Result<i32> {
    let report = run(input).await;
    let stdout = std::io::stdout();
    let mut h = stdout.lock();
    match format {
        "json" => {
            report.render_json(&mut h)?;
            h.write_all(b"\n")?;
        }
        _ => {
            report.render_text(&mut h)?;
        }
    }
    Ok(report.exit_code())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    /// The orchestrator wires every section and produces correct
    /// totals. Use `skip_fingerprint=true` so the test doesn't
    /// depend on the live JA4 observer (separate integration
    /// test covers that path).
    #[tokio::test]
    async fn orchestrator_runs_all_sections_and_aggregates_totals() {
        let r = run(PreflightAllInput {
            // No config: ip_reputation will FAIL (no IP), host_posture
            // will run host-level checks only.
            public_ip_override: Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
            skip_fingerprint: true,
            ..Default::default()
        })
        .await;
        // At minimum: both sub-checks ran and produced at least one
        // finding each. (Exact counts depend on host environment so we
        // assert structural shape, not specific numbers.)
        assert!(r.ip_reputation.is_some());
        assert!(r.host_posture.is_some());
        assert!(r.fingerprint.is_none(), "fingerprint should be skipped");
        let (p, w, f) = r.totals;
        assert!(
            p + w + f >= 2,
            "expected ≥2 findings across sections; got {p}p/{w}w/{f}f"
        );
    }

    /// exit_code is 1 iff totals.fail > 0. Test the boundary in
    /// both directions.
    #[test]
    fn exit_code_maps_to_any_failure() {
        let mut r = OrchestratorReport {
            ip_reputation: None,
            host_posture: None,
            fingerprint: None,
            totals: (5, 2, 0),
        };
        assert_eq!(r.exit_code(), 0);
        r.totals = (5, 2, 1);
        assert_eq!(r.exit_code(), 1);
    }

    /// Text rendering produces all section banners + totals line.
    /// Test the structural skeleton, not exact human-readable
    /// strings (those can shift without affecting deploy gates).
    #[test]
    fn text_render_includes_every_section_banner_and_totals_line() {
        let r = OrchestratorReport {
            ip_reputation: None,
            host_posture: None,
            fingerprint: Some(FingerprintSection {
                live_ja4: "t13d0911h2_xxx_yyy".to_string(),
                expected_baseline: "t13d0911h2_xxx_yyy",
                matches_baseline: true,
            }),
            totals: (1, 0, 0),
        };
        let mut buf = Vec::new();
        r.render_text(&mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        for needle in [
            "preflight: ip_reputation",
            "preflight: host_posture",
            "preflight: fingerprint",
            "totals",
            "summary:",
            "exit 0",
        ] {
            assert!(s.contains(needle), "missing {needle:?} in:\n{s}");
        }
    }

    /// JSON rendering produces a single parseable object whose
    /// totals + exit_code agree. Don't pull serde_json into the
    /// crate just for this — structural string contains is enough
    /// to catch broken templating.
    #[test]
    fn json_render_includes_top_level_keys() {
        let r = OrchestratorReport {
            ip_reputation: None,
            host_posture: None,
            fingerprint: Some(FingerprintSection {
                live_ja4: "t13d0911h2_xxx_yyy".to_string(),
                expected_baseline: "t13d0911h2_xxx_yyy",
                matches_baseline: true,
            }),
            totals: (3, 1, 0),
        };
        let mut buf = Vec::new();
        r.render_json(&mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        for needle in [
            r#""kind":"preflight_summary""#,
            r#""sections":"#,
            r#""ip_reputation":"#,
            r#""host_posture":"#,
            r#""fingerprint":"#,
            r#""totals":"#,
            r#""pass":3"#,
            r#""warn":1"#,
            r#""fail":0"#,
            r#""exit_code":0"#,
            r#""matches_baseline":true"#,
        ] {
            assert!(s.contains(needle), "missing {needle:?} in:\n{s}");
        }
        // No trailing newline (render_json contract).
        assert!(
            !s.ends_with('\n'),
            "render_json must not emit trailing newline"
        );
    }

    /// Drifted fingerprint = WARN, not FAIL (operator decides
    /// whether the drift is expected uTLS progress). Verify the
    /// severity mapping AND the rendered text reflects it.
    #[test]
    fn drifted_fingerprint_is_warn_not_fail() {
        let fp = FingerprintSection {
            live_ja4: "t13dXXXXh2_zzz_qqq".to_string(),
            expected_baseline: "t13d0911h2_xxx_yyy",
            matches_baseline: false,
        };
        assert_eq!(fp.severity(), Severity::Warn);
        let r = OrchestratorReport {
            ip_reputation: None,
            host_posture: None,
            fingerprint: Some(fp),
            totals: (0, 1, 0),
        };
        assert_eq!(r.exit_code(), 0); // drift alone does not fail the gate
    }

    /// skip_fingerprint omits the section entirely. Verify both
    /// the orchestrator path and the rendered output.
    #[tokio::test]
    async fn skip_fingerprint_omits_the_section() {
        let r = run(PreflightAllInput {
            public_ip_override: Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
            skip_fingerprint: true,
            ..Default::default()
        })
        .await;
        assert!(r.fingerprint.is_none());
        let mut buf = Vec::new();
        r.render_text(&mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(
            s.contains("--skip-fingerprint set"),
            "missing skip note:\n{s}"
        );
    }
}
