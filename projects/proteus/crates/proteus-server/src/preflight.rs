//! `proteus-server preflight --check-ip-reputation` — offline
//! IP-reputation classifier driver.
//!
//! Wraps [`crate::ip_reputation::classify`] in a CLI suitable for
//! Terraform / Ansible / CI pre-deploy gates. Exits 0 when the IP
//! classifies as PASS or WARN (operator may proceed with informed
//! consent); 1 on FAIL (config error — bound to a loopback / RFC
//! 1918 / CGNAT address — OR operator watchlist hit).
//!
//! ## How the IP is determined
//!
//! Priority order:
//!
//! 1. **`--public-ip <ip>`** — operator-supplied literal. Always wins.
//! 2. **Listen address from `--config`** — when `listen_alpha` or
//!    `listen_beta` is bound to a non-`0.0.0.0` / non-`[::]` literal,
//!    that IP is the deployment's outbound IP. Use it.
//! 3. **Failure to determine** — when both above are absent and the
//!    config binds to `0.0.0.0`/`[::]`, the preflight emits a FAIL
//!    asking the operator to provide `--public-ip` explicitly. We
//!    DO NOT auto-discover via STUN / external HTTP — see
//!    `ip_reputation.rs` discussion: external probes leak operator
//!    metadata. The operator must consciously decide which IP to check.
//!
//! ## Why not auto-discover via the OS interfaces
//!
//! `getifaddrs(3)` works on a VPS where eth0 has the public IP
//! directly, but breaks on NAT / VPN-overlay / multi-homed deploys.
//! Asking the operator to specify is the only correct answer; a
//! best-effort interface scan would silently classify the WRONG IP
//! on common topologies (Hetzner with floating IP, GCE without
//! external IP attached to the VM, k8s pod with cluster-internal
//! address).

use std::fmt;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use crate::config::ServerConfig;
use crate::ip_reputation::{classify, IpClass, Severity, WatchlistRule};

/// Output of a preflight run. Mirrors `validate::PreflightReport`'s
/// shape so the binary's stdout pipeline stays consistent.
#[derive(Debug, Clone)]
pub struct PreflightReport {
    pub lines: Vec<ReportLine>,
}

#[derive(Debug, Clone)]
pub struct ReportLine {
    pub severity: Severity,
    pub message: String,
}

impl PreflightReport {
    fn push(&mut self, severity: Severity, message: impl Into<String>) {
        self.lines.push(ReportLine {
            severity,
            message: message.into(),
        });
    }

    /// True iff any line is `Severity::Fail`.
    #[must_use]
    pub fn has_failures(&self) -> bool {
        self.lines.iter().any(|l| l.severity == Severity::Fail)
    }

    /// `(passes, warns, fails)`.
    #[must_use]
    pub fn counts(&self) -> (usize, usize, usize) {
        let (mut p, mut w, mut f) = (0, 0, 0);
        for l in &self.lines {
            match l.severity {
                Severity::Pass => p += 1,
                Severity::Warn => w += 1,
                Severity::Fail => f += 1,
            }
        }
        (p, w, f)
    }
}

impl fmt::Display for PreflightReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for l in &self.lines {
            writeln!(f, "  {sev}  {msg}", sev = l.severity, msg = l.message)?;
        }
        let (p, w, fail) = self.counts();
        writeln!(f, "\nsummary: {p} pass, {w} warn, {fail} fail")
    }
}

/// Input bundle for [`run`]. All fields are optional so the caller
/// (CLI or test harness) can construct the source-of-truth they need.
#[derive(Debug, Default)]
pub struct PreflightInput {
    pub config_path: Option<PathBuf>,
    pub public_ip_override: Option<IpAddr>,
    pub watchlist_path: Option<PathBuf>,
}

/// Run the IP-reputation preflight against the supplied inputs.
///
/// Order of operations:
/// 1. Load operator watchlist if `--watchlist` is set. Failure to
///    read = FAIL (operator probably wants the file enforced, not
///    silently ignored).
/// 2. Determine the IP to check (see module doc).
/// 3. Call [`classify`] and report the result.
pub fn run(input: PreflightInput) -> PreflightReport {
    let mut r = PreflightReport { lines: Vec::new() };

    // Step 1: watchlist
    let watchlist: Vec<WatchlistRule> = match &input.watchlist_path {
        Some(p) => match crate::ip_reputation::load_watchlist_from_file(p) {
            Ok(rules) => {
                r.push(
                    Severity::Pass,
                    format!(
                        "watchlist loaded: {} ({} rule{})",
                        p.display(),
                        rules.len(),
                        if rules.len() == 1 { "" } else { "s" }
                    ),
                );
                rules
            }
            Err(e) => {
                r.push(
                    Severity::Fail,
                    format!("watchlist load failed: {e} — abort preflight"),
                );
                return r;
            }
        },
        None => Vec::new(),
    };

    // Step 2: determine the IP.
    let (ip, source) = match determine_ip(&input, &mut r) {
        Some(t) => t,
        None => return r, // determine_ip already pushed the FAIL line.
    };
    r.push(
        Severity::Pass,
        format!("checking IP {ip} (source: {source})"),
    );

    // Step 3: classify.
    let cls = classify(ip, &watchlist);
    let sev = cls.class.severity();
    let pretty_class = match &cls.class {
        IpClass::Special { kind } => format!("Special({kind})"),
        IpClass::LikelyCommercialCloud { provider } => {
            format!("LikelyCommercialCloud({provider})")
        }
        IpClass::LikelyResidential => "LikelyResidential".to_string(),
        IpClass::OperatorBlocked { reason } => format!("OperatorBlocked({reason})"),
    };
    r.push(sev, format!("{pretty_class}: {}", cls.rationale));

    // Step 4: actionable guidance for the operator.
    match (&cls.class, sev) {
        (_, Severity::Pass) => r.push(
            Severity::Pass,
            "preflight CLEAN — proceed with deployment. \
             Remember: a CLEAN classification is not a guarantee against \
             real-time GFW probing; monitor for breakage post-deploy.",
        ),
        (IpClass::LikelyCommercialCloud { provider }, Severity::Warn) => r.push(
            Severity::Warn,
            format!(
                "IP class is high-risk ({provider}). Acceptable if the VPS is freshly \
                 provisioned and you accept the IP-rotation overhead — but for a long-lived \
                 personal node, prefer a less-collected provider (residential proxy, smaller \
                 hosting, or a non-cloud bare-metal). If you proceed, set up `proteus-server \
                 admin status` alerting + rotate IPs on first sustained breakage report."
            ),
        ),
        (IpClass::Special { .. }, Severity::Fail) => r.push(
            Severity::Fail,
            "config error: cannot deploy a public proxy on a special-use IP. Fix `listen_alpha` \
             / `listen_beta` to bind to the VPS's actual public address, OR provide \
             `--public-ip <ip>` explicitly if you're preflighting before the listener exists."
                .to_string(),
        ),
        (IpClass::OperatorBlocked { reason }, Severity::Fail) => r.push(
            Severity::Fail,
            format!(
                "operator watchlist refuses this IP (reason: {reason}). \
                 If this was intentional, remove the rule from the watchlist; otherwise \
                 deploy on a different IP."
            ),
        ),
        _ => {}
    }
    r
}

#[derive(Debug, Clone, Copy)]
enum IpSource {
    OperatorOverride,
    ConfigListenAlpha,
    ConfigListenBeta,
}

impl fmt::Display for IpSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            IpSource::OperatorOverride => "--public-ip override",
            IpSource::ConfigListenAlpha => "config listen_alpha (literal bind)",
            IpSource::ConfigListenBeta => "config listen_beta (literal bind)",
        })
    }
}

fn determine_ip(input: &PreflightInput, r: &mut PreflightReport) -> Option<(IpAddr, IpSource)> {
    // Priority 1: operator override.
    if let Some(ip) = input.public_ip_override {
        return Some((ip, IpSource::OperatorOverride));
    }

    // Priority 2: derive from config listen addresses.
    let cfg_path = match &input.config_path {
        Some(p) => p,
        None => {
            r.push(
                Severity::Fail,
                "no --public-ip and no --config supplied — preflight has nothing to check. \
                 Provide one of: `--public-ip <ip>` (preferred for fresh VPS preflight), \
                 OR `--config /etc/proteus/server.yaml` (when the config's listen address \
                 is bound to a literal public IP).",
            );
            return None;
        }
    };
    let cfg = match load_config(cfg_path) {
        Ok(c) => c,
        Err(e) => {
            r.push(Severity::Fail, format!("config load failed: {e}"));
            return None;
        }
    };

    if let Some((ip, src)) = extract_listen_ip(&cfg) {
        return Some((ip, src));
    }
    r.push(
        Severity::Fail,
        format!(
            "config {} binds listen_alpha to 0.0.0.0 / [::] (wildcard); the preflight \
             cannot infer the public IP from the wildcard bind. Re-run with \
             `--public-ip <vps-public-ip>` to specify which IP to classify.",
            cfg_path.display(),
        ),
    );
    None
}

fn load_config(path: &Path) -> Result<ServerConfig, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("io {}: {e}", path.display()))?;
    let cfg: ServerConfig = serde_yaml::from_str(&text).map_err(|e| format!("yaml: {e}"))?;
    Ok(cfg)
}

fn extract_listen_ip(cfg: &ServerConfig) -> Option<(IpAddr, IpSource)> {
    if let Some(ip) = literal_listen_ip(&cfg.listen_alpha) {
        return Some((ip, IpSource::ConfigListenAlpha));
    }
    if let Some(beta) = &cfg.listen_beta {
        if let Some(ip) = literal_listen_ip(beta) {
            return Some((ip, IpSource::ConfigListenBeta));
        }
    }
    None
}

/// Return Some(ip) only when the listen address is bound to a
/// non-wildcard literal (i.e., the operator's actual public IP). A
/// `0.0.0.0:8443` or `[::]:8443` bind returns None because the
/// public IP is implicit (varies by interface) — we can't pick the
/// "right" one without operator input.
fn literal_listen_ip(addr: &str) -> Option<IpAddr> {
    let sa: std::net::SocketAddr = addr.parse().ok()?;
    let ip = sa.ip();
    if ip.is_unspecified() {
        return None;
    }
    Some(ip)
}

/// CLI entry point. Returns exit code (0 on PASS/WARN-only, 1 on FAIL).
pub fn cli_run(input: PreflightInput) -> std::io::Result<i32> {
    let report = run(input);
    let stdout = std::io::stdout();
    let mut h = stdout.lock();
    write!(h, "{report}")?;
    Ok(if report.has_failures() { 1 } else { 0 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn write_min_yaml(dir: &Path, listen_alpha: &str) -> PathBuf {
        let p = dir.join("server.yaml");
        std::fs::write(
            &p,
            format!(
                "listen_alpha: \"{listen_alpha}\"\n\
                 keys:\n  \
                     mlkem_pk: ./k.pk\n  \
                     mlkem_sk: ./k.sk\n  \
                     x25519_pk: ./x.pk\n  \
                     x25519_sk: ./x.sk\n",
            ),
        )
        .unwrap();
        p
    }

    fn tmp(suffix: &str) -> PathBuf {
        let base = std::env::var("CARGO_TARGET_TMPDIR").unwrap_or_else(|_| "/tmp".to_string());
        let p = PathBuf::from(format!(
            "{base}/proteus-preflight-{suffix}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn no_ip_and_no_config_fails_with_actionable_message() {
        let r = run(PreflightInput::default());
        assert!(r.has_failures());
        let last_fail = r
            .lines
            .iter()
            .rev()
            .find(|l| l.severity == Severity::Fail)
            .unwrap();
        assert!(
            last_fail.message.contains("--public-ip") && last_fail.message.contains("--config"),
            "FAIL message should point at both knobs; got {:?}",
            last_fail.message,
        );
    }

    #[test]
    fn public_ip_override_wins_over_config() {
        // Config binds to a special-use address (which would FAIL),
        // but operator override of 1.2.3.4 should be the IP checked.
        let dir = tmp("override");
        let _y = write_min_yaml(&dir, "127.0.0.1:8443");
        let r = run(PreflightInput {
            config_path: None,
            public_ip_override: Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
            watchlist_path: None,
        });
        assert!(!r.has_failures(), "override should bypass config: {r}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn loopback_listen_address_fails_preflight() {
        let dir = tmp("loopback");
        let yaml = write_min_yaml(&dir, "127.0.0.1:8443");
        let r = run(PreflightInput {
            config_path: Some(yaml),
            public_ip_override: None,
            watchlist_path: None,
        });
        assert!(r.has_failures(), "{r}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wildcard_bind_without_override_fails_with_guidance() {
        let dir = tmp("wildcard");
        let yaml = write_min_yaml(&dir, "0.0.0.0:8443");
        let r = run(PreflightInput {
            config_path: Some(yaml),
            public_ip_override: None,
            watchlist_path: None,
        });
        assert!(r.has_failures());
        let msg = r
            .lines
            .iter()
            .find(|l| l.severity == Severity::Fail && l.message.contains("wildcard"))
            .expect("wildcard message expected");
        assert!(msg.message.contains("--public-ip"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn literal_listen_ip_is_picked_up() {
        let dir = tmp("literal");
        let yaml = write_min_yaml(&dir, "203.0.113.7:8443");
        let r = run(PreflightInput {
            config_path: Some(yaml),
            public_ip_override: None,
            watchlist_path: None,
        });
        // 203.0.113.7 is documentation range → Special → FAIL
        // (intentional: this is how operators catch the "I used a
        // placeholder example IP" mistake).
        assert!(r.has_failures());
        let class_line = r
            .lines
            .iter()
            .find(|l| l.message.starts_with("Special"))
            .expect("Special classification expected for 203.0.113.7");
        assert!(class_line.message.contains("documentation"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn known_commercial_cloud_ip_passes_with_warn() {
        let dir = tmp("cloud");
        // 138.197.x.x is DigitalOcean per our static table.
        let yaml = write_min_yaml(&dir, "138.197.42.42:8443");
        let r = run(PreflightInput {
            config_path: Some(yaml),
            public_ip_override: None,
            watchlist_path: None,
        });
        // WARN is not a failure.
        assert!(!r.has_failures(), "{r}");
        let (_, w, _) = r.counts();
        assert!(w >= 1, "expected ≥1 WARN line: {r}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn likely_residential_ip_passes_clean() {
        let r = run(PreflightInput {
            config_path: None,
            public_ip_override: Some("8.8.8.8".parse().unwrap()),
            watchlist_path: None,
        });
        assert!(!r.has_failures(), "{r}");
        // CLEAN guidance line must be present.
        let clean = r
            .lines
            .iter()
            .any(|l| l.message.contains("preflight CLEAN"));
        assert!(clean, "expected CLEAN guidance: {r}");
    }

    #[test]
    fn watchlist_blocks_otherwise_clean_ip() {
        let dir = tmp("watchlist");
        let wl = dir.join("watch.txt");
        std::fs::write(&wl, "8.8.8.0/24  burned last quarter\n").unwrap();
        let r = run(PreflightInput {
            config_path: None,
            public_ip_override: Some("8.8.8.8".parse().unwrap()),
            watchlist_path: Some(wl),
        });
        assert!(r.has_failures(), "{r}");
        let fail_msg = r
            .lines
            .iter()
            .find(|l| l.severity == Severity::Fail && l.message.contains("watchlist"))
            .expect("expected watchlist FAIL");
        assert!(fail_msg.message.contains("burned last quarter"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bad_watchlist_file_fails_fast() {
        let dir = tmp("bad-watch");
        let wl = dir.join("watch.txt");
        std::fs::write(&wl, "not-a-cidr reason\n").unwrap();
        let r = run(PreflightInput {
            config_path: None,
            public_ip_override: Some("8.8.8.8".parse().unwrap()),
            watchlist_path: Some(wl),
        });
        assert!(r.has_failures());
        let fail_msg = r
            .lines
            .iter()
            .find(|l| l.severity == Severity::Fail && l.message.contains("watchlist load failed"))
            .expect("expected watchlist load FAIL");
        assert!(fail_msg.message.contains("abort"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ipv6_listen_address_works() {
        let dir = tmp("v6");
        let yaml = write_min_yaml(&dir, "[2001:db8::1]:8443");
        let r = run(PreflightInput {
            config_path: Some(yaml),
            public_ip_override: None,
            watchlist_path: None,
        });
        // documentation range → Special → FAIL
        assert!(r.has_failures(), "{r}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
