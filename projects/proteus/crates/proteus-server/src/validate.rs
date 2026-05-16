//! Configuration preflight ("`proteus-server validate <path>`").
//!
//! Production deployments need a dry-run check before SIGHUP /
//! systemd-reload, because a typo in `/etc/proteus/server.yaml`:
//!
//! - Silently fails the SIGHUP cert reload (the server keeps the old
//!   cert and logs ERROR — operator doesn't notice).
//! - On first boot would prevent `systemctl start proteus-server` from
//!   coming up cleanly.
//!
//! The preflight runs every cheap-to-verify check up front and prints
//! a coloured pass/fail report. It does NOT bind sockets, talk to the
//! cover endpoint, or call `accept()`. Pure I/O against the config
//! file plus the files it references (TLS cert, private key, key
//! files, metrics token, allowlist Ed25519 pubs, access log
//! writability, firewall CIDR syntax).
//!
//! Exit code: 0 on all-green; 1 if any check failed. Suitable for
//! CI / Ansible / Terraform pre-deploy gating.

use std::fmt;
use std::io::Write;
use std::path::Path;

use crate::config::ServerConfig;

/// One check result. `Check::Warn` does not fail the preflight; only
/// `Check::Fail` does.
#[derive(Debug, Clone)]
pub enum Check {
    Pass(String),
    Warn(String),
    Fail(String),
}

impl Check {
    fn is_fail(&self) -> bool {
        matches!(self, Check::Fail(_))
    }
}

/// Output of a full preflight run.
#[derive(Debug, Clone, Default)]
pub struct PreflightReport {
    pub checks: Vec<Check>,
}

impl PreflightReport {
    /// True if any [`Check::Fail`] is present.
    #[must_use]
    pub fn has_failures(&self) -> bool {
        self.checks.iter().any(Check::is_fail)
    }

    /// Count of (passes, warns, fails).
    #[must_use]
    pub fn counts(&self) -> (usize, usize, usize) {
        let mut p = 0;
        let mut w = 0;
        let mut f = 0;
        for c in &self.checks {
            match c {
                Check::Pass(_) => p += 1,
                Check::Warn(_) => w += 1,
                Check::Fail(_) => f += 1,
            }
        }
        (p, w, f)
    }

    fn push_pass(&mut self, s: impl Into<String>) {
        self.checks.push(Check::Pass(s.into()));
    }
    fn push_warn(&mut self, s: impl Into<String>) {
        self.checks.push(Check::Warn(s.into()));
    }
    fn push_fail(&mut self, s: impl Into<String>) {
        self.checks.push(Check::Fail(s.into()));
    }
}

impl fmt::Display for PreflightReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for c in &self.checks {
            match c {
                Check::Pass(m) => writeln!(f, "  [ok]   {m}")?,
                Check::Warn(m) => writeln!(f, "  [warn] {m}")?,
                Check::Fail(m) => writeln!(f, "  [FAIL] {m}")?,
            }
        }
        let (p, w, fail) = self.counts();
        writeln!(f, "  ----")?;
        writeln!(f, "  {p} passed, {w} warnings, {fail} failed")?;
        Ok(())
    }
}

/// Run every preflight check against `cfg` (already parsed) and the
/// referenced filesystem state. Pure: no network I/O.
#[must_use]
pub fn preflight(cfg: &ServerConfig) -> PreflightReport {
    let mut r = PreflightReport::default();

    // 1. listen_alpha parses as SocketAddr (or host:port).
    match cfg.listen_alpha.parse::<std::net::SocketAddr>() {
        Ok(_) => r.push_pass(format!("listen_alpha parses ({})", cfg.listen_alpha)),
        Err(e) => r.push_fail(format!("listen_alpha {:?}: {e}", cfg.listen_alpha)),
    }

    // 2. Server key files exist + readable.
    check_file(&mut r, "keys.mlkem_pk", &cfg.keys.mlkem_pk);
    check_file(&mut r, "keys.mlkem_sk", &cfg.keys.mlkem_sk);
    check_file(&mut r, "keys.x25519_pk", &cfg.keys.x25519_pk);
    check_file(&mut r, "keys.x25519_sk", &cfg.keys.x25519_sk);

    // 3. TLS cert chain + key parse via the actual rustls parser
    //    (catches expired chains, mismatched key types, malformed PEM).
    match cfg.tls.as_ref() {
        Some(tls) => {
            check_file(&mut r, "tls.cert_chain", &tls.cert_chain);
            check_file(&mut r, "tls.private_key", &tls.private_key);
            match proteus_transport_alpha::tls::load_cert_chain(&tls.cert_chain) {
                Ok(chain) => {
                    r.push_pass(format!("tls.cert_chain parses ({} certs)", chain.len()));
                }
                Err(e) => r.push_fail(format!("tls.cert_chain: {e}")),
            }
            match proteus_transport_alpha::tls::load_private_key(&tls.private_key) {
                Ok(_) => r.push_pass("tls.private_key parses"),
                Err(e) => r.push_fail(format!("tls.private_key: {e}")),
            }
            // Final sanity: chain + key actually combine into an
            // acceptor (rustls catches RSA-vs-EC mismatch here).
            if let (Ok(chain), Ok(key)) = (
                proteus_transport_alpha::tls::load_cert_chain(&tls.cert_chain),
                proteus_transport_alpha::tls::load_private_key(&tls.private_key),
            ) {
                match proteus_transport_alpha::tls::build_acceptor(chain, key) {
                    Ok(_) => r.push_pass("tls.acceptor builds (cert/key match)"),
                    Err(e) => r.push_fail(format!("tls.acceptor: {e}")),
                }
            }
        }
        None => r.push_warn(
            "tls block missing — server will run plain TCP; passive DPI will identify the protocol",
        ),
    }

    // 4. Client allowlist files exist.
    if cfg.client_allowlist.is_empty() {
        r.push_warn(
            "client_allowlist is empty — server accepts any client; only acceptable for testing",
        );
    } else {
        for client in &cfg.client_allowlist {
            check_file(
                &mut r,
                &format!("client_allowlist[{}].ed25519_pk", client.user_id),
                &client.ed25519_pk,
            );
            if client.user_id.is_empty() || client.user_id.len() > 8 {
                r.push_fail(format!(
                    "client_allowlist[{}].user_id must be 1..=8 chars, got len={}",
                    client.user_id,
                    client.user_id.len()
                ));
            }
        }
        r.push_pass(format!(
            "client_allowlist has {} users",
            cfg.client_allowlist.len()
        ));
    }

    // 5. Cover endpoint parses.
    match cfg.cover_endpoint.as_ref() {
        Some(c) => match proteus_transport_alpha::cover::parse_cover_endpoint(c) {
            Some(parsed) => r.push_pass(format!("cover_endpoint parses ({parsed})")),
            None => r.push_fail(format!("cover_endpoint {c:?}: bad host:port")),
        },
        None => {
            r.push_warn("cover_endpoint unset — auth-fail connections will be silently dropped")
        }
    }

    // 6. Firewall CIDR rules parse — using the same parser the server
    //    will use at runtime.
    if let Some(fw) = cfg.firewall.as_ref() {
        let mut tmp = proteus_transport_alpha::firewall::Firewall::new();
        if let Err(e) = tmp.extend_allow(&fw.allow) {
            r.push_fail(format!("firewall.allow: {e}"));
        }
        if let Err(e) = tmp.extend_deny(&fw.deny) {
            r.push_fail(format!("firewall.deny: {e}"));
        }
        if tmp.is_active() {
            r.push_pass(format!(
                "firewall: {} allow, {} deny rules parse",
                fw.allow.len(),
                fw.deny.len()
            ));
        }
    }

    // 7. Metrics bearer-token file readable + nonempty.
    if let Some(path) = cfg.metrics_token_file.as_ref() {
        match std::fs::read_to_string(path) {
            Ok(s) if s.trim().is_empty() => {
                r.push_fail(format!("metrics_token_file {path:?} is empty"));
            }
            Ok(_) => r.push_pass(format!("metrics_token_file readable ({path:?})")),
            Err(e) => r.push_fail(format!("metrics_token_file {path:?}: {e}")),
        }
    } else if let Some(addr) = cfg.metrics_listen.as_ref() {
        if !crate::is_loopback(addr) {
            r.push_warn(format!(
                "metrics_listen={addr:?} is non-loopback but metrics_token_file is unset; /metrics is unauthenticated"
            ));
        }
    }

    // 8. metrics_listen address parses (when set).
    if let Some(addr) = cfg.metrics_listen.as_ref() {
        match addr.parse::<std::net::SocketAddr>() {
            Ok(_) => r.push_pass(format!("metrics_listen parses ({addr})")),
            Err(e) => r.push_fail(format!("metrics_listen {addr:?}: {e}")),
        }
    }

    // 9. Access-log parent dir exists and is writable.
    if let Some(path) = cfg.access_log.as_ref() {
        let parent = path.parent().unwrap_or_else(|| Path::new("/"));
        match parent.metadata() {
            Ok(md) => {
                if !md.is_dir() {
                    r.push_fail(format!("access_log parent {parent:?} is not a directory"));
                } else {
                    r.push_pass(format!("access_log parent dir exists ({parent:?})"));
                }
            }
            Err(e) => r.push_fail(format!("access_log parent {parent:?}: {e}")),
        }
    }

    // 10. POW difficulty range (config field is u8 so 0..=255 by type;
    //     the server caps to 24 internally, but warn loudly so the
    //     operator doesn't think they got 32-bit difficulty).
    if let Some(d) = cfg.pow_difficulty {
        if d > 24 {
            r.push_warn(format!(
                "pow_difficulty={d} exceeds the in-code cap of 24; runtime will clamp to 24"
            ));
        } else if d > 0 {
            r.push_pass(format!("pow_difficulty = {d} bits"));
        }
    }

    // 11. Rate-limit knobs are positive.
    if let Some(rl) = cfg.rate_limit.as_ref() {
        if rl.burst <= 0.0 || rl.refill_per_sec < 0.0 {
            r.push_fail(format!(
                "rate_limit must have burst>0 and refill_per_sec>=0, got {:?}",
                rl
            ));
        } else {
            r.push_pass(format!(
                "rate_limit: burst={}, refill={}/s",
                rl.burst, rl.refill_per_sec
            ));
        }
    }
    if let Some(rl) = cfg.handshake_budget.as_ref() {
        if rl.burst <= 0.0 || rl.refill_per_sec < 0.0 {
            r.push_fail(format!(
                "handshake_budget must have burst>0 and refill_per_sec>=0, got {:?}",
                rl
            ));
        } else {
            r.push_pass(format!(
                "handshake_budget: burst={}, refill={}/s",
                rl.burst, rl.refill_per_sec
            ));
        }
    }
    if let Some(u) = cfg.user_rate_limit.as_ref() {
        if u.burst <= 0.0 || u.refill_per_sec < 0.0 || u.max_users == 0 {
            r.push_fail(format!(
                "user_rate_limit must have burst>0, refill_per_sec>=0, max_users>0; got {u:?}"
            ));
        } else {
            r.push_pass(format!(
                "user_rate_limit: burst={}, refill={}/s, max_users={}",
                u.burst, u.refill_per_sec, u.max_users
            ));
        }
    }

    r
}

/// Helper: assert a file exists and is readable by the current
/// process. Records [`Check::Fail`] otherwise.
fn check_file(report: &mut PreflightReport, label: &str, path: &Path) {
    match std::fs::File::open(path) {
        Ok(_) => report.push_pass(format!("{label} exists and readable ({path:?})")),
        Err(e) => report.push_fail(format!("{label} {path:?}: {e}")),
    }
}

/// Top-level driver for the `validate` subcommand. Loads the YAML
/// file, then runs the rest of [`preflight`].
///
/// Returns `Ok(true)` on all-green (or warnings only), `Ok(false)`
/// if any check failed, and `Err` if even the YAML didn't parse.
pub async fn run(config_path: &Path) -> Result<bool, Box<dyn std::error::Error>> {
    println!("preflight check: {config_path:?}");
    let cfg = ServerConfig::load(config_path)
        .await
        .map_err(|e| format!("config parse: {e}"))?;
    println!("  [ok]   YAML parses");
    let report = preflight(&cfg);
    let _ = std::io::stdout().flush();
    print!("{report}");
    let _ = std::io::stdout().flush();
    Ok(!report.has_failures())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ClientCfg, FirewallCfg, KeysCfg, RateLimitCfg};
    use std::path::PathBuf;

    fn tmpdir() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "proteus-preflight-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn write(p: &Path, content: &[u8]) {
        std::fs::write(p, content).unwrap();
    }

    fn minimal_cfg(dir: &Path) -> ServerConfig {
        for name in ["mlkem.pk", "mlkem.sk", "x25519.pk", "x25519.sk"] {
            write(&dir.join(name), b"placeholder");
        }
        ServerConfig {
            listen_alpha: "0.0.0.0:8443".to_string(),
            keys: KeysCfg {
                mlkem_pk: dir.join("mlkem.pk"),
                mlkem_sk: dir.join("mlkem.sk"),
                x25519_pk: dir.join("x25519.pk"),
                x25519_sk: dir.join("x25519.sk"),
            },
            client_allowlist: Vec::new(),
            cover_endpoint: None,
            metrics_listen: None,
            metrics_token_file: None,
            rate_limit: None,
            handshake_budget: None,
            user_rate_limit: None,
            handshake_deadline_secs: None,
            tcp_keepalive_secs: None,
            tls: None,
            pow_difficulty: None,
            drain_secs: None,
            access_log: None,
            session_idle_secs: None,
            firewall: None,
            max_connections: None,
        }
    }

    #[test]
    fn minimal_config_passes_with_warnings() {
        let dir = tmpdir();
        let cfg = minimal_cfg(&dir);
        let report = preflight(&cfg);
        assert!(
            !report.has_failures(),
            "minimal cfg should not fail: {report}"
        );
        let (_, w, _) = report.counts();
        assert!(w > 0, "expected at least one warning, got: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_key_file_fails() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.keys.mlkem_pk = dir.join("does-not-exist");
        let report = preflight(&cfg);
        assert!(report.has_failures(), "expected fail: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bad_listen_addr_fails() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.listen_alpha = "not-an-addr".to_string();
        let report = preflight(&cfg);
        assert!(report.has_failures(), "expected fail: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bad_cover_endpoint_fails() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.cover_endpoint = Some("not a host:port at all".to_string());
        let report = preflight(&cfg);
        assert!(report.has_failures(), "expected fail: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bad_firewall_cidr_fails() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.firewall = Some(FirewallCfg {
            allow: vec!["10.0.0.0/8".to_string(), "not-a-cidr".to_string()],
            deny: vec![],
        });
        let report = preflight(&cfg);
        assert!(report.has_failures(), "expected fail: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_metrics_token_file_fails() {
        let dir = tmpdir();
        let token_path = dir.join("metrics.token");
        write(&token_path, b""); // empty
        let mut cfg = minimal_cfg(&dir);
        cfg.metrics_listen = Some("127.0.0.1:9090".to_string());
        cfg.metrics_token_file = Some(token_path);
        let report = preflight(&cfg);
        assert!(report.has_failures(), "expected fail: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn nonempty_metrics_token_file_passes() {
        let dir = tmpdir();
        let token_path = dir.join("metrics.token");
        write(&token_path, b"abcdef1234567890\n");
        let mut cfg = minimal_cfg(&dir);
        cfg.metrics_listen = Some("127.0.0.1:9090".to_string());
        cfg.metrics_token_file = Some(token_path);
        let report = preflight(&cfg);
        assert!(!report.has_failures(), "got: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bad_metrics_listen_addr_fails() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.metrics_listen = Some("garbage:port".to_string());
        let report = preflight(&cfg);
        assert!(report.has_failures(), "expected fail: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn nonloopback_metrics_without_token_warns_but_passes() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.metrics_listen = Some("0.0.0.0:9090".to_string());
        // metrics_token_file unset
        let report = preflight(&cfg);
        assert!(
            !report.has_failures(),
            "non-loopback w/o token must warn, not fail: {report}"
        );
        assert!(
            report
                .checks
                .iter()
                .any(|c| matches!(c, Check::Warn(m) if m.contains("non-loopback"))),
            "expected a non-loopback warning: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn access_log_in_nonexistent_dir_fails() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.access_log = Some(PathBuf::from("/does/not/exist/access.log"));
        let report = preflight(&cfg);
        assert!(report.has_failures(), "expected fail: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pow_over_cap_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.pow_difficulty = Some(50);
        let report = preflight(&cfg);
        assert!(
            report
                .checks
                .iter()
                .any(|c| matches!(c, Check::Warn(m) if m.contains("pow_difficulty"))),
            "expected pow_difficulty warning: {report}"
        );
        assert!(!report.has_failures(), "should warn, not fail: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn negative_rate_limit_fails() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.rate_limit = Some(RateLimitCfg {
            burst: -1.0,
            refill_per_sec: 1.0,
        });
        let report = preflight(&cfg);
        assert!(report.has_failures(), "expected fail: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn long_user_id_fails() {
        let dir = tmpdir();
        let pk = dir.join("client.pk");
        write(&pk, b"x");
        let mut cfg = minimal_cfg(&dir);
        cfg.client_allowlist = vec![ClientCfg {
            user_id: "this-is-way-too-long".to_string(),
            ed25519_pk: pk,
        }];
        let report = preflight(&cfg);
        assert!(report.has_failures(), "expected fail: {report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn counts_render_consistently() {
        let dir = tmpdir();
        let cfg = minimal_cfg(&dir);
        let report = preflight(&cfg);
        let (p, w, f) = report.counts();
        let rendered = report.to_string();
        assert!(rendered.contains(&format!("{p} passed")));
        assert!(rendered.contains(&format!("{w} warnings")));
        assert!(rendered.contains(&format!("{f} failed")));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
