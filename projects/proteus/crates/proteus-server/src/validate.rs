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
    // 1b. listen_beta parses (when set) AND cert/key resolution
    // policy is consistent (β-specific paths take precedence; α tls
    // fallback applies otherwise).
    if let Some(beta) = cfg.listen_beta.as_ref() {
        match beta.parse::<std::net::SocketAddr>() {
            Ok(_) => r.push_pass(format!("listen_beta parses ({beta})")),
            Err(e) => r.push_fail(format!("listen_beta {beta:?}: {e}")),
        }
        // The binary will refuse to start if neither β-specific nor
        // α-tls cert/key paths are available. Surface that here as a
        // FAIL so operators catch it pre-deploy.
        let beta_has_explicit = cfg.beta_cert_chain.is_some() && cfg.beta_private_key.is_some();
        let tls_fallback_available = cfg.tls.is_some();
        if !beta_has_explicit && !tls_fallback_available {
            r.push_fail(
                "listen_beta is set but no cert/key resolution path: \
                 set beta_cert_chain + beta_private_key, OR configure tls block",
            );
        }
        // If β-specific paths are partially set, that's a typo.
        if cfg.beta_cert_chain.is_some() != cfg.beta_private_key.is_some() {
            r.push_fail(
                "beta_cert_chain and beta_private_key must be either both set or both unset",
            );
        }
        // Make sure the resolved cert/key files actually load.
        let (cert_path, key_path) = match (
            cfg.beta_cert_chain.as_ref(),
            cfg.beta_private_key.as_ref(),
            cfg.tls.as_ref(),
        ) {
            (Some(c), Some(k), _) => (Some(c.clone()), Some(k.clone())),
            (_, _, Some(tls)) => (Some(tls.cert_chain.clone()), Some(tls.private_key.clone())),
            _ => (None, None),
        };
        if let (Some(c), Some(k)) = (cert_path, key_path) {
            match proteus_transport_alpha::tls::load_cert_chain(&c) {
                Ok(_) => r.push_pass(format!("β cert chain loads ({c:?})")),
                Err(e) => r.push_fail(format!("β cert chain {c:?}: {e}")),
            }
            match proteus_transport_alpha::tls::load_private_key(&k) {
                Ok(_) => r.push_pass(format!("β private key loads ({k:?})")),
                Err(e) => r.push_fail(format!("β private key {k:?}: {e}")),
            }
        }
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

    // 12+. Cross-field coherence checks: catches policy combinations
    // that pass per-field validation but interact badly at runtime.
    coherence_checks(cfg, &mut r);

    r
}

/// Cross-field coherence: catches typos and policy combinations that
/// look valid in isolation but make every client fail at runtime.
/// Mostly emits [`Check::Warn`] — these are *unlikely* misconfigurations
/// but the operator should see them rather than discover in prod.
fn coherence_checks(cfg: &ServerConfig, r: &mut PreflightReport) {
    // 12. PoW difficulty × handshake deadline.
    //
    // Rough cost model: at difficulty d, the *expected* SHA-256 hash
    // count to find a solution is 2^d. A modern laptop runs ~10 M
    // SHA-256/sec single-thread (we measured ~9-12 M across recent
    // ARM/Intel cores). Worst-case clients (slow mobiles) are 5-10×
    // slower. Treat 1 M hashes/sec as the floor.
    //
    // If the deadline is shorter than 2× the floor solve time, the
    // operator has probably misconfigured — most legit clients won't
    // finish PoW + KEX + sig in the budget.
    if let Some(d) = cfg.pow_difficulty {
        if d > 0 {
            let deadline = cfg.handshake_deadline_secs.unwrap_or(15);
            let expected_hashes = 1u64.checked_shl(u32::from(d.min(31))).unwrap_or(u64::MAX);
            // Floor: 1 M hashes/sec for the slowest legit clients.
            let floor_solve_secs = expected_hashes / 1_000_000;
            if floor_solve_secs * 2 > deadline {
                r.push_warn(format!(
                    "pow_difficulty={d} bits implies ~{floor_solve_secs}s solve time on slow \
                     mobile clients (1 M hashes/s floor); handshake_deadline_secs={deadline} \
                     leaves no margin. Either lower difficulty or raise the deadline.",
                ));
            } else {
                r.push_pass(format!(
                    "pow_difficulty + deadline coherent (floor solve ≈{floor_solve_secs}s, deadline {deadline}s)",
                ));
            }
        }
    }

    // 13. Per-IP rate-limit burst vs. per-user rate-limit burst.
    // The per-IP limit is supposed to BOUND the per-user limit
    // (multiple users share an IP under CGNAT). If per-user burst
    // exceeds per-IP burst, a single-IP user can never actually
    // reach their per-user quota — the IP limit fires first.
    if let (Some(ip_rl), Some(user_rl)) = (cfg.rate_limit.as_ref(), cfg.user_rate_limit.as_ref()) {
        if user_rl.burst > ip_rl.burst {
            r.push_warn(format!(
                "user_rate_limit.burst={} exceeds rate_limit.burst={} — single-IP users will \
                 never reach their per-user quota because the per-IP limit fires first. \
                 Either raise rate_limit.burst or lower user_rate_limit.burst.",
                user_rl.burst, ip_rl.burst,
            ));
        }
    }

    // 14. drain_secs configured but /metrics + /readyz not bound.
    // The graceful-drain path flips /readyz to 503 on SIGTERM so an
    // upstream load balancer stops sending traffic. Without
    // metrics_listen there's nothing for the LB to poll.
    if let Some(drain) = cfg.drain_secs {
        if drain > 0 && cfg.metrics_listen.is_none() {
            r.push_warn(format!(
                "drain_secs={drain} is set but metrics_listen is unset — no /readyz endpoint \
                 means upstream load balancers can't observe the drain. Either set \
                 metrics_listen or accept that drain is a server-internal flush only.",
            ));
        }
    }

    // 15. session_idle_secs < handshake_deadline_secs.
    // Idle bounds the *steady-state* session lifetime; deadline bounds
    // the *setup*. Idle smaller than deadline is almost certainly a
    // typo — would mean an established session can be reaped faster
    // than its handshake was allowed to take.
    let idle = cfg.session_idle_secs.unwrap_or(600);
    let deadline = cfg.handshake_deadline_secs.unwrap_or(15);
    if idle > 0 && idle < deadline {
        r.push_warn(format!(
            "session_idle_secs={idle} is less than handshake_deadline_secs={deadline}. \
             Sessions would be reaped while still finishing setup. Almost certainly a typo.",
        ));
    }

    // 16. max_connections < rate_limit.burst.
    // The per-IP rate limit's burst is the worst-case number of
    // simultaneous in-flight handshakes from one source. If
    // max_connections is smaller, a single source IP can saturate
    // the global cap by itself — defeating both layers.
    if let (Some(max_conn), Some(ip_rl)) = (cfg.max_connections, cfg.rate_limit.as_ref()) {
        let burst = ip_rl.burst.ceil() as usize;
        if max_conn < burst {
            r.push_warn(format!(
                "max_connections={max_conn} is below rate_limit.burst={burst} — one source IP \
                 can saturate the global concurrency cap by itself. Raise max_connections.",
            ));
        }
    }

    // 17. Firewall allow ∩ deny: an IP matching both is denied
    // (deny wins). Likely an operator typo where they thought
    // allow trumps deny.
    if let Some(fw) = cfg.firewall.as_ref() {
        // Naive O(n*m): only realistic for the small N these lists
        // ever have. A real conflict means the operator typoed the
        // same /32 into both lists.
        for d in &fw.deny {
            if fw.allow.contains(d) {
                r.push_warn(format!(
                    "firewall: rule {d:?} appears in both allow and deny — deny wins, so this \
                     IP is blocked. Likely an operator typo.",
                ));
            }
        }
    }

    // 18a. max_session_bytes must be at least 1 MiB.
    // Anything smaller breaks even a single HTTP page load.
    if let Some(cap) = cfg.max_session_bytes {
        if cap < 1024 * 1024 {
            r.push_warn(format!(
                "max_session_bytes={cap} is below 1 MiB — most HTTP pages won't load. \
                 Either set it to a sensible value (~50 GiB for streaming users, \
                 53687091200) or unset it.",
            ));
        }
    }

    // 18. cover_endpoint host == listen_alpha host: would loop
    // auth-fail traffic back into ourselves until both stack-bust.
    if let Some(cover) = cfg.cover_endpoint.as_ref() {
        // Compare host portions only (port may differ — e.g. 8443
        // vs cover on 443). A loopback bind catches the simplest
        // case.
        let listen_host = cfg
            .listen_alpha
            .rsplit_once(':')
            .map_or(cfg.listen_alpha.as_str(), |(h, _)| h);
        let cover_host = cover.rsplit_once(':').map_or(cover.as_str(), |(h, _)| h);
        if !listen_host.is_empty() && listen_host == cover_host {
            r.push_warn(format!(
                "cover_endpoint host {cover_host:?} matches listen_alpha host — auth-fail \
                 traffic would loop back into the server. Configure cover_endpoint to a \
                 distinct external HTTPS service (cloudflare/microsoft/apple).",
            ));
        }
        if listen_host == "0.0.0.0" || listen_host == "::" {
            // listen_alpha binds all interfaces; can't catch the
            // loopback case structurally. Best we can do is flag
            // common foot-guns.
            if cover_host == "127.0.0.1" || cover_host == "localhost" || cover_host == "::1" {
                r.push_warn(format!(
                    "cover_endpoint {cover_host:?} is loopback while listen_alpha binds all \
                     interfaces — auth-fail traffic loops back into ourselves. Configure a \
                     distinct external HTTPS service.",
                ));
            }
        }
    }
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
            listen_beta: None,
            beta_cert_chain: None,
            beta_private_key: None,
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
            max_session_bytes: None,
            abuse_detector: None,
            outbound_filter: None,
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

    // ----- coherence checks -----

    #[test]
    fn pow_aggressive_vs_short_deadline_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.pow_difficulty = Some(22); // ~4s floor solve
        cfg.handshake_deadline_secs = Some(2);
        let report = preflight(&cfg);
        assert!(!report.has_failures(), "should warn, not fail: {report}");
        assert!(
            report
                .checks
                .iter()
                .any(|c| matches!(c, Check::Warn(m) if m.contains("solve time"))),
            "expected pow/deadline coherence warning: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pow_coherent_with_default_deadline_passes() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.pow_difficulty = Some(16); // ~65 ms floor — fine for 15s default
        let report = preflight(&cfg);
        assert!(!report.has_failures(), "got: {report}");
        assert!(
            !report
                .checks
                .iter()
                .any(|c| matches!(c, Check::Warn(m) if m.contains("solve time"))),
            "should NOT warn at d=16: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn user_burst_exceeding_ip_burst_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.rate_limit = Some(RateLimitCfg {
            burst: 5.0,
            refill_per_sec: 1.0,
        });
        cfg.user_rate_limit = Some(crate::config::UserRateLimitCfg {
            burst: 50.0,
            refill_per_sec: 1.0,
            max_users: 1024,
        });
        let report = preflight(&cfg);
        assert!(
            report.checks.iter().any(
                |c| matches!(c, Check::Warn(m) if m.contains("never reach their per-user quota"))
            ),
            "expected user-vs-ip-burst warning: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn drain_without_metrics_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.drain_secs = Some(30);
        // metrics_listen unset
        let report = preflight(&cfg);
        assert!(
            report
                .checks
                .iter()
                .any(|c| matches!(c, Check::Warn(m) if m.contains("/readyz"))),
            "expected drain-without-metrics warning: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn drain_with_metrics_does_not_warn() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.drain_secs = Some(30);
        cfg.metrics_listen = Some("127.0.0.1:9090".to_string());
        let report = preflight(&cfg);
        assert!(
            !report
                .checks
                .iter()
                .any(|c| matches!(c, Check::Warn(m) if m.contains("/readyz"))),
            "should not warn when metrics_listen is set: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn idle_smaller_than_deadline_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.session_idle_secs = Some(5);
        cfg.handshake_deadline_secs = Some(15);
        let report = preflight(&cfg);
        assert!(
            report
                .checks
                .iter()
                .any(|c| matches!(c, Check::Warn(m) if m.contains("less than handshake_deadline"))),
            "expected idle<deadline warning: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn max_conn_below_burst_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.max_connections = Some(3);
        cfg.rate_limit = Some(RateLimitCfg {
            burst: 50.0,
            refill_per_sec: 5.0,
        });
        let report = preflight(&cfg);
        assert!(
            report
                .checks
                .iter()
                .any(|c| matches!(c, Check::Warn(m) if m.contains("can saturate the global concurrency cap"))),
            "expected max_conn<burst warning: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn firewall_allow_deny_overlap_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.firewall = Some(FirewallCfg {
            allow: vec!["10.0.0.0/8".to_string(), "192.0.2.42/32".to_string()],
            deny: vec!["192.0.2.42/32".to_string()],
        });
        let report = preflight(&cfg);
        assert!(
            report
                .checks
                .iter()
                .any(|c| matches!(c, Check::Warn(m) if m.contains("both allow and deny"))),
            "expected allow/deny overlap warning: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cover_loopback_with_wildcard_listen_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.listen_alpha = "0.0.0.0:8443".to_string();
        cfg.cover_endpoint = Some("127.0.0.1:443".to_string());
        let report = preflight(&cfg);
        assert!(
            report
                .checks
                .iter()
                .any(|c| matches!(c, Check::Warn(m) if m.contains("loops back into ourselves"))),
            "expected loopback-cover warning: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cover_same_host_as_listen_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.listen_alpha = "203.0.113.7:8443".to_string();
        cfg.cover_endpoint = Some("203.0.113.7:443".to_string());
        let report = preflight(&cfg);
        assert!(
            report
                .checks
                .iter()
                .any(|c| matches!(c, Check::Warn(m) if m.contains("matches listen_alpha host"))),
            "expected same-host-cover warning: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tiny_max_session_bytes_warns() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.max_session_bytes = Some(512); // < 1 MiB
        let report = preflight(&cfg);
        assert!(
            report
                .checks
                .iter()
                .any(|c| matches!(c, Check::Warn(m) if m.contains("below 1 MiB"))),
            "expected tiny-cap warning: {report}"
        );
        assert!(!report.has_failures(), "should warn, not fail");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reasonable_max_session_bytes_does_not_warn() {
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.max_session_bytes = Some(50 * 1024 * 1024 * 1024); // 50 GiB
        let report = preflight(&cfg);
        assert!(
            !report
                .checks
                .iter()
                .any(|c| matches!(c, Check::Warn(m) if m.contains("below 1 MiB"))),
            "should not warn at 50 GiB: {report}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn coherent_default_config_has_no_coherence_warnings() {
        // A "normal" prod config — sensible knobs that don't trip any
        // coherence rule.
        let dir = tmpdir();
        let mut cfg = minimal_cfg(&dir);
        cfg.pow_difficulty = Some(8);
        cfg.handshake_deadline_secs = Some(15);
        cfg.session_idle_secs = Some(600);
        cfg.max_connections = Some(4096);
        cfg.rate_limit = Some(RateLimitCfg {
            burst: 10.0,
            refill_per_sec: 5.0,
        });
        cfg.user_rate_limit = Some(crate::config::UserRateLimitCfg {
            burst: 5.0,
            refill_per_sec: 1.0,
            max_users: 1024,
        });
        cfg.metrics_listen = Some("127.0.0.1:9090".to_string());
        cfg.drain_secs = Some(30);
        cfg.cover_endpoint = Some("www.cloudflare.com:443".to_string());
        cfg.listen_alpha = "0.0.0.0:8443".to_string();

        let report = preflight(&cfg);
        // Filter to coherence-class warnings only (those introduced by
        // coherence_checks). The minimal_cfg may still emit warnings
        // from the per-field checks (e.g. tls missing).
        let coherence_warns: Vec<_> = report
            .checks
            .iter()
            .filter_map(|c| match c {
                Check::Warn(m)
                    if m.contains("solve time")
                        || m.contains("never reach their per-user quota")
                        || m.contains("/readyz")
                        || m.contains("less than handshake_deadline")
                        || m.contains("can saturate the global concurrency cap")
                        || m.contains("both allow and deny")
                        || m.contains("matches listen_alpha")
                        || m.contains("loops back into ourselves") =>
                {
                    Some(m.clone())
                }
                _ => None,
            })
            .collect();
        assert!(
            coherence_warns.is_empty(),
            "coherent config tripped a coherence rule: {coherence_warns:?}"
        );
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
