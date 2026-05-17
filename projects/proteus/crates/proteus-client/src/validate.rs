//! Configuration preflight (`proteus-client validate <path>`).
//!
//! Catches operator errors BEFORE the SOCKS5 listener binds, so a
//! typo in `client.yaml` doesn't manifest as a silent dial failure
//! at every CONNECT attempt — instead it fails fast at deploy
//! time with a clear diagnostic.
//!
//! Mirrors `proteus-server validate` in scope: pure I/O against
//! the config file and the files it references. Does NOT bind
//! sockets, does NOT dial the upstream server, does NOT call
//! `accept()`. Designed to run inside CI / Ansible / Terraform
//! gates BEFORE the client binary is restarted.
//!
//! Exit code: 0 on all-green; 1 if any check failed.
//!
//! ## Checks performed
//!
//! Required-field presence:
//!   - `server_endpoint` non-empty, parses as `host:port`.
//!   - `socks_listen` non-empty, parses as `host:port`.
//!   - `user_id` non-empty, ≤ 8 bytes (`encode_user_id` truncation
//!     would silently drop the rest — operator must shorten).
//!
//! Key file accessibility + length:
//!   - `keys.server_mlkem_pk` exists, decodes to ≥ 32 bytes.
//!   - `keys.server_x25519_pk` exists, decodes to exactly 32 bytes.
//!   - `keys.server_pq_fingerprint` exists, decodes to exactly 32 bytes.
//!   - `keys.client_ed25519_sk` exists, decodes to exactly 32 bytes.
//!
//! TLS:
//!   - When `tls.trusted_ca` is set, the file is readable and
//!     contains at least one PEM CERTIFICATE block.
//!
//! β-profile coherence:
//!   - When `server_endpoint_beta` is set:
//!     - It parses as `host:port`.
//!     - Either `beta_server_name` OR `tls.server_name` must be set
//!       (the β QUIC handshake needs SNI).
//!     - `beta_initial_mtu` is in the [1200, 1500] sanity range.
//!
//! Numeric sanity warnings (Warn, not Fail):
//!   - `pad_quantum` outside {0, 64, 128, 256, 512, 1280} —
//!     unusual; operator should re-check (typo for 1280?).
//!   - `pow_difficulty` > 24 — likely a typo; sustained 24-bit
//!     PoW costs ~1 s on a laptop, anything higher is operator-
//!     hostile.
//!
//! Bootstrap-DNS posture (Warn, not Fail — production decision is
//! the operator's, but the default is dangerous in 2026):
//!   - `server_endpoint` is a hostname AND `bootstrap_dns` is unset
//!     or set to `system` → WARN. The 2026 GFW identifies DoH/DoT
//!     by flow pattern (threat-intel main line 6); a hostname
//!     resolved through the OS resolver may transit DoH and be
//!     identified before any Proteus payload is sent. Production
//!     anti-censorship deploys MUST either embed an IP literal in
//!     `server_endpoint` or set `bootstrap_dns: { direct_ip: ... }`.
//!   - `server_endpoint_beta` hostname under system bootstrap_dns →
//!     same warning, for the β carrier.
//!   - All-IP-literal deploy + still set `bootstrap_dns: direct_ip` →
//!     informational PASS (the direct_ip is ignored — harmless but
//!     the operator should know).

use std::fmt;
use std::io::Write;
use std::path::Path;

use crate::config::ClientConfig;

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

    /// `(passes, warns, fails)` counts.
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
                Check::Pass(s) => writeln!(f, "  PASS  {s}")?,
                Check::Warn(s) => writeln!(f, "  WARN  {s}")?,
                Check::Fail(s) => writeln!(f, "  FAIL  {s}")?,
            }
        }
        let (p, w, fail) = self.counts();
        writeln!(f, "\nsummary: {p} pass, {w} warn, {fail} fail")?;
        Ok(())
    }
}

/// Run the preflight against the YAML at `path`. Returns the report;
/// caller decides exit code based on `has_failures()`.
pub async fn run(path: &Path) -> PreflightReport {
    let mut r = PreflightReport::default();

    // ----- Parse step ----- (any further checks need the parsed cfg).
    let cfg = match ClientConfig::load(path).await {
        Ok(c) => {
            r.push_pass(format!("YAML parses: {}", path.display()));
            c
        }
        Err(e) => {
            r.push_fail(format!("YAML parse failed: {e}"));
            return r;
        }
    };

    // ----- Required fields -----
    if cfg.server_endpoint.is_empty() {
        r.push_fail("server_endpoint is empty");
    } else if parse_host_port(&cfg.server_endpoint).is_some() {
        r.push_pass(format!("server_endpoint = {}", cfg.server_endpoint));
    } else {
        r.push_fail(format!(
            "server_endpoint does not parse as host:port: {:?}",
            cfg.server_endpoint
        ));
    }

    // ----- Multi-VPS HA fallback list (server_endpoints) -----
    //
    // Operator-opt-in; empty by default. When present, every entry
    // must parse as host:port. Repeats of the primary entry are
    // accepted (operator may include it as a deliberate retry
    // anchor). Single-entry list is a hard WARN — equivalent to
    // having no list at all, so the operator probably meant to add
    // more.
    if !cfg.server_endpoints.is_empty() {
        let mut bad = Vec::new();
        for (idx, raw) in cfg.server_endpoints.iter().enumerate() {
            if raw.is_empty() {
                bad.push(format!("[{idx}] empty"));
            } else if parse_host_port(raw).is_none() {
                bad.push(format!("[{idx}]={raw:?}"));
            }
        }
        if bad.is_empty() {
            r.push_pass(format!(
                "server_endpoints pool ({} entries) — multi-VPS HA dispatch wins over \
                 single server_endpoint at runtime",
                cfg.server_endpoints.len()
            ));
        } else {
            r.push_fail(format!(
                "server_endpoints has bad host:port entries: {}",
                bad.join(", ")
            ));
        }
        if cfg.server_endpoints.len() == 1 {
            r.push_warn(
                "server_endpoints has only one entry — equivalent to the single-endpoint \
                 fallback; add ≥2 distinct VPS endpoints to actually get HA (or remove the \
                 field entirely to silence this warning)",
            );
        }
        // Coherence warn: if server_endpoint is NOT present in the
        // pool, the operator has set up a strange config where the
        // primary they configured isn't in the failover list. Likely
        // intentional in some advanced topologies but suspicious in
        // the common case.
        if !cfg
            .server_endpoints
            .iter()
            .any(|e| e == &cfg.server_endpoint)
        {
            r.push_warn(
                "server_endpoint is not present in server_endpoints — operator has set up a \
                 split-brain pool where the primary is dialed only when the fallback list is \
                 exhausted. If intentional, fine; if accidental, add the primary to \
                 server_endpoints[0]",
            );
        }
    }

    if cfg.socks_listen.is_empty() {
        r.push_fail("socks_listen is empty");
    } else if parse_host_port(&cfg.socks_listen).is_some() {
        r.push_pass(format!("socks_listen = {}", cfg.socks_listen));
    } else {
        r.push_fail(format!(
            "socks_listen does not parse as host:port: {:?}",
            cfg.socks_listen
        ));
    }

    // admin_listen is operator-opt-in; validate the format and warn
    // when a non-loopback bind is configured (matches the runtime
    // warn! line so operators see the same caution at preflight time).
    if let Some(admin_addr) = cfg.admin_listen.as_deref() {
        match parse_host_port(admin_addr) {
            Some((host, _port)) => {
                // Cheap textual loopback check: covers IPv4 127.x.x.x
                // (the conventional `127.0.0.1` and oddballs like
                // `127.0.0.99` that bind to loopback), IPv6 `::1`, and
                // the literal `localhost` (system resolver maps to
                // loopback on every sensible system). Wildcard binds
                // (`0.0.0.0`, `::`, empty) are flagged non-loopback.
                let loopback_ip = host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback());
                let is_loopback = loopback_ip || host.eq_ignore_ascii_case("localhost");
                if is_loopback {
                    r.push_pass(format!("admin_listen = {admin_addr} (loopback, no auth)"));
                } else {
                    r.push_warn(format!(
                        "admin_listen = {admin_addr} is NON-loopback. The endpoint has no \
                         authentication; bind 127.0.0.1 / [::1] unless you have a specific \
                         operational reason. Anyone who can reach this address can read your \
                         in-process CarrierHealth + EndpointPool state."
                    ));
                }
            }
            None => {
                r.push_fail(format!(
                    "admin_listen does not parse as host:port: {admin_addr:?}"
                ));
            }
        }
    }

    if cfg.user_id.is_empty() {
        r.push_fail("user_id is empty");
    } else if cfg.user_id.len() > 8 {
        r.push_fail(format!(
            "user_id is {} bytes; max is 8 (encode_user_id silently truncates the rest, \
             breaking server allowlist match): {:?}",
            cfg.user_id.len(),
            cfg.user_id,
        ));
    } else {
        r.push_pass(format!("user_id = {:?}", cfg.user_id));
    }

    // ----- Key files -----
    check_key_file(
        &mut r,
        "server_mlkem_pk",
        &cfg.keys.server_mlkem_pk,
        |n| n >= 32,
        "≥32 bytes (ML-KEM-768 EK)",
    );
    check_key_file(
        &mut r,
        "server_x25519_pk",
        &cfg.keys.server_x25519_pk,
        |n| n == 32,
        "exactly 32 bytes",
    );
    check_key_file(
        &mut r,
        "server_pq_fingerprint",
        &cfg.keys.server_pq_fingerprint,
        |n| n == 32,
        "exactly 32 bytes (SHA-256)",
    );
    check_key_file(
        &mut r,
        "client_ed25519_sk",
        &cfg.keys.client_ed25519_sk,
        |n| n == 32,
        "exactly 32 bytes (raw seed)",
    );

    // ----- TLS -----
    match &cfg.tls {
        Some(tls) => {
            if tls.server_name.is_empty() {
                r.push_fail("tls.server_name is empty");
            } else {
                r.push_pass(format!("tls.server_name = {}", tls.server_name));
            }
            if let Some(ca) = &tls.trusted_ca {
                match std::fs::read(ca) {
                    Ok(bytes) => {
                        if bytes.windows(11).any(|w| w == b"-----BEGIN ") {
                            r.push_pass(format!("tls.trusted_ca readable: {}", ca.display()));
                        } else {
                            r.push_fail(format!(
                                "tls.trusted_ca file does not contain a PEM block: {}",
                                ca.display()
                            ));
                        }
                    }
                    Err(e) => {
                        r.push_fail(format!("tls.trusted_ca unreadable: {} ({e})", ca.display()))
                    }
                }
            }
        }
        None => r.push_warn(
            "tls: block is unset — production deployments MUST set it (server uses TLS 1.3)",
        ),
    }

    // ----- β-profile coherence -----
    if let Some(beta) = &cfg.server_endpoint_beta {
        if parse_host_port(beta).is_some() {
            r.push_pass(format!("server_endpoint_beta = {beta}"));
        } else {
            r.push_fail(format!(
                "server_endpoint_beta does not parse as host:port: {beta:?}"
            ));
        }
        // β SNI must come from somewhere.
        let has_sni = cfg.beta_server_name.is_some()
            || cfg
                .tls
                .as_ref()
                .map(|t| !t.server_name.is_empty())
                .unwrap_or(false);
        if has_sni {
            r.push_pass("β: TLS SNI available (beta_server_name or tls.server_name set)");
        } else {
            r.push_fail(
                "server_endpoint_beta is set but neither beta_server_name nor tls.server_name is — \
                 β QUIC handshake will fail with no SNI",
            );
        }
        if let Some(mtu) = cfg.beta_initial_mtu {
            if (1200..=1500).contains(&mtu) {
                r.push_pass(format!("beta_initial_mtu = {mtu}"));
            } else {
                r.push_fail(format!(
                    "beta_initial_mtu = {mtu} is out of sane range [1200, 1500]"
                ));
            }
        }
    }

    // ----- Bootstrap-DNS posture -----
    //
    // Walk both `server_endpoint` and (when set) `server_endpoint_beta`.
    // For each: classify as ip-literal / pinned-direct-ip / system-resolver.
    // Surface a WARN when the operator is still on the system-resolver
    // path — that's the route the 2026 GFW DoH-ID attack rides on.
    // See qa/2026-05-17-gfw-2026-q1q2-threat-intel.md main line 6.
    {
        use crate::bootstrap::endpoint_is_ip_literal;
        let mut audit_endpoint = |label: &str, endpoint: &str| {
            let is_literal = endpoint_is_ip_literal(endpoint);
            match (&cfg.bootstrap_dns, is_literal) {
                (_, true) => r.push_pass(format!(
                    "bootstrap: {label} = {endpoint} is an IP literal — DNS skipped"
                )),
                (Some(b), false) if b.is_direct_ip() => {
                    let ip = b.pinned_ip().expect("is_direct_ip implies pinned_ip");
                    r.push_pass(format!(
                        "bootstrap: {label} hostname is pinned via bootstrap_dns.direct_ip = {ip}"
                    ));
                }
                (_, false) => r.push_warn(format!(
                    "bootstrap: {label} = {endpoint} resolves via OS resolver — \
                     production deploys SHOULD either use an IP literal in {label} \
                     or set `bootstrap_dns: {{ direct_ip: <vps-ip> }}` to defeat \
                     the 2026 GFW DoH/DoT identification attack"
                )),
            }
        };
        audit_endpoint("server_endpoint", &cfg.server_endpoint);
        if let Some(beta) = &cfg.server_endpoint_beta {
            audit_endpoint("server_endpoint_beta", beta);
        }

        // If the operator pinned a direct_ip but BOTH endpoints are
        // already IP literals, the pin is harmless but dead-letter —
        // surface as info so the operator can clean up the config.
        if let Some(b) = &cfg.bootstrap_dns {
            if b.is_direct_ip() {
                let ep_literal = endpoint_is_ip_literal(&cfg.server_endpoint);
                let beta_literal = cfg
                    .server_endpoint_beta
                    .as_ref()
                    .map(|s| endpoint_is_ip_literal(s))
                    .unwrap_or(true);
                if ep_literal && beta_literal {
                    r.push_pass(
                        "bootstrap: bootstrap_dns.direct_ip is set but all endpoints \
                         are already IP literals — the direct_ip pin is unused (harmless; \
                         remove it for clarity if desired)",
                    );
                }
            }
        }
    }

    // ----- Numeric sanity -----
    if let Some(q) = cfg.pad_quantum {
        const COMMON: &[u16] = &[0, 64, 128, 256, 512, 1280];
        if !COMMON.contains(&q) {
            r.push_warn(format!(
                "pad_quantum = {q} is unusual (typical values: {COMMON:?}); \
                 typo for 1280?"
            ));
        } else {
            r.push_pass(format!("pad_quantum = {q}"));
        }
    }
    if let Some(pow) = cfg.pow_difficulty {
        if pow > 24 {
            r.push_fail(format!(
                "pow_difficulty = {pow} is operator-hostile (>24 bits costs ≥1 s of CPU per \
                 client handshake on a modern laptop)"
            ));
        } else {
            r.push_pass(format!("pow_difficulty = {pow}"));
        }
    }
    if let Some(t) = cfg.beta_first_timeout_secs {
        if t == 0 {
            r.push_fail("beta_first_timeout_secs = 0 means β dial returns instantly");
        } else if t > 30 {
            r.push_warn(format!(
                "beta_first_timeout_secs = {t} is high; dual-stack fallback to α will be slow. \
                 The carrier-health back-off (CarrierHealth) caps the cost AFTER \
                 DEFAULT_FAILURE_THRESHOLD = 3 consecutive failures, but each of those \
                 first 3 CONNECTs pays the full timeout"
            ));
        } else {
            r.push_pass(format!(
                "beta_first_timeout_secs = {t}s (CarrierHealth limits the impact to the \
                 first ≤ 3 CONNECTs of any burst before β suppression engages)"
            ));
        }
    }
    if let Some(d) = cfg.drain_secs {
        if d > 120 {
            r.push_warn(format!(
                "drain_secs = {d} is high; systemd TimeoutStopSec must be larger"
            ));
        }
    }

    r
}

/// Helper: read a key file and run a size predicate.
fn check_key_file(
    r: &mut PreflightReport,
    label: &str,
    path: &Path,
    size_ok: impl Fn(usize) -> bool,
    expected: &str,
) {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            r.push_fail(format!("keys.{label}: unreadable {} ({e})", path.display()));
            return;
        }
    };
    // Decode base64 if it looks like base64, else use raw.
    let decoded = base64_or_raw(&bytes);
    if size_ok(decoded.len()) {
        r.push_pass(format!(
            "keys.{label} OK ({} bytes, {})",
            decoded.len(),
            expected
        ));
    } else {
        r.push_fail(format!(
            "keys.{label}: wrong size — got {} bytes after base64 decode, want {}",
            decoded.len(),
            expected
        ));
    }
}

fn base64_or_raw(input: &[u8]) -> Vec<u8> {
    use base64::Engine;
    let trimmed: Vec<u8> = input
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&trimmed) {
        return decoded;
    }
    input.to_vec()
}

fn parse_host_port(s: &str) -> Option<(&str, u16)> {
    // IPv6 literal: `[addr]:port`.
    if let Some(stripped) = s.strip_prefix('[') {
        if let Some(end) = stripped.find(']') {
            let host = &stripped[..end];
            let rest = &stripped[end + 1..];
            if let Some(port) = rest.strip_prefix(':').and_then(|p| p.parse::<u16>().ok()) {
                return Some((host, port));
            }
        }
        return None;
    }
    let (host, port) = s.rsplit_once(':')?;
    let port = port.parse::<u16>().ok()?;
    if host.is_empty() {
        return None;
    }
    Some((host, port))
}

/// `proteus-client validate <path>` entry point. Prints the report
/// + sets exit code.
pub async fn cli_run(path: &Path) -> std::io::Result<i32> {
    let report = run(path).await;
    let stdout = std::io::stdout();
    let mut h = stdout.lock();
    write!(h, "{report}")?;
    Ok(if report.has_failures() { 1 } else { 0 })
}
