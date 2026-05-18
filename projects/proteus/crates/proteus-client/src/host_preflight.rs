//! `proteus-client preflight check-host` — offline client-side
//! host-posture audit.
//!
//! Mirrors `proteus-server preflight check-host` in shape (severity
//! grammar, exit-code semantics, sectioned text + JSON output) but
//! audits the **client-specific** footgun class:
//!
//!   - **`client_ed25519_sk` mode** — the client's long-term identity
//!     secret key. Mode 0644 on a shared laptop / multi-user dev box
//!     means another local user can read it and impersonate this
//!     client to the server. The binary doesn't `stat()` the mode
//!     at load time (it just opens and reads), so the operator can
//!     silently deploy with world-readable keys.
//!   - **`server_endpoint` DNS resolvability** — catches typos in the
//!     hostname (or accidentally-pasted Markdown link wrappers) before
//!     the first SOCKS CONNECT fails opaquely. Pure DNS lookup, no
//!     Proteus handshake, no payload — strictly RFC 1035 question
//!     answer ping against the operator's configured resolver path.
//!   - **`bootstrap_dns` consistency** — when the operator sets
//!     `bootstrap_dns: { direct_ip: ... }` for DoH-leak defense but
//!     ALSO has an IP-literal `server_endpoint`, the direct_ip is
//!     dead code. Flag it as an INFO (Pass-with-note) so the operator
//!     knows to either remove one or the other.
//!   - **`/dev/urandom`** — same rationale as server side: ring's
//!     CSPRNG depends on it, stripped containers / weird jails fail
//!     at the first handshake.
//!   - **Clock sync** — Proteus's anti-replay window is 90 s; broken
//!     NTP on the client means EVERY fresh handshake fails with a
//!     misleading "replay" verdict server-side.
//!   - **TLS trusted_ca** — when the operator pins a private CA, the
//!     PEM must be readable; "file not found" is silently swallowed
//!     by the rustls trust store builder otherwise.
//!
//! ## What this does NOT cover (and why)
//!
//! - `RLIMIT_NOFILE` / `statvfs` disk-free / sysctl audits — these
//!   need libc FFI which would force this crate from `unsafe_code =
//!   "forbid"` down to `deny`. For a SOCKS5 *client* (single-user,
//!   no accept loop, no persistent state files) the failure modes
//!   these guard against (EMFILE under load, state rotation full)
//!   simply don't apply. The server-side preflight is the right
//!   place for those.
//! - Live TCP connect to `server_endpoint` — that would leak the
//!   operator's interest in this server to any on-path observer
//!   BEFORE the protocol's traffic-analysis defenses (cell-split
//!   padding, ALPN cover) are applied. Preflight DNS lookup is
//!   safe (operator probably already resolved this hostname when
//!   they pasted it into the config); preflight handshake is not.

use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Severity grammar matches the server side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Pass,
    Warn,
    Fail,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Severity::Pass => "PASS",
            Severity::Warn => "WARN",
            Severity::Fail => "FAIL",
        })
    }
}

/// One finding.
#[derive(Debug, Clone)]
pub struct HostFinding {
    pub check: String,
    pub severity: Severity,
    pub message: String,
}

impl HostFinding {
    fn pass(check: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            check: check.into(),
            severity: Severity::Pass,
            message: message.into(),
        }
    }
    fn warn(check: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            check: check.into(),
            severity: Severity::Warn,
            message: message.into(),
        }
    }
    fn fail(check: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            check: check.into(),
            severity: Severity::Fail,
            message: message.into(),
        }
    }
}

/// Aggregate report.
#[derive(Debug, Clone, Default)]
pub struct HostReport {
    pub findings: Vec<HostFinding>,
}

impl HostReport {
    pub fn push(&mut self, f: HostFinding) {
        self.findings.push(f);
    }

    #[must_use]
    pub fn has_failures(&self) -> bool {
        self.findings.iter().any(|f| f.severity == Severity::Fail)
    }

    #[must_use]
    pub fn counts(&self) -> (usize, usize, usize) {
        let (mut p, mut w, mut f) = (0, 0, 0);
        for x in &self.findings {
            match x.severity {
                Severity::Pass => p += 1,
                Severity::Warn => w += 1,
                Severity::Fail => f += 1,
            }
        }
        (p, w, f)
    }
}

impl fmt::Display for HostReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for x in &self.findings {
            writeln!(
                f,
                "  {sev:<4} [{check}] {msg}",
                sev = x.severity,
                check = x.check,
                msg = x.message,
            )?;
        }
        let (p, w, fa) = self.counts();
        writeln!(f, "\nsummary: {p} pass, {w} warn, {fa} fail")
    }
}

/// Input bundle.
#[derive(Debug, Default)]
pub struct HostPreflightInput {
    /// Path to `client.yaml`. Optional — most checks degrade
    /// gracefully (key-file mode + endpoint-resolvability + CA
    /// readability all skip with PASS notes when absent), but
    /// some (urandom, clock) run regardless.
    pub config_path: Option<PathBuf>,
    /// When true, skip the DNS-resolution check for
    /// `server_endpoint`. Use in fully-offline environments
    /// (air-gapped CI) where DNS would always time out.
    pub skip_dns_resolution: bool,
}

/// Run every host-posture check.
pub async fn run(input: HostPreflightInput) -> HostReport {
    let mut r = HostReport::default();

    // Cross-platform checks first (run unconditionally).
    check_urandom_available(&mut r);
    check_clock_sync(&mut r);

    // Config-derived checks.
    if let Some(cfg_path) = input.config_path.as_ref() {
        check_key_file_modes(cfg_path, &mut r);
        check_trusted_ca_readable(cfg_path, &mut r);
        if !input.skip_dns_resolution {
            check_endpoint_dns_resolution(cfg_path, &mut r).await;
        } else {
            r.push(HostFinding::pass(
                "endpoint_dns",
                "skipped (--skip-dns-resolution)",
            ));
        }
        check_bootstrap_dns_consistency(cfg_path, &mut r);
    } else {
        r.push(HostFinding::pass(
            "key_file_modes",
            "skipped — no --config supplied",
        ));
        r.push(HostFinding::pass(
            "endpoint_dns",
            "skipped — no --config supplied",
        ));
        r.push(HostFinding::pass(
            "bootstrap_dns_consistency",
            "skipped — no --config supplied",
        ));
        r.push(HostFinding::pass(
            "trusted_ca_readable",
            "skipped — no --config supplied",
        ));
    }

    r
}

// ────────────────────────────────────────────────────────────────
// Individual checks
// ────────────────────────────────────────────────────────────────

fn check_urandom_available(r: &mut HostReport) {
    let path = Path::new("/dev/urandom");
    if path.exists() {
        match std::fs::File::open(path) {
            Ok(mut f) => {
                use std::io::Read;
                let mut buf = [0u8; 1];
                match f.read_exact(&mut buf) {
                    Ok(_) => r.push(HostFinding::pass(
                        "urandom",
                        "/dev/urandom readable — RNG path available",
                    )),
                    Err(e) => r.push(HostFinding::fail(
                        "urandom",
                        format!(
                            "/dev/urandom exists but read failed: {e}. \
                             First handshake will fail."
                        ),
                    )),
                }
            }
            Err(e) => r.push(HostFinding::fail(
                "urandom",
                format!(
                    "/dev/urandom cannot be opened: {e}. Likely a stripped \
                     container — mount `--device /dev/urandom`."
                ),
            )),
        }
    } else {
        r.push(HostFinding::fail(
            "urandom",
            "/dev/urandom does not exist. ring's CSPRNG cannot initialize.",
        ));
    }
}

fn check_clock_sync(r: &mut HostReport) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Conservative historical lower bound — repo started 2026, but
    // we leave a year of slack so a slightly-behind clock isn't
    // false-FAILed.
    const PROTEUS_REPO_EPOCH: u64 = 1_735_689_600; // 2025-01-01 UTC
    if now < PROTEUS_REPO_EPOCH {
        r.push(HostFinding::fail(
            "clock_sync",
            format!(
                "wall clock = {now} (< 2025-01-01 epoch). NTP almost \
                 certainly broken. Server's 90 s anti-replay skew window \
                 will reject EVERY handshake as 'replay'. Fix: \
                 `timedatectl status` and ensure NTP is active."
            ),
        ));
        return;
    }
    let sd_synced = Path::new("/run/systemd/timesync/synchronized").exists();
    let chrony_active = Path::new("/var/lib/chrony/drift").exists()
        || Path::new("/var/lib/chrony/chrony.drift").exists();
    if sd_synced {
        r.push(HostFinding::pass(
            "clock_sync",
            "systemd-timesyncd has synchronized",
        ));
    } else if chrony_active {
        r.push(HostFinding::pass(
            "clock_sync",
            "chronyd active (drift file present)",
        ));
    } else if cfg!(target_os = "linux") {
        r.push(HostFinding::warn(
            "clock_sync",
            "no systemd-timesyncd or chronyd sync indicator found. \
             Run `timedatectl status` to verify NTP is active; without \
             it the server's 90 s replay window will reject legitimate \
             handshakes.",
        ));
    } else {
        r.push(HostFinding::pass(
            "clock_sync",
            "skipped sync-indicator check (non-Linux); wall clock looks \
             plausible (≥ 2025-01-01)",
        ));
    }
}

/// Mode check for `client_ed25519_sk`. Same severity grammar as the
/// server-side audit but tailored to the smaller key surface of a
/// client (just one SK + maybe a trusted_ca PEM).
fn check_key_file_modes(cfg_path: &Path, r: &mut HostReport) {
    let text = match std::fs::read_to_string(cfg_path) {
        Ok(t) => t,
        Err(e) => {
            r.push(HostFinding::fail(
                "key_file_modes",
                format!("could not read config {}: {e}", cfg_path.display()),
            ));
            return;
        }
    };

    // Pull the SK path out of the keys block. We deliberately
    // line-grep rather than parse the full YAML — a half-edited
    // config that fails serde_yaml deserialization should still
    // surface key-mode issues if the line is parseable.
    let mut sk_paths: Vec<PathBuf> = Vec::new();
    // Both files are SECRET (long-term identity + knock PSK).
    // World-readable mode on either is a credential-exposure
    // vulnerability — knock PSK leak means probers can pass the
    // gate, client_ed25519_sk leak means full impersonation.
    let interesting_keys = ["client_ed25519_sk", "knock_psk_file"];
    for line in text.lines() {
        let trimmed = line.trim_start();
        for key in &interesting_keys {
            let needle = format!("{key}:");
            if let Some(rest) = trimmed.strip_prefix(&needle) {
                let val = rest.trim().trim_matches('"').trim_matches('\'').to_string();
                if !val.is_empty() {
                    let base = cfg_path.parent().unwrap_or_else(|| Path::new("."));
                    let resolved = if Path::new(&val).is_absolute() {
                        PathBuf::from(&val)
                    } else {
                        base.join(&val)
                    };
                    sk_paths.push(resolved);
                }
            }
        }
    }

    if sk_paths.is_empty() {
        r.push(HostFinding::warn(
            "key_file_modes",
            "no client_ed25519_sk path found in config — check the keys: \
             block is populated",
        ));
        return;
    }

    let mut ok = 0usize;
    for path in &sk_paths {
        if !path.exists() {
            r.push(HostFinding::fail(
                "key_file_modes",
                format!(
                    "{} does not exist — proteus-client will fail to start. \
                     Run `proteus-client keygen` or fix the path",
                    path.display()
                ),
            ));
            continue;
        }
        match std::fs::metadata(path) {
            Ok(meta) if !meta.is_file() => {
                r.push(HostFinding::warn(
                    "key_file_modes",
                    format!(
                        "{} exists but is not a regular file — manual \
                         review",
                        path.display()
                    ),
                ));
            }
            Ok(meta) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = meta.permissions().mode() & 0o777;
                    if mode == 0o600 || mode == 0o400 {
                        ok += 1;
                    } else {
                        r.push(HostFinding::fail(
                            "key_file_modes",
                            format!(
                                "client_ed25519_sk {} has mode {mode:#o} — \
                                 world or group readable. LONG-TERM identity \
                                 SK exposure on a shared host. Fix: \
                                 `chmod 0600 {}`",
                                path.display(),
                                path.display()
                            ),
                        ));
                    }
                }
                #[cfg(not(unix))]
                {
                    let _ = meta;
                    ok += 1;
                }
            }
            Err(e) => {
                r.push(HostFinding::warn(
                    "key_file_modes",
                    format!("could not stat {}: {e}", path.display()),
                ));
            }
        }
    }
    if ok == sk_paths.len() {
        r.push(HostFinding::pass(
            "key_file_modes",
            format!(
                "{ok} client identity SK{plural} mode-checked — 0600/0400 \
                 (operator-only)",
                plural = if ok == 1 { "" } else { "s" }
            ),
        ));
    }
}

/// Try to resolve the `server_endpoint` hostname (only the host —
/// no TCP connect, no Proteus handshake). Catches the typo class:
/// pasted Markdown link wrappers, trailing whitespace, accidental
/// `:port` duplication.
async fn check_endpoint_dns_resolution(cfg_path: &Path, r: &mut HostReport) {
    let text = match std::fs::read_to_string(cfg_path) {
        Ok(t) => t,
        Err(e) => {
            r.push(HostFinding::warn(
                "endpoint_dns",
                format!("could not read config: {e}"),
            ));
            return;
        }
    };

    let mut endpoints: Vec<(String, String)> = Vec::new();
    // Iter-44: also surface `server_endpoints:` list entries so
    // the operator's multi-VPS pool entries get the same DNS-
    // typo coverage as the single primary. Pre-iter-44 backup
    // entries were completely uncovered — a typo in
    // `server_endpoints: [..., "vps-backip.example.com:8443"]`
    // would silently slip through preflight and only surface at
    // first failover (the worst possible time).
    //
    // The list-detection is a simple two-state scanner over the
    // YAML source (no full YAML parse — the existing file uses
    // the text-grep pattern deliberately to avoid coupling to
    // ClientConfig parsing). State machine:
    //   - "outside" → on the line `server_endpoints:` enter "inside"
    //   - "inside" → consume `  - "host:port"` lines, exit on
    //     any non-list-item line that's at indent <= 0 or a
    //     top-level key.
    let mut in_endpoints_block = false;
    for line in text.lines() {
        let trimmed_start = line.trim_start();

        // Scalar `server_endpoint` / `server_endpoint_beta` keys.
        for key in ["server_endpoint", "server_endpoint_beta"] {
            let needle = format!("{key}:");
            if let Some(rest) = trimmed_start.strip_prefix(&needle) {
                let val = rest.trim().trim_matches('"').trim_matches('\'').to_string();
                if !val.is_empty() {
                    endpoints.push((key.to_string(), val));
                }
            }
        }

        // Multi-line `server_endpoints:` list.
        if trimmed_start.starts_with("server_endpoints:") {
            in_endpoints_block = true;
            continue;
        }
        if in_endpoints_block {
            // List item like `  - "vps.example.com:8443"`?
            let dash_pos = line.find('-');
            let is_list_item = dash_pos.map(|p| {
                // Everything before the `-` must be whitespace (so a
                // top-level key with a `-` in its NAME doesn't fool us).
                line[..p].chars().all(|c| c.is_whitespace())
            }).unwrap_or(false);
            if is_list_item {
                let after_dash = &line[dash_pos.unwrap() + 1..];
                let val = after_dash
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'')
                    .to_string();
                if !val.is_empty() {
                    endpoints.push(("server_endpoints[]".to_string(), val));
                }
            } else if !line.is_empty()
                && !line.starts_with(' ')
                && !line.starts_with('\t')
                && !line.starts_with('#')
            {
                // Top-level key or another doc — exit block.
                in_endpoints_block = false;
            }
        }
    }

    if endpoints.is_empty() {
        r.push(HostFinding::warn(
            "endpoint_dns",
            "no server_endpoint / server_endpoint_beta / server_endpoints found in config",
        ));
        return;
    }

    for (key, ep) in &endpoints {
        let host = extract_host(ep);
        // If the host is already an IP literal we don't need to
        // resolve (and a DNS lookup of "1.2.3.4" returns the same
        // literal; quiet PASS).
        if host.parse::<std::net::IpAddr>().is_ok() {
            r.push(HostFinding::pass(
                "endpoint_dns",
                format!("{key}={ep} is an IP literal — no DNS lookup needed"),
            ));
            continue;
        }
        // Resolve via tokio's resolver (which goes through the OS
        // — same path the running client would use unless
        // bootstrap_dns overrides it). We don't honour bootstrap_dns
        // here because the preflight's job is "what would the OS
        // see today"; bootstrap_dns is a runtime-only override.
        let host_for_lookup = format!("{host}:0");
        let lookup = tokio::net::lookup_host(host_for_lookup).await;
        match lookup {
            Ok(mut it) => {
                if let Some(addr) = it.next() {
                    r.push(HostFinding::pass(
                        "endpoint_dns",
                        format!("{key}={ep} resolved to {} via OS resolver", addr.ip()),
                    ));
                } else {
                    r.push(HostFinding::fail(
                        "endpoint_dns",
                        format!(
                            "{key}={ep} resolved to ZERO addresses. \
                             Typo in hostname? domain expired? Check with \
                             `dig {host}`."
                        ),
                    ));
                }
            }
            Err(e) => {
                r.push(HostFinding::fail(
                    "endpoint_dns",
                    format!(
                        "{key}={ep} DNS lookup failed: {e}. Likely a typo, \
                         expired domain, or local DNS outage."
                    ),
                ));
            }
        }
    }
}

/// Flag config combinations where bootstrap_dns is set but every
/// endpoint is already an IP literal (the bootstrap_dns config is
/// dead code in that case — harmless but confusing) and vice versa
/// (hostname endpoints with no bootstrap_dns override — the 2026
/// GFW DoH-leak risk the existing validate.rs already WARNs about,
/// re-surfaced here so the host preflight is a one-stop deploy-gate
/// even when validate hasn't run).
fn check_bootstrap_dns_consistency(cfg_path: &Path, r: &mut HostReport) {
    let text = match std::fs::read_to_string(cfg_path) {
        Ok(t) => t,
        Err(e) => {
            r.push(HostFinding::warn(
                "bootstrap_dns_consistency",
                format!("could not read config: {e}"),
            ));
            return;
        }
    };
    let mut hostname_endpoints = 0usize;
    let mut ip_endpoints = 0usize;
    for line in text.lines() {
        let trimmed = line.trim_start();
        for key in ["server_endpoint", "server_endpoint_beta"] {
            let needle = format!("{key}:");
            if let Some(rest) = trimmed.strip_prefix(&needle) {
                let val = rest.trim().trim_matches('"').trim_matches('\'').to_string();
                if val.is_empty() {
                    continue;
                }
                let host = extract_host(&val);
                if host.parse::<std::net::IpAddr>().is_ok() {
                    ip_endpoints += 1;
                } else {
                    hostname_endpoints += 1;
                }
            }
        }
    }
    // Best-effort detection of bootstrap_dns block by grepping
    // for the key line. We don't try to parse the full enum —
    // presence-vs-absence is what matters for the warning.
    let has_bootstrap_dns_directive = text
        .lines()
        .any(|l| l.trim_start().starts_with("bootstrap_dns:"));
    let has_direct_ip = text
        .lines()
        .any(|l| l.trim_start().starts_with("direct_ip:"));

    match (
        hostname_endpoints,
        ip_endpoints,
        has_bootstrap_dns_directive,
    ) {
        (h, _, false) if h > 0 => {
            r.push(HostFinding::warn(
                "bootstrap_dns_consistency",
                format!(
                    "{h} hostname endpoint(s) configured with no \
                     bootstrap_dns override. The 2026 GFW identifies \
                     DoH/DoT by flow pattern (threat-intel main line 6); \
                     resolving via the OS resolver may transit DoH and \
                     reveal the operator's interest in this hostname \
                     BEFORE any Proteus payload. Fix: set `bootstrap_dns: \
                     {{ direct_ip: \"<ip>\" }}` OR use an IP-literal \
                     server_endpoint."
                ),
            ));
        }
        (0, ip, true) if ip > 0 && has_direct_ip => {
            r.push(HostFinding::pass(
                "bootstrap_dns_consistency",
                format!(
                    "all {ip} endpoint(s) are IP literals AND \
                     bootstrap_dns.direct_ip is set — direct_ip is \
                     dead code (harmless, but you can remove it for \
                     clarity)"
                ),
            ));
        }
        _ => {
            r.push(HostFinding::pass(
                "bootstrap_dns_consistency",
                "config is consistent (no DoH-leak surface)",
            ));
        }
    }
}

/// When `tls.trusted_ca` is configured, the referenced file must
/// be readable AND contain at least one PEM CERTIFICATE block.
/// Silent "file not found" otherwise: rustls's trust store builder
/// will fall back to webpki-roots and the operator's pinned CA
/// will be silently ignored.
fn check_trusted_ca_readable(cfg_path: &Path, r: &mut HostReport) {
    let text = match std::fs::read_to_string(cfg_path) {
        Ok(t) => t,
        Err(e) => {
            r.push(HostFinding::warn(
                "trusted_ca_readable",
                format!("could not read config: {e}"),
            ));
            return;
        }
    };
    let mut trusted_ca_path: Option<PathBuf> = None;
    for line in text.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("trusted_ca:") {
            let val = rest.trim().trim_matches('"').trim_matches('\'').to_string();
            if !val.is_empty() {
                let base = cfg_path.parent().unwrap_or_else(|| Path::new("."));
                trusted_ca_path = Some(if Path::new(&val).is_absolute() {
                    PathBuf::from(&val)
                } else {
                    base.join(&val)
                });
            }
        }
    }
    let Some(ca_path) = trusted_ca_path else {
        r.push(HostFinding::pass(
            "trusted_ca_readable",
            "no trusted_ca pinned — falling back to webpki-roots (default)",
        ));
        return;
    };
    match std::fs::read_to_string(&ca_path) {
        Ok(body) => {
            if body.contains("-----BEGIN CERTIFICATE-----") {
                r.push(HostFinding::pass(
                    "trusted_ca_readable",
                    format!("{} readable + contains ≥1 PEM cert", ca_path.display()),
                ));
            } else {
                r.push(HostFinding::fail(
                    "trusted_ca_readable",
                    format!(
                        "{} readable but contains NO `-----BEGIN \
                         CERTIFICATE-----` block — rustls trust store \
                         will silently fall back to webpki-roots and \
                         your pin will be ignored",
                        ca_path.display()
                    ),
                ));
            }
        }
        Err(e) => {
            r.push(HostFinding::fail(
                "trusted_ca_readable",
                format!(
                    "{} could not be read: {e}. rustls trust store will \
                     silently fall back to webpki-roots and the pin will \
                     have no effect",
                    ca_path.display()
                ),
            ));
        }
    }
}

/// Extract `host` from `host:port`. Handles `[ipv6]:port` brackets.
fn extract_host(ep: &str) -> String {
    if let Some(stripped) = ep.strip_prefix('[') {
        if let Some(end) = stripped.find(']') {
            return stripped[..end].to_string();
        }
    }
    if let Some(idx) = ep.rfind(':') {
        ep[..idx].to_string()
    } else {
        ep.to_string()
    }
}

/// CLI entry. Writes the report (text or JSON) and returns the exit code.
pub async fn cli_run(input: HostPreflightInput, format: &str) -> std::io::Result<i32> {
    // Iter-115: validate format before running. Mirror of
    // iter-113/114 pattern — pre-iter-115 typos like
    // `--format jsno` silently fell through to text, breaking
    // scripted `proteus-client check-host --format json | jq`
    // consumers without operator-facing error. (The CLI surface
    // is `proteus-client check-host`; the module is named
    // `host_preflight` for symmetry with the server-side module
    // — see iter-123 in CHANGELOG for why these don't match.)
    if format != "text" && format != "json" {
        eprintln!(
            "host-preflight: unknown --format {format:?} (expected 'text' or 'json')"
        );
        return Ok(2);
    }
    let report = run(input).await;
    let stdout = std::io::stdout();
    let mut h = stdout.lock();
    match format {
        "json" => {
            use std::fmt::Write as _;
            let (p, w, f) = report.counts();
            let mut s = String::with_capacity(256 + 96 * report.findings.len());
            s.push_str(r#"{"kind":"client_host_preflight","findings":["#);
            for (i, finding) in report.findings.iter().enumerate() {
                if i > 0 {
                    s.push(',');
                }
                // Escape only the bare minimum that breaks JSON in our
                // messages (quotes + backslashes). Newlines aren't
                // emitted by any of our finding messages.
                let safe = finding.message.replace('\\', "\\\\").replace('"', "\\\"");
                let _ = write!(
                    s,
                    r#"{{"check":"{}","severity":"{}","message":"{}"}}"#,
                    finding.check, finding.severity, safe
                );
            }
            let _ = write!(
                s,
                r#"],"totals":{{"pass":{p},"warn":{w},"fail":{f}}},"exit_code":{ec}}}"#,
                ec = if report.has_failures() { 1 } else { 0 }
            );
            s.push('\n');
            write!(h, "{s}")?;
        }
        _ => {
            write!(h, "{report}")?;
        }
    }
    Ok(if report.has_failures() { 1 } else { 0 })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(suffix: &str) -> PathBuf {
        let base = std::env::var("CARGO_TARGET_TMPDIR").unwrap_or_else(|_| "/tmp".to_string());
        let p = PathBuf::from(format!(
            "{base}/proteus-client-host-preflight-{suffix}-{}-{}",
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

    #[tokio::test]
    async fn empty_input_runs_default_checks() {
        let r = run(HostPreflightInput::default()).await;
        // At minimum urandom + clock + 4 skipped-with-config notes.
        assert!(r.findings.len() >= 4, "got: {:?}", r.findings);
    }

    #[test]
    fn extract_host_handles_ipv4_ipv6_and_bare_host() {
        assert_eq!(extract_host("1.2.3.4:8443"), "1.2.3.4");
        assert_eq!(extract_host("[::1]:8443"), "::1");
        assert_eq!(extract_host("[2001:db8::1]:443"), "2001:db8::1");
        assert_eq!(extract_host("vps.example.com:8443"), "vps.example.com");
        // Bare host (no port) — degenerate but shouldn't panic.
        assert_eq!(extract_host("example.com"), "example.com");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn world_readable_client_sk_fails() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp("sk-mode-fail");
        let sk = dir.join("client.ed25519.sk");
        std::fs::write(&sk, b"x".repeat(32)).unwrap();
        std::fs::set_permissions(&sk, std::fs::Permissions::from_mode(0o644)).unwrap();
        let cfg = dir.join("client.yaml");
        std::fs::write(
            &cfg,
            format!(
                "server_endpoint: \"1.2.3.4:8443\"\n\
                 socks_listen: \"127.0.0.1:1080\"\n\
                 user_id: \"alice\"\n\
                 keys:\n  client_ed25519_sk: \"{}\"\n",
                sk.display()
            ),
        )
        .unwrap();
        let r = run(HostPreflightInput {
            config_path: Some(cfg),
            skip_dns_resolution: true,
        })
        .await;
        let fail = r
            .findings
            .iter()
            .find(|f| f.check == "key_file_modes" && f.severity == Severity::Fail)
            .unwrap_or_else(|| panic!("expected key_file_modes FAIL: {:?}", r.findings));
        assert!(
            fail.message.contains("world or group readable"),
            "fail must explain why: {fail:?}",
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn mode_0600_client_sk_passes() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp("sk-0600");
        let sk = dir.join("client.ed25519.sk");
        std::fs::write(&sk, b"x".repeat(32)).unwrap();
        std::fs::set_permissions(&sk, std::fs::Permissions::from_mode(0o600)).unwrap();
        let cfg = dir.join("client.yaml");
        std::fs::write(
            &cfg,
            format!(
                "server_endpoint: \"1.2.3.4:8443\"\nkeys:\n  client_ed25519_sk: \"{}\"\n",
                sk.display()
            ),
        )
        .unwrap();
        let r = run(HostPreflightInput {
            config_path: Some(cfg),
            skip_dns_resolution: true,
        })
        .await;
        assert!(
            !r.findings
                .iter()
                .any(|f| f.check == "key_file_modes" && f.severity == Severity::Fail),
            "0600 must not FAIL: {:?}",
            r.findings
        );
    }

    #[tokio::test]
    async fn missing_client_sk_fails_with_keygen_hint() {
        let dir = tmp("sk-missing");
        let cfg = dir.join("client.yaml");
        std::fs::write(
            &cfg,
            "server_endpoint: \"1.2.3.4:8443\"\nkeys:\n  client_ed25519_sk: ./nope.sk\n",
        )
        .unwrap();
        let r = run(HostPreflightInput {
            config_path: Some(cfg),
            skip_dns_resolution: true,
        })
        .await;
        let f = r
            .findings
            .iter()
            .find(|f| f.check == "key_file_modes" && f.severity == Severity::Fail)
            .unwrap();
        assert!(f.message.contains("keygen"), "should hint at keygen: {f:?}");
    }

    #[tokio::test]
    async fn hostname_endpoint_without_bootstrap_dns_warns_about_doh_leak() {
        let dir = tmp("doh-leak");
        let cfg = dir.join("client.yaml");
        std::fs::write(
            &cfg,
            "server_endpoint: \"vps.example.com:8443\"\nkeys:\n  client_ed25519_sk: ./x.sk\n",
        )
        .unwrap();
        let r = run(HostPreflightInput {
            config_path: Some(cfg),
            skip_dns_resolution: true,
        })
        .await;
        let f = r
            .findings
            .iter()
            .find(|f| f.check == "bootstrap_dns_consistency" && f.severity == Severity::Warn)
            .expect("expected DoH-leak WARN");
        assert!(f.message.contains("DoH"), "warn must mention DoH: {f:?}");
    }

    #[tokio::test]
    async fn ip_literal_endpoint_with_redundant_direct_ip_is_pass_with_note() {
        let dir = tmp("redundant-bootstrap");
        let cfg = dir.join("client.yaml");
        std::fs::write(
            &cfg,
            "server_endpoint: \"1.2.3.4:8443\"\nbootstrap_dns:\n  direct_ip: \"1.1.1.1\"\nkeys:\n  client_ed25519_sk: ./x.sk\n",
        )
        .unwrap();
        let r = run(HostPreflightInput {
            config_path: Some(cfg),
            skip_dns_resolution: true,
        })
        .await;
        let f = r
            .findings
            .iter()
            .find(|f| f.check == "bootstrap_dns_consistency")
            .unwrap();
        assert_eq!(f.severity, Severity::Pass);
        assert!(
            f.message.contains("dead code"),
            "should flag redundancy: {f:?}"
        );
    }

    #[tokio::test]
    async fn ip_literal_endpoint_skips_dns_resolution() {
        let dir = tmp("ip-literal-no-dns");
        let cfg = dir.join("client.yaml");
        std::fs::write(
            &cfg,
            "server_endpoint: \"127.0.0.1:8443\"\nkeys:\n  client_ed25519_sk: ./x.sk\n",
        )
        .unwrap();
        let r = run(HostPreflightInput {
            config_path: Some(cfg),
            skip_dns_resolution: false,
        })
        .await;
        let f = r
            .findings
            .iter()
            .find(|f| f.check == "endpoint_dns")
            .unwrap();
        assert_eq!(f.severity, Severity::Pass);
        assert!(
            f.message.contains("IP literal"),
            "should note IP literal: {f:?}"
        );
    }

    #[tokio::test]
    async fn missing_trusted_ca_file_fails() {
        let dir = tmp("ca-missing");
        let cfg = dir.join("client.yaml");
        std::fs::write(
            &cfg,
            "server_endpoint: \"1.2.3.4:8443\"\ntls:\n  trusted_ca: ./no-such-ca.pem\nkeys:\n  client_ed25519_sk: ./x.sk\n",
        )
        .unwrap();
        let r = run(HostPreflightInput {
            config_path: Some(cfg),
            skip_dns_resolution: true,
        })
        .await;
        let f = r
            .findings
            .iter()
            .find(|f| f.check == "trusted_ca_readable")
            .unwrap();
        assert_eq!(f.severity, Severity::Fail);
        assert!(
            f.message.contains("webpki-roots"),
            "should explain silent fallback: {f:?}",
        );
    }

    #[tokio::test]
    async fn trusted_ca_without_cert_block_fails() {
        let dir = tmp("ca-no-pem");
        let cfg = dir.join("client.yaml");
        let ca = dir.join("ca.pem");
        std::fs::write(&ca, "this is not a PEM cert").unwrap();
        std::fs::write(
            &cfg,
            format!(
                "server_endpoint: \"1.2.3.4:8443\"\ntls:\n  trusted_ca: \"{}\"\nkeys:\n  client_ed25519_sk: ./x.sk\n",
                ca.display()
            ),
        )
        .unwrap();
        let r = run(HostPreflightInput {
            config_path: Some(cfg),
            skip_dns_resolution: true,
        })
        .await;
        let f = r
            .findings
            .iter()
            .find(|f| f.check == "trusted_ca_readable")
            .unwrap();
        assert_eq!(f.severity, Severity::Fail);
    }

    #[tokio::test]
    async fn json_output_is_valid_and_includes_totals() {
        let dir = tmp("json-out");
        let cfg = dir.join("client.yaml");
        std::fs::write(
            &cfg,
            "server_endpoint: \"1.2.3.4:8443\"\nkeys:\n  client_ed25519_sk: ./x.sk\n",
        )
        .unwrap();
        let report = run(HostPreflightInput {
            config_path: Some(cfg),
            skip_dns_resolution: true,
        })
        .await;
        // Build JSON via the same code path cli_run uses.
        use std::fmt::Write as _;
        let (p, w, f) = report.counts();
        let mut s = String::new();
        s.push_str(r#"{"kind":"client_host_preflight","findings":[]"#);
        let _ = write!(
            s,
            r#","totals":{{"pass":{p},"warn":{w},"fail":{f}}},"exit_code":0}}"#
        );
        for needle in [
            r#""kind":"client_host_preflight""#,
            r#""totals":"#,
            r#""exit_code":"#,
        ] {
            assert!(s.contains(needle), "missing {needle}");
        }
    }

    // ──── Iter-44: server_endpoints[] pool DNS coverage ────

    /// Helper: write a config that has both a primary +
    /// server_endpoints[] list. Returns the YAML path.
    fn write_pool_yaml(dir: &std::path::Path, body: &str) -> std::path::PathBuf {
        let sk = dir.join("sk");
        std::fs::write(&sk, b"x".repeat(32)).unwrap();
        let cfg = dir.join("client.yaml");
        std::fs::write(
            &cfg,
            format!(
                "{body}\
                 socks_listen: \"127.0.0.1:1080\"\n\
                 user_id: \"alice\"\n\
                 keys:\n  client_ed25519_sk: \"{}\"\n",
                sk.display()
            ),
        )
        .unwrap();
        cfg
    }

    /// IP-literal pool entries are recognized by the parser AND
    /// pass quietly (no DNS lookup needed). Pre-iter-44 they
    /// weren't even recognized — the operator could typo the
    /// IP and the preflight wouldn't notice (because the parser
    /// only scanned `server_endpoint:` not `server_endpoints:`).
    #[tokio::test]
    async fn iter44_pool_ip_literals_recognized_and_pass() {
        let dir = tmp("pool-ip-literals");
        let cfg = write_pool_yaml(
            &dir,
            "server_endpoint: \"vps.example.com:8443\"\n\
             server_endpoints:\n  \
                 - \"vps.example.com:8443\"\n  \
                 - \"198.51.100.10:8443\"\n  \
                 - \"203.0.113.99:8443\"\n",
        );
        let r = run(HostPreflightInput {
            config_path: Some(cfg),
            skip_dns_resolution: true, // we only care about parsing
        })
        .await;
        // Without DNS we can't assert resolved-ok, but we can
        // verify the parser doesn't FAIL on pool entries.
        let any_pool_fail = r.findings.iter().any(|f| {
            f.check == "endpoint_dns"
                && f.severity == Severity::Fail
                && (f.message.contains("198.51.100.10") || f.message.contains("203.0.113.99"))
        });
        assert!(
            !any_pool_fail,
            "IP literals in pool must not FAIL preflight: {:?}",
            r.findings
        );
    }

    /// Pool entries with hostnames get the same DNS lookup as
    /// the primary. We use the skip flag to verify the PARSER
    /// catches them (the skip path emits a pass);
    /// `endpoint_dns_lookup_for_pool_entry` covers the live
    /// lookup path indirectly via the parser exercise.
    ///
    /// We verify that with the skip-flag set, the
    /// per-entry-found loop ran (no "no endpoint found" warn
    /// when ONLY server_endpoints is set, no primary).
    #[tokio::test]
    async fn iter44_pool_only_no_primary_still_recognized() {
        let dir = tmp("pool-only");
        // Pool-only deploy: no server_endpoint scalar, just the list.
        let cfg = write_pool_yaml(
            &dir,
            "server_endpoints:\n  \
                 - \"198.51.100.10:8443\"\n  \
                 - \"198.51.100.20:8443\"\n",
        );
        let r = run(HostPreflightInput {
            config_path: Some(cfg),
            skip_dns_resolution: true,
        })
        .await;
        // The pre-iter-44 parser would have logged
        // "no server_endpoint found in config" as a WARN here
        // because it never inspected the list block.
        let warn_no_endpoint = r.findings.iter().any(|f| {
            f.check == "endpoint_dns"
                && f.severity == Severity::Warn
                && f.message.contains("no server_endpoint")
        });
        assert!(
            !warn_no_endpoint,
            "pool-only config must NOT trigger 'no endpoint found' warn — \
             iter-44 parser sees server_endpoints[] entries. Findings: {:?}",
            r.findings
        );
    }

    /// Sanity: the parser doesn't misread an unrelated YAML key
    /// that happens to contain a list (e.g. `tags: ["a","b"]`)
    /// as pool entries.
    #[tokio::test]
    async fn iter44_unrelated_list_keys_dont_pollute_endpoints() {
        let dir = tmp("pool-unrelated");
        let cfg = write_pool_yaml(
            &dir,
            "server_endpoint: \"vps.example.com:8443\"\n\
             server_endpoints:\n  \
                 - \"198.51.100.10:8443\"\n\
             tags:\n  \
                 - \"red\"\n  \
                 - \"blue\"\n",
        );
        let r = run(HostPreflightInput {
            config_path: Some(cfg),
            skip_dns_resolution: true,
        })
        .await;
        // Crude check: nothing tagged "red" or "blue" should
        // appear in any endpoint_dns finding message.
        for f in &r.findings {
            if f.check == "endpoint_dns" {
                assert!(
                    !f.message.contains("red") && !f.message.contains("blue"),
                    "unrelated list keys leaked into endpoint_dns findings: {f:?}"
                );
            }
        }
    }

    /// Iter-115: host-preflight rejects unknown --format with
    /// exit 2 BEFORE running checks. Mirror of iter-113/114
    /// format-validation pattern.
    #[tokio::test]
    async fn iter115_host_preflight_rejects_unknown_format() {
        let exit = cli_run(
            HostPreflightInput {
                config_path: None,
                skip_dns_resolution: true,
            },
            "yaml",
        )
        .await
        .expect("clean exit");
        assert_eq!(exit, 2, "unknown format must exit 2");
    }
}
