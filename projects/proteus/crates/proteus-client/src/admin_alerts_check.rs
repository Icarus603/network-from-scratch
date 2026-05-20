//! `proteus-client alerts-check` — evaluate point-in-time alert
//! rules against the running client's `/metrics` endpoint.
//!
//! Symmetric with `proteus-server admin alerts-check` (which
//! exists for the server's `/metrics` surface): one-shot scrape +
//! in-process evaluation + per-rule verdict, exit 0 / 1, no
//! Prometheus dependency. Designed for:
//!
//! - fresh-deploy smoke: did this new client.yaml result in a
//!   working SOCKS5 listener?
//! - incident triage: which carrier / endpoint is currently
//!   suppressed?
//! - CI / Ansible deploy gates: one shell-pipeline check.
//!
//! ## Rules evaluated today
//!
//! - **ProteusClientNotAlive**: `proteus_client_up == 0` → CRIT.
//!   SOCKS5 listener is not bound. Every upstream CONNECT will
//!   fail at the SOCKS layer.
//! - **ProteusClientAllEndpointsSuppressed**: every endpoint in
//!   the multi-VPS pool has `suppressed == 1` simultaneously →
//!   CRIT. Dispatch will force-probe the primary but most or all
//!   dials will fail until at least one entry recovers.
//! - **ProteusClientBetaCarrierSuppressed**:
//!   `proteus_client_carrier_suppressed == 1` → WARN. β is
//!   backing off; α fallback still works but throughput may be
//!   degraded for clients that prefer β.
//! - **ProteusClientNoRecentDialSuccess**: when alive and at
//!   least one dial was attempted, `last_dial_success_unix == 0`
//!   means no dial has EVER succeeded → CRIT.
//! - **ProteusClientHighDialFailureRatio**:
//!   `dials_failed_total > dials_succeeded_total > 0` → WARN.
//!   Coarser than `rate(...)` over a real TSDB window, but
//!   useful for "more failures than successes since boot"
//!   triage.
//! - **ProteusClientBootstrapViaSystemResolver**:
//!   `bootstrap_via_system_resolver_total > 0` → WARN. 2026 GFW
//!   threat-intel main line 6 (DoH leak): the operator should
//!   pin `bootstrap_dns: { direct_ip: ... }` instead of letting
//!   the OS resolver transit a DoH provider.
//! - **ProteusClientPoolReloadFailing**: `attempts_total >
//!   succeeded_total` → WARN. The operator issued at least one
//!   SIGHUP that failed to apply the new `server_endpoints` list.
//!   The running pool still uses the previous config; the
//!   operator's edit didn't take effect. Symmetric with the
//!   bundled `proteus-client-alerts.yaml` rule of the same name.
//!
//! Rules that genuinely need a TSDB (`rate(...[5m])` etc.) are
//! deliberately NOT mirrored here — the operator wires the
//! bundled `deploy/prometheus/proteus-alerts.yaml` for those
//! when they want full coverage.

use std::fmt;
use std::io::Write;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Errors surfaced by [`cli_run`].
#[derive(thiserror::Error, Debug)]
pub enum AlertsCheckError {
    /// Output write failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// `url` parameter was not a well-formed http://host:port URL.
    #[error("bad URL: {0}")]
    BadUrl(String),
    /// HTTP layer returned non-200.
    #[error("admin endpoint returned: {0}")]
    Status(String),
    /// Network-level failure (connect / read / timeout).
    #[error("network: {0}")]
    Network(String),
}

/// Verdict for a single alert check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckSeverity {
    /// Check did not fire — green signal.
    Pass,
    /// Investigate within the hour.
    Warn,
    /// Page-grade — operator must act now.
    Crit,
}

impl fmt::Display for CheckSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Pass => "PASS",
            Self::Warn => "WARN",
            Self::Crit => "CRIT",
        })
    }
}

/// A single alert verdict.
#[derive(Debug, Clone)]
pub struct Check {
    /// Stable rule identifier (no version suffix, matches a future
    /// bundled `proteus-client-alerts.yaml`).
    pub rule_name: &'static str,
    /// Severity bucket — drives exit-code + dashboard tier.
    pub severity: CheckSeverity,
    /// Operator-readable explanation with concrete numbers.
    pub message: String,
}

/// Aggregate report. Tuple counts via [`Report::counts`].
#[derive(Debug, Clone, Default)]
pub struct Report {
    /// Per-rule verdicts in evaluation order.
    pub checks: Vec<Check>,
}

impl Report {
    /// Append a [`Check`] to the report. Caller-visible so tests
    /// can build synthetic reports.
    pub fn push(&mut self, c: Check) {
        self.checks.push(c);
    }

    /// `(pass, warn, crit)` counts.
    #[must_use]
    pub fn counts(&self) -> (usize, usize, usize) {
        let (mut p, mut w, mut c) = (0, 0, 0);
        for x in &self.checks {
            match x.severity {
                CheckSeverity::Pass => p += 1,
                CheckSeverity::Warn => w += 1,
                CheckSeverity::Crit => c += 1,
            }
        }
        (p, w, c)
    }

    /// Exit code: 0 on PASS+WARN-only, 1 on any CRIT.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        if self.counts().2 > 0 {
            1
        } else {
            0
        }
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for c in &self.checks {
            writeln!(
                f,
                "  {sev:<4} [{rule}] {msg}",
                sev = c.severity,
                rule = c.rule_name,
                msg = c.message
            )?;
        }
        let (p, w, cr) = self.counts();
        writeln!(
            f,
            "\nsummary: {p} pass, {w} warn, {cr} crit  (exit {ec})",
            ec = self.exit_code()
        )
    }
}

/// Parse the subset of /metrics we care about. Returns a map of
/// (metric_name, labels-string-or-empty) → numeric value.
///
/// Re-implements the small Prometheus exposition parser the
/// server-side helper uses; intentionally lives here to keep the
/// client crate dep-light (the server's helper is in
/// `proteus-server` which the client shouldn't pull in).
pub fn parse_metrics(body: &str) -> std::collections::HashMap<(String, String), f64> {
    let mut out = std::collections::HashMap::new();
    for line in body.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let (name_end, has_labels) = match trimmed.find(['{', ' ']) {
            Some(i) if trimmed.as_bytes()[i] == b'{' => (i, true),
            Some(i) => (i, false),
            None => continue,
        };
        let name = trimmed[..name_end].to_string();
        let (labels, value_str) = if has_labels {
            let label_end = match trimmed.find('}') {
                Some(i) => i,
                None => continue,
            };
            let labels = trimmed[name_end + 1..label_end].to_string();
            let rest = trimmed[label_end + 1..].trim_start();
            (labels, rest)
        } else {
            ("".to_string(), trimmed[name_end..].trim_start())
        };
        let val_token = value_str.split_whitespace().next().unwrap_or("");
        if let Ok(v) = val_token.parse::<f64>() {
            out.insert((name, labels), v);
        }
    }
    out
}

/// Evaluate every supported client-side rule against the parsed
/// `/metrics` body. Order matches the rule list in the module
/// docstring.
pub fn evaluate(body: &str) -> Report {
    let m = parse_metrics(body);
    let mut r = Report::default();

    let g = |name: &str| -> Option<f64> { m.get(&(name.to_string(), String::new())).copied() };

    // ──── ProteusClientNotAlive ────
    let alive = g("proteus_client_up").unwrap_or(0.0);
    if alive == 0.0 {
        r.push(Check {
            rule_name: "ProteusClientNotAlive",
            severity: CheckSeverity::Crit,
            message: "proteus_client_up == 0 — SOCKS5 listener is NOT bound".to_string(),
        });
    } else {
        r.push(Check {
            rule_name: "ProteusClientNotAlive",
            severity: CheckSeverity::Pass,
            message: "proteus_client_up == 1".to_string(),
        });
    }

    // ──── ProteusClientPanic ────
    //
    // Iter-101: cumulative-counter check on proteus_panics_total.
    // Any non-zero count = the panic-hook captured at least one
    // panic since process start. CRIT severity matches the
    // server-side ProteusPanic alert (and the Prometheus
    // ProteusClientPanic alert).
    if let Some(v) = g("proteus_panics_total") {
        let sev = if v > 0.0 {
            CheckSeverity::Crit
        } else {
            CheckSeverity::Pass
        };
        let msg = if v > 0.0 {
            format!(
                "{v} panic(s) captured since process start — `journalctl --user -u \
                 proteus-client -o json | jq 'select(.target==\"proteus_panic\")'`. \
                 The panic-unwind workspace profile keeps the binary running, but \
                 each captured panic is investigation-worthy."
            )
        } else {
            "no panics captured".to_string()
        };
        r.push(Check {
            rule_name: "ProteusClientPanic",
            severity: sev,
            message: msg,
        });
    }

    // Note: ProteusClientUncleanShutdown is NOT added on the
    // client side because the client currently doesn't ship
    // restart_tracker (server-only feature). If client-side
    // restart tracking lands in a future iteration, the check
    // can be added symmetric with the server-side one.

    // ──── ProteusClientBetaCarrierSuppressed ────
    if let Some(supp) = g("proteus_client_carrier_suppressed") {
        let sev = if supp >= 1.0 {
            CheckSeverity::Warn
        } else {
            CheckSeverity::Pass
        };
        let msg = if supp >= 1.0 {
            let streak = g("proteus_client_carrier_failure_streak").unwrap_or(0.0);
            let remaining = g("proteus_client_carrier_suppression_secs_remaining").unwrap_or(0.0);
            format!(
                "β carrier SUPPRESSED — failure_streak={streak}, {remaining:.0}s left on suppression window. α fallback still works."
            )
        } else {
            "β carrier active (not suppressed)".to_string()
        };
        r.push(Check {
            rule_name: "ProteusClientBetaCarrierSuppressed",
            severity: sev,
            message: msg,
        });
    }

    // ──── ProteusClientAllEndpointsSuppressed ────
    // Inspect labelled gauge `proteus_client_endpoint_suppressed{addr="..."}`.
    // If we observe N entries (N > 0) AND every one is 1, alert.
    let endpoint_suppressed_entries: Vec<(String, f64)> = m
        .iter()
        .filter(|((name, _), _)| name == "proteus_client_endpoint_suppressed")
        .map(|((_, labels), v)| (labels.clone(), *v))
        .collect();
    if !endpoint_suppressed_entries.is_empty() {
        let total = endpoint_suppressed_entries.len();
        let suppressed = endpoint_suppressed_entries
            .iter()
            .filter(|(_, v)| *v >= 1.0)
            .count();
        if suppressed == total {
            r.push(Check {
                rule_name: "ProteusClientAllEndpointsSuppressed",
                severity: CheckSeverity::Crit,
                message: format!(
                    "EVERY endpoint in the multi-VPS pool is suppressed ({suppressed}/{total}) — dispatcher will force-probe the primary but most dials will fail. Investigate upstream connectivity."
                ),
            });
        } else if suppressed > 0 {
            r.push(Check {
                rule_name: "ProteusClientAllEndpointsSuppressed",
                severity: CheckSeverity::Warn,
                message: format!(
                    "{suppressed}/{total} endpoints suppressed — pool dispatch will skip the suppressed entries until the window expires"
                ),
            });
        } else {
            r.push(Check {
                rule_name: "ProteusClientAllEndpointsSuppressed",
                severity: CheckSeverity::Pass,
                message: format!("all {total} endpoints healthy"),
            });
        }
    }

    // ──── ProteusClientNoRecentDialSuccess ────
    let attempted = g("proteus_client_dials_attempted_total").unwrap_or(0.0);
    let last_success = g("proteus_client_last_dial_success_unix_seconds").unwrap_or(0.0);
    if alive >= 1.0 && attempted > 0.0 && last_success == 0.0 {
        r.push(Check {
            rule_name: "ProteusClientNoRecentDialSuccess",
            severity: CheckSeverity::Crit,
            message: format!(
                "{attempted} dial(s) attempted, ZERO succeeded since startup — server connectivity broken or credential mismatch"
            ),
        });
    } else if alive >= 1.0 && attempted > 0.0 {
        // Soft-report; useful in text mode to confirm the success path is alive.
        r.push(Check {
            rule_name: "ProteusClientNoRecentDialSuccess",
            severity: CheckSeverity::Pass,
            message: format!(
                "{} attempts, last success at unix {}",
                attempted as u64, last_success as u64
            ),
        });
    }

    // ──── ProteusClientHighDialFailureRatio ────
    let failed = g("proteus_client_dials_failed_total").unwrap_or(0.0);
    let succeeded = g("proteus_client_dials_succeeded_total").unwrap_or(0.0);
    if failed > succeeded && succeeded > 0.0 {
        r.push(Check {
            rule_name: "ProteusClientHighDialFailureRatio",
            severity: CheckSeverity::Warn,
            message: format!(
                "more failures than successes since startup ({failed} failed vs {succeeded} succeeded) — investigate upstream"
            ),
        });
    } else if failed + succeeded > 0.0 {
        r.push(Check {
            rule_name: "ProteusClientHighDialFailureRatio",
            severity: CheckSeverity::Pass,
            message: format!("{succeeded} successes, {failed} failures (healthy ratio)"),
        });
    }

    // ──── ProteusClientPoolReloadFailing ────
    // Mirrors deploy/prometheus/proteus-client-alerts.yaml:
    //   (attempts_total - succeeded_total) > 0
    // The SIGHUP path bumps `attempts` first, then `succeeded`
    // after the atomic swap completes. A positive gap means at
    // least one SIGHUP was observed but the reload didn't apply
    // — the running pool still uses the pre-SIGHUP config. The
    // operator's edit is silently ineffective; surface it.
    //
    // Three-state emit (matching every other rule in this module):
    //   - gap > 0          → WARN with concrete (att, succ) numbers
    //   - gap == 0, att>0  → PASS (reloads happened, all succeeded)
    //   - att == 0         → suppress entirely (no SIGHUP yet — no
    //                        signal to report; same convention as
    //                        ProteusClientNoRecentDialSuccess when
    //                        attempts == 0)
    let pool_reload_att = g("proteus_client_pool_reload_attempts_total").unwrap_or(0.0);
    let pool_reload_ok = g("proteus_client_pool_reload_succeeded_total").unwrap_or(0.0);
    if pool_reload_att > 0.0 {
        let gap = pool_reload_att - pool_reload_ok;
        if gap > 0.0 {
            r.push(Check {
                rule_name: "ProteusClientPoolReloadFailing",
                severity: CheckSeverity::Warn,
                message: format!(
                    "{} reload attempt(s), only {} succeeded ({} failed) — running pool still uses the pre-SIGHUP config; the operator's edit didn't take effect. Check journalctl for the parse error.",
                    pool_reload_att as u64,
                    pool_reload_ok as u64,
                    gap as u64,
                ),
            });
        } else {
            r.push(Check {
                rule_name: "ProteusClientPoolReloadFailing",
                severity: CheckSeverity::Pass,
                message: format!(
                    "all {} pool reload attempt(s) succeeded",
                    pool_reload_att as u64
                ),
            });
        }
    }

    // ──── ProteusClientBootstrapViaSystemResolver ────
    let via_sys = g("proteus_client_bootstrap_via_system_resolver_total").unwrap_or(0.0);
    if via_sys > 0.0 {
        r.push(Check {
            rule_name: "ProteusClientBootstrapViaSystemResolver",
            severity: CheckSeverity::Warn,
            message: format!(
                "{via_sys} bootstrap resolution(s) transited the OS resolver — 2026 GFW threat-intel main line 6 (DoH leak). Pin `bootstrap_dns: {{ direct_ip: ... }}` in client.yaml"
            ),
        });
    } else if g("proteus_client_bootstrap_via_ip_literal_total").is_some() {
        // Metric series exists → bootstrap was exercised. No
        // system-resolver hits → green.
        r.push(Check {
            rule_name: "ProteusClientBootstrapViaSystemResolver",
            severity: CheckSeverity::Pass,
            message: "no bootstrap resolutions transited the OS resolver".to_string(),
        });
    }

    r
}

/// Async HTTP GET against the client's admin endpoint. The
/// client admin surface is loopback-only and unauthenticated by
/// design — no token gate. Returns the response body on 200,
/// errors otherwise.
async fn http_get_async(url: &str, timeout: Duration) -> Result<String, AlertsCheckError> {
    let (host, port, base_path) = parse_http_url(url)?;
    let path = if base_path == "/" {
        "/metrics".to_string()
    } else {
        format!("{base_path}/metrics")
    };
    let req = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}:{port}\r\n\
         User-Agent: proteus-client-alerts-check/1\r\n\
         Accept: */*\r\n\
         Connection: close\r\n\r\n"
    );
    let fut = async {
        let mut stream = tokio::net::TcpStream::connect((host.as_str(), port))
            .await
            .map_err(|e| AlertsCheckError::Network(format!("connect: {e}")))?;
        stream
            .write_all(req.as_bytes())
            .await
            .map_err(|e| AlertsCheckError::Network(format!("write: {e}")))?;
        let mut buf = Vec::with_capacity(16 * 1024);
        stream
            .read_to_end(&mut buf)
            .await
            .map_err(|e| AlertsCheckError::Network(format!("read: {e}")))?;
        Ok::<Vec<u8>, AlertsCheckError>(buf)
    };
    let buf = tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| AlertsCheckError::Network("timeout".to_string()))??;
    let s = std::str::from_utf8(&buf)
        .map_err(|e| AlertsCheckError::Network(format!("non-UTF8: {e}")))?;
    let split = s
        .find("\r\n\r\n")
        .ok_or_else(|| AlertsCheckError::Network("no body separator".to_string()))?;
    let head = &s[..split];
    let body = &s[split + 4..];
    let status_line = head.lines().next().unwrap_or("");
    if !status_line.starts_with("HTTP/1.1 200") {
        return Err(AlertsCheckError::Status(status_line.to_string()));
    }
    Ok(body.to_string())
}

/// Parse `http://host:port[/path]`. HTTP only (admin endpoint is
/// loopback-by-default, no TLS). Returns `(host, port, path)`;
/// path defaults to `/`.
fn parse_http_url(url: &str) -> Result<(String, u16, String), AlertsCheckError> {
    // Iter-116: actionable error messages mirroring the
    // server-side parse_http_url + client main.rs version.
    if url.starts_with("https://") {
        return Err(AlertsCheckError::BadUrl(format!(
            "{url:?}: admin endpoint is HTTP-only (loopback-by-default; no TLS \
             terminator between the operator and the binary). Use `http://`."
        )));
    }
    let rest = url.strip_prefix("http://").ok_or_else(|| {
        AlertsCheckError::BadUrl(format!(
            "{url:?}: missing `http://` scheme prefix. Expected `http://host:port[/path]`."
        ))
    })?;
    let (authority, path) = match rest.find('/') {
        Some(ix) => (&rest[..ix], rest[ix..].to_string()),
        None => (rest, "/".to_string()),
    };
    let (host, port) = authority.rsplit_once(':').ok_or_else(|| {
        AlertsCheckError::BadUrl(format!(
            "{url:?}: missing explicit `:port` — the admin endpoint has no default port. \
             Example: `http://127.0.0.1:9091`."
        ))
    })?;
    let port: u16 = port.parse().map_err(|_| {
        AlertsCheckError::BadUrl(format!(
            "{url:?}: port {port:?} isn't a valid u16 (1-65535)"
        ))
    })?;
    // Iter-159: reject empty host. Symmetric with the
    // iter-116 server-side gate; closes the
    // `http://:9091/status` shape that previously parsed
    // cleanly with host="" and resolved via libc to either
    // localhost or 0.0.0.0 — an implicit-loopback surprise.
    if host.is_empty() {
        return Err(AlertsCheckError::BadUrl(format!(
            "{url:?}: host portion is empty (likely `http://:port` without a host)."
        )));
    }
    // Iter-159: reject port 0. Symmetric with the iter-158
    // cover-endpoint port-0 gate — TCP-connect to port 0 fails
    // with EADDRNOTAVAIL on every platform, so port 0 is never a
    // legitimate admin endpoint; the bare `u16::parse` happily
    // accepted it before.
    if port == 0 {
        return Err(AlertsCheckError::BadUrl(format!(
            "{url:?}: port 0 is invalid as a TCP-connect target (reserved for bind/listen \
             'any free port')."
        )));
    }
    // Iter-147: reject CRLF / NUL / TAB / space in host or path —
    // both get embedded verbatim into the HTTP GET request (host
    // into Host:, path into the request line). Defense-in-depth
    // against operator config-template tools pulling URLs from
    // untrusted sources. Symmetric with the server-side
    // `admin::parse_http_url` gate.
    if host
        .bytes()
        .any(|b| b == 0 || b == b'\r' || b == b'\n' || b == b'\t' || b == b' ')
    {
        return Err(AlertsCheckError::BadUrl(format!(
            "{url:?}: host contains a forbidden control character (NUL / CR / LF / TAB / space). \
             HTTP request smuggling defense-in-depth — strip the offending byte from the --url argument."
        )));
    }
    if path
        .bytes()
        .any(|b| b == 0 || b == b'\r' || b == b'\n' || b == b'\t')
    {
        return Err(AlertsCheckError::BadUrl(format!(
            "{url:?}: path contains a forbidden control character (NUL / CR / LF / TAB). \
             HTTP request smuggling defense-in-depth — strip the offending byte from the --url argument."
        )));
    }
    Ok((host.to_string(), port, path))
}

/// CLI entry. Scrapes `url` over plain HTTP (no auth — the
/// client's admin endpoint is loopback-only by convention),
/// evaluates rules, prints in the requested format, returns
/// exit code.
pub async fn cli_run(url: &str, timeout: Duration, format: &str) -> Result<i32, AlertsCheckError> {
    // Iter-114: validate format string before any network I/O.
    // Mirror of iter-113 connect-test format validation. Same
    // trap class — typos silently fell through to text mode,
    // breaking scripted jq pipelines.
    if format != "text" && format != "json" {
        return Err(AlertsCheckError::BadUrl(format!(
            "unknown --format {format:?} (expected 'text' or 'json')"
        )));
    }
    let body = http_get_async(url, timeout).await?;
    let report = evaluate(&body);
    let stdout = std::io::stdout();
    let mut h = stdout.lock();
    match format {
        "json" => {
            use std::fmt::Write as _;
            let mut s = String::with_capacity(512 + 128 * report.checks.len());
            s.push_str(r#"{"kind":"client_alerts_check","checks":["#);
            for (i, c) in report.checks.iter().enumerate() {
                if i > 0 {
                    s.push(',');
                }
                let safe_msg = c.message.replace('\\', "\\\\").replace('"', "\\\"");
                let _ = write!(
                    s,
                    r#"{{"rule":"{}","severity":"{}","message":"{}"}}"#,
                    c.rule_name, c.severity, safe_msg
                );
            }
            let (p, w, cr) = report.counts();
            let _ = write!(
                s,
                r#"],"totals":{{"pass":{p},"warn":{w},"crit":{cr}}},"exit_code":{ec}}}"#,
                ec = report.exit_code()
            );
            s.push('\n');
            write!(h, "{s}")?;
        }
        _ => {
            write!(h, "{report}")?;
        }
    }
    Ok(report.exit_code())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body_with(s: &str) -> String {
        format!("# HELP test test\n# TYPE test gauge\n{s}\n")
    }

    #[test]
    fn parse_metrics_handles_label_free_and_labelled_series() {
        let body = body_with(
            "proteus_client_up 1\nproteus_client_endpoint_suppressed{addr=\"vps1.example.com:8443\"} 0",
        );
        let m = parse_metrics(&body);
        assert_eq!(
            m.get(&("proteus_client_up".to_string(), String::new())),
            Some(&1.0)
        );
        assert_eq!(
            m.get(&(
                "proteus_client_endpoint_suppressed".to_string(),
                r#"addr="vps1.example.com:8443""#.to_string()
            )),
            Some(&0.0)
        );
    }

    #[test]
    fn evaluate_emits_crit_when_client_not_alive() {
        let r = evaluate(&body_with("proteus_client_up 0"));
        let c = r
            .checks
            .iter()
            .find(|c| c.rule_name == "ProteusClientNotAlive")
            .unwrap();
        assert_eq!(c.severity, CheckSeverity::Crit);
    }

    #[test]
    fn evaluate_emits_pass_when_client_alive() {
        let r = evaluate(&body_with("proteus_client_up 1"));
        let c = r
            .checks
            .iter()
            .find(|c| c.rule_name == "ProteusClientNotAlive")
            .unwrap();
        assert_eq!(c.severity, CheckSeverity::Pass);
    }

    /// Iter-101: client panic counter zero → PASS.
    #[test]
    fn iter101_client_panic_zero_passes() {
        let body = body_with("proteus_panics_total 0");
        let r = evaluate(&body);
        let pass = r
            .checks
            .iter()
            .find(|c| c.rule_name == "ProteusClientPanic")
            .expect("rule must fire when metric present");
        assert_eq!(pass.severity, CheckSeverity::Pass);
    }

    /// Iter-101: client panic counter nonzero → CRIT.
    #[test]
    fn iter101_client_panic_nonzero_crits() {
        let body = body_with("proteus_panics_total 3");
        let r = evaluate(&body);
        let crit = r
            .checks
            .iter()
            .find(|c| c.rule_name == "ProteusClientPanic")
            .expect("rule must fire");
        assert_eq!(crit.severity, CheckSeverity::Crit);
        assert!(crit.message.contains("3"));
        assert!(crit.message.contains("journalctl"));
    }

    /// Iter-101: metric absent → suppressed.
    #[test]
    fn iter101_client_panic_metric_absent_suppresses() {
        let body = body_with("proteus_client_up 1");
        let r = evaluate(&body);
        let any = r.checks.iter().any(|c| c.rule_name == "ProteusClientPanic");
        assert!(!any);
    }

    #[test]
    fn evaluate_emits_warn_when_beta_carrier_suppressed() {
        let body = body_with(
            "proteus_client_up 1\nproteus_client_carrier_suppressed 1\nproteus_client_carrier_failure_streak 3\nproteus_client_carrier_suppression_secs_remaining 25",
        );
        let r = evaluate(&body);
        let c = r
            .checks
            .iter()
            .find(|c| c.rule_name == "ProteusClientBetaCarrierSuppressed")
            .unwrap();
        assert_eq!(c.severity, CheckSeverity::Warn);
        assert!(c.message.contains("streak=3"));
        assert!(c.message.contains("25s"));
    }

    #[test]
    fn evaluate_emits_crit_when_all_endpoints_suppressed() {
        let body = body_with(
            "proteus_client_up 1\nproteus_client_endpoint_suppressed{addr=\"a\"} 1\nproteus_client_endpoint_suppressed{addr=\"b\"} 1\nproteus_client_endpoint_suppressed{addr=\"c\"} 1",
        );
        let r = evaluate(&body);
        let c = r
            .checks
            .iter()
            .find(|c| c.rule_name == "ProteusClientAllEndpointsSuppressed")
            .unwrap();
        assert_eq!(c.severity, CheckSeverity::Crit);
        assert!(c.message.contains("3/3"));
    }

    #[test]
    fn evaluate_emits_warn_when_partial_endpoints_suppressed() {
        let body = body_with(
            "proteus_client_up 1\nproteus_client_endpoint_suppressed{addr=\"a\"} 1\nproteus_client_endpoint_suppressed{addr=\"b\"} 0",
        );
        let r = evaluate(&body);
        let c = r
            .checks
            .iter()
            .find(|c| c.rule_name == "ProteusClientAllEndpointsSuppressed")
            .unwrap();
        assert_eq!(c.severity, CheckSeverity::Warn);
        assert!(c.message.contains("1/2"));
    }

    #[test]
    fn evaluate_emits_pass_when_endpoints_all_healthy() {
        let body = body_with(
            "proteus_client_up 1\nproteus_client_endpoint_suppressed{addr=\"a\"} 0\nproteus_client_endpoint_suppressed{addr=\"b\"} 0",
        );
        let r = evaluate(&body);
        let c = r
            .checks
            .iter()
            .find(|c| c.rule_name == "ProteusClientAllEndpointsSuppressed")
            .unwrap();
        assert_eq!(c.severity, CheckSeverity::Pass);
    }

    #[test]
    fn evaluate_emits_crit_when_no_dial_has_ever_succeeded() {
        let body = body_with(
            "proteus_client_up 1\nproteus_client_dials_attempted_total 10\nproteus_client_last_dial_success_unix_seconds 0",
        );
        let r = evaluate(&body);
        let c = r
            .checks
            .iter()
            .find(|c| c.rule_name == "ProteusClientNoRecentDialSuccess")
            .unwrap();
        assert_eq!(c.severity, CheckSeverity::Crit);
        assert!(c.message.contains("10"));
    }

    #[test]
    fn evaluate_skips_no_recent_dial_check_when_no_attempts() {
        // Fresh client with no SOCKS traffic yet — don't fire the
        // "no dial has succeeded" alert just because nothing has
        // been tried.
        let body = body_with(
            "proteus_client_up 1\nproteus_client_dials_attempted_total 0\nproteus_client_last_dial_success_unix_seconds 0",
        );
        let r = evaluate(&body);
        let any_no_dial = r
            .checks
            .iter()
            .any(|c| c.rule_name == "ProteusClientNoRecentDialSuccess");
        assert!(
            !any_no_dial,
            "must not emit ProteusClientNoRecentDialSuccess when nothing was attempted"
        );
    }

    #[test]
    fn evaluate_emits_warn_when_failures_exceed_successes() {
        let body = body_with(
            "proteus_client_up 1\nproteus_client_dials_succeeded_total 3\nproteus_client_dials_failed_total 8",
        );
        let r = evaluate(&body);
        let c = r
            .checks
            .iter()
            .find(|c| c.rule_name == "ProteusClientHighDialFailureRatio")
            .unwrap();
        assert_eq!(c.severity, CheckSeverity::Warn);
        assert!(c.message.contains("8 failed"));
    }

    #[test]
    fn evaluate_emits_warn_when_bootstrap_used_system_resolver() {
        let body = body_with(
            "proteus_client_up 1\nproteus_client_bootstrap_via_ip_literal_total 0\nproteus_client_bootstrap_via_system_resolver_total 5",
        );
        let r = evaluate(&body);
        let c = r
            .checks
            .iter()
            .find(|c| c.rule_name == "ProteusClientBootstrapViaSystemResolver")
            .unwrap();
        assert_eq!(c.severity, CheckSeverity::Warn);
        assert!(c.message.contains("DoH leak"));
        assert!(c.message.contains("direct_ip"));
    }

    #[test]
    fn evaluate_emits_warn_when_pool_reload_failing() {
        // attempts=5, succeeded=3 → gap=2 → WARN with concrete counts.
        let body = body_with(
            "proteus_client_up 1\nproteus_client_pool_reload_attempts_total 5\nproteus_client_pool_reload_succeeded_total 3",
        );
        let r = evaluate(&body);
        let c = r
            .checks
            .iter()
            .find(|c| c.rule_name == "ProteusClientPoolReloadFailing")
            .unwrap();
        assert_eq!(c.severity, CheckSeverity::Warn);
        assert!(c.message.contains("5 reload attempt"), "msg={}", c.message);
        assert!(c.message.contains("3 succeeded"), "msg={}", c.message);
        assert!(c.message.contains("2 failed"), "msg={}", c.message);
    }

    #[test]
    fn evaluate_emits_pass_when_pool_reload_all_succeeded() {
        // attempts == succeeded > 0 → PASS.
        let body = body_with(
            "proteus_client_up 1\nproteus_client_pool_reload_attempts_total 4\nproteus_client_pool_reload_succeeded_total 4",
        );
        let r = evaluate(&body);
        let c = r
            .checks
            .iter()
            .find(|c| c.rule_name == "ProteusClientPoolReloadFailing")
            .unwrap();
        assert_eq!(c.severity, CheckSeverity::Pass);
        assert!(c.message.contains("4"), "msg={}", c.message);
    }

    #[test]
    fn evaluate_skips_pool_reload_check_when_no_attempts() {
        // attempts == 0 → no SIGHUP yet → no signal to emit.
        // Same convention as ProteusClientNoRecentDialSuccess when
        // dials_attempted_total == 0.
        let body = body_with(
            "proteus_client_up 1\nproteus_client_pool_reload_attempts_total 0\nproteus_client_pool_reload_succeeded_total 0",
        );
        let r = evaluate(&body);
        let any = r
            .checks
            .iter()
            .any(|c| c.rule_name == "ProteusClientPoolReloadFailing");
        assert!(
            !any,
            "must NOT emit ProteusClientPoolReloadFailing when no reload was attempted"
        );
    }

    /// Pool-reload failure is WARN-only — it does NOT escalate
    /// the overall exit code to 1. The dispatcher is still
    /// serving the previous-known-good pool; the failure is
    /// "your edit didn't take effect", not "we're down".
    #[test]
    fn evaluate_pool_reload_warn_does_not_force_crit_exit() {
        let body = body_with(
            "proteus_client_up 1\nproteus_client_pool_reload_attempts_total 3\nproteus_client_pool_reload_succeeded_total 1",
        );
        let r = evaluate(&body);
        assert_eq!(
            r.exit_code(),
            0,
            "warn-only rules must not escalate to exit 1"
        );
        let (_, w, cr) = r.counts();
        assert!(w >= 1);
        assert_eq!(cr, 0);
    }

    #[test]
    fn evaluate_exit_code_zero_when_no_crit() {
        let body = body_with("proteus_client_up 1");
        let r = evaluate(&body);
        assert_eq!(r.exit_code(), 0);
    }

    #[test]
    fn evaluate_exit_code_one_when_any_crit() {
        let r = evaluate(&body_with("proteus_client_up 0"));
        assert_eq!(r.exit_code(), 1);
    }

    #[test]
    fn report_display_includes_summary_line() {
        let body = body_with("proteus_client_up 1");
        let r = evaluate(&body);
        let s = format!("{r}");
        assert!(s.contains("summary:"));
        assert!(s.contains("exit"));
    }

    /// Iter-116: client alerts-check parse_http_url HTTPS
    /// rejection now actionable.
    #[test]
    fn iter116_parse_https_rejected_with_actionable_msg() {
        let err = parse_http_url("https://127.0.0.1:9091").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("HTTP-only") && msg.contains("loopback"),
            "iter-116 must explain HTTPS rejection: {msg}"
        );
    }

    #[test]
    fn iter116_parse_missing_scheme_rejected_with_actionable_msg() {
        let err = parse_http_url("127.0.0.1:9091").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("http://") && msg.contains("scheme"),
            "iter-116 must explain missing scheme: {msg}"
        );
    }

    #[test]
    fn iter116_parse_bad_port_rejected_with_actionable_msg() {
        let err = parse_http_url("http://127.0.0.1:99999").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("99999") && msg.contains("u16"),
            "iter-116 must name bad port + valid range: {msg}"
        );
    }

    /// Iter-159: empty host (`http://:9091`) previously parsed
    /// cleanly with host="". Symmetric with the iter-116
    /// server-side gate.
    #[test]
    fn iter159_parse_empty_host_rejected() {
        let err = parse_http_url("http://:9091").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("host portion is empty"),
            "iter-159: empty host must reject: {msg}"
        );
    }

    /// Iter-159: port 0 is invalid as a TCP-connect target.
    /// Symmetric with the iter-158 cover-endpoint port-0 gate.
    #[test]
    fn iter159_parse_port_zero_rejected() {
        let err = parse_http_url("http://127.0.0.1:0").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("port 0 is invalid"),
            "iter-159: port 0 must reject: {msg}"
        );
    }

    /// Iter-159 regression: legit URLs still parse.
    #[test]
    fn iter159_well_formed_urls_still_parse() {
        for url in [
            "http://127.0.0.1:9091",
            "http://127.0.0.1:1",
            "http://127.0.0.1:65535",
            "http://localhost:9091/status",
        ] {
            assert!(
                parse_http_url(url).is_ok(),
                "iter-159: legit URL {url:?} must parse"
            );
        }
    }

    /// Iter-114: unknown --format errors BEFORE any network I/O.
    /// We use a bogus URL to prove the early-return path: if
    /// format validation happened AFTER the network attempt,
    /// the test would either succeed (network down on bogus
    /// URL → some other error) or hang.
    #[tokio::test]
    async fn iter114_alerts_check_rejects_unknown_format() {
        let result = cli_run(
            "http://127.0.0.1:1",
            std::time::Duration::from_secs(1),
            "yaml",
        )
        .await;
        let err = result.expect_err("must error on bad format");
        let msg = err.to_string();
        assert!(
            msg.contains("yaml") && msg.contains("text") && msg.contains("json"),
            "error must name the bad format + valid alternatives: {msg}"
        );
    }
}
