//! `proteus-server admin alerts-check` — run the bundled alert
//! rules against a one-shot /metrics scrape.
//!
//! ## Why this exists
//!
//! The bundled `deploy/prometheus/proteus-alerts.yaml` is the
//! canonical production-alerting surface, but operators don't
//! always have a full Prometheus stack standing up — especially
//! for:
//!
//!   * fresh deploys: "did my new server come up clean?"
//!   * incident triage: "which of the documented alerts is
//!     ACTIVELY firing right now?"
//!   * CI / Ansible smoke tests: "the binary started, but is
//!     anything obviously broken before I tag it green?"
//!
//! Standing up Prometheus + Alertmanager for the above is heavy.
//! This command does a single `/metrics` scrape, evaluates the
//! same alert conditions in-process, and reports per-rule
//! verdict in 50-200 ms.
//!
//! ## What it is NOT
//!
//! - Not a Prometheus replacement. It's a one-shot point-in-time
//!   evaluation; the real `rate(...[5m])` queries need a TSDB.
//!   Rate-based alerts here are approximated by "is the counter
//!   currently NON-zero AND has the metric been observed at all"
//!   — coarse but useful for the operator triage use case.
//! - Not a complete reimplementation of every alert in the YAML.
//!   The set here is the small fixed list of POINT-IN-TIME
//!   checkable conditions: TLS cert expired/expiring, panic
//!   counter non-zero, restart_count delta non-zero in this
//!   process lifetime, previous_run_unclean=1, writer_alive=0.
//!   For full rate-based evaluation operators wire the YAML into
//!   their existing Prometheus.
//!
//! ## Output formats
//!
//! - `text` (default): one line per check, with PASS / WARN /
//!   CRIT severity prefix + message. Summary line at the end.
//! - `json`: single JSON document with `{ checks: [...],
//!   totals: {...}, exit_code: N }` for scripted gates.
//!
//! Exit code: 0 on PASS+WARN-only, 1 on any CRIT.

use std::fmt;
use std::io::Write;
use std::time::Duration;

use crate::admin::{http_get, AdminError};

/// Verdict for a single alert check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckSeverity {
    Pass,
    Warn,
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

/// A single alert verdict. `rule_name` matches the corresponding
/// alert in `deploy/prometheus/proteus-alerts.yaml` so operators
/// can cross-reference. `expr` is the PromQL the bundled file
/// uses — useful when the operator wants to deepen the
/// investigation with a real TSDB query.
#[derive(Debug, Clone)]
pub struct Check {
    pub rule_name: &'static str,
    pub severity: CheckSeverity,
    pub message: String,
    /// PromQL expression from the bundled rule, for operator
    /// cross-reference. Empty string when the in-process check
    /// is a POINT-IN-TIME approximation that doesn't map 1:1
    /// to a single PromQL line.
    pub equivalent_promql: &'static str,
}

/// Aggregate report. `(pass, warn, crit)` counts via
/// [`Report::counts`].
#[derive(Debug, Clone, Default)]
pub struct Report {
    pub checks: Vec<Check>,
}

impl Report {
    pub fn push(&mut self, c: Check) {
        self.checks.push(c);
    }

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
/// (metric_name, labels-string-or-empty) → numeric value. We
/// deliberately don't pull in a full Prometheus parser — the
/// exposition format is simple enough that 30 lines does the
/// job for our handful of metrics.
pub fn parse_metrics(body: &str) -> std::collections::HashMap<(String, String), f64> {
    let mut out = std::collections::HashMap::new();
    for line in body.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // Format options:
        //   metric_name value
        //   metric_name{label="..."} value
        // Find the first '{' or first ' ' to decide.
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
        // The value is whitespace-separated; some Prometheus
        // exporters also emit a trailing timestamp. We take the
        // FIRST whitespace token.
        let val_token = value_str.split_whitespace().next().unwrap_or("");
        if let Ok(v) = val_token.parse::<f64>() {
            out.insert((name, labels), v);
        }
    }
    out
}

/// Evaluate every supported alert against the parsed /metrics
/// body. Returns a [`Report`] with one [`Check`] per rule.
pub fn evaluate(body: &str) -> Report {
    let m = parse_metrics(body);
    let mut r = Report::default();

    // Helper: lookup a label-free series.
    let g = |name: &str| -> Option<f64> { m.get(&(name.to_string(), String::new())).copied() };

    // ──── ProteusServerUnhealthy ────
    if let Some(v) = g("proteus_up") {
        if v == 0.0 {
            r.push(Check {
                rule_name: "ProteusServerUnhealthy",
                severity: CheckSeverity::Crit,
                message: "proteus_up == 0 — process reports unhealthy".to_string(),
                equivalent_promql: "proteus_up == 0",
            });
        } else {
            r.push(Check {
                rule_name: "ProteusServerUnhealthy",
                severity: CheckSeverity::Pass,
                message: "proteus_up == 1".to_string(),
                equivalent_promql: "proteus_up == 0",
            });
        }
    }

    // ──── ProteusTlsCertExpired / ExpiringSoon ────
    if let Some(not_after) = g("proteus_tls_cert_not_after_unix_seconds") {
        // Filter the "no cert configured" sentinel (0).
        if not_after > 0.0 {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as f64)
                .unwrap_or(0.0);
            let secs_until = not_after - now;
            if secs_until <= 0.0 {
                r.push(Check {
                    rule_name: "ProteusTlsCertExpired",
                    severity: CheckSeverity::Crit,
                    message: format!(
                        "TLS cert EXPIRED {} days ago — every TLS handshake will fail",
                        (-secs_until / 86_400.0) as i64
                    ),
                    equivalent_promql: "proteus_tls_cert_not_after_unix_seconds < time()",
                });
            } else if secs_until < 14.0 * 86_400.0 {
                r.push(Check {
                    rule_name: "ProteusTlsCertExpiringSoon",
                    severity: CheckSeverity::Warn,
                    message: format!(
                        "TLS cert expires in {} days — verify auto-renewal is wired",
                        (secs_until / 86_400.0) as i64
                    ),
                    equivalent_promql:
                        "proteus_tls_cert_not_after_unix_seconds - time() < 14*86400",
                });
            } else {
                r.push(Check {
                    rule_name: "ProteusTlsCertExpiringSoon",
                    severity: CheckSeverity::Pass,
                    message: format!("TLS cert valid for {} days", (secs_until / 86_400.0) as i64),
                    equivalent_promql: "",
                });
            }
        }
    }

    // ──── ProteusTlsAutoReloadFailing ────
    // POINT-IN-TIME approximation: failed_total > 0 at any
    // observation means the file watcher has SOMETIME failed.
    // The rate-based real alert needs Prometheus; here we
    // warn if the counter is non-zero.
    if let Some(v) = g("proteus_tls_cert_watcher_auto_reload_failed_total") {
        let sev = if v > 0.0 {
            CheckSeverity::Warn
        } else {
            CheckSeverity::Pass
        };
        let msg = if v > 0.0 {
            format!("{v} cert auto-reload failure(s) since start — check journalctl")
        } else {
            "no cert auto-reload failures observed".to_string()
        };
        r.push(Check {
            rule_name: "ProteusTlsAutoReloadFailing",
            severity: sev,
            message: msg,
            equivalent_promql: "rate(proteus_tls_cert_watcher_auto_reload_failed_total[10m]) > 0",
        });
    }

    // ──── ProteusPanic ────
    if let Some(v) = g("proteus_panics_total") {
        let sev = if v > 0.0 {
            CheckSeverity::Crit
        } else {
            CheckSeverity::Pass
        };
        let msg = if v > 0.0 {
            format!("{v} panic(s) captured since process start — `journalctl -u proteus-server -o json | jq 'select(.target==\"proteus_panic\")'`")
        } else {
            "no panics captured".to_string()
        };
        r.push(Check {
            rule_name: "ProteusPanic",
            severity: sev,
            message: msg,
            equivalent_promql: "rate(proteus_panics_total[5m]) > 0",
        });
    }

    // ──── ProteusUncleanShutdown ────
    if let Some(v) = g("proteus_previous_run_unclean") {
        if v >= 1.0 {
            r.push(Check {
                rule_name: "ProteusUncleanShutdown",
                severity: CheckSeverity::Warn,
                message: "previous run exited uncleanly (panic-abort / OOM kill / segfault / kill -9) — investigate the previous journal window".to_string(),
                equivalent_promql: "proteus_previous_run_unclean == 1",
            });
        } else {
            r.push(Check {
                rule_name: "ProteusUncleanShutdown",
                severity: CheckSeverity::Pass,
                message: "previous shutdown was clean".to_string(),
                equivalent_promql: "",
            });
        }
    }

    // ──── ProteusAccessLogWriterDead ────
    if let Some(alive) = g("proteus_access_log_writer_alive") {
        // Only meaningful when access_log is configured (the
        // series is only emitted in that case). The metric being
        // absent → no check emitted.
        if alive < 1.0 {
            r.push(Check {
                rule_name: "ProteusAccessLogWriterDead",
                severity: CheckSeverity::Crit,
                message: "access-log writer task is DEAD — every subsequent session is dropping its audit record. Free disk / fix log permissions, then `systemctl restart proteus-server`".to_string(),
                equivalent_promql:
                    "proteus_access_log_writer_alive == 0 and proteus_up == 1",
            });
        } else {
            r.push(Check {
                rule_name: "ProteusAccessLogWriterDead",
                severity: CheckSeverity::Pass,
                message: "access-log writer alive".to_string(),
                equivalent_promql: "",
            });
        }
    }

    // ──── ProteusDnsResolverWedged (point-in-time approx) ────
    let dns_timeouts = m
        .get(&(
            "proteus_dns_lookups_total".to_string(),
            r#"outcome="timeout""#.to_string(),
        ))
        .copied()
        .unwrap_or(0.0);
    let dns_ok = m
        .get(&(
            "proteus_dns_lookups_total".to_string(),
            r#"outcome="ok""#.to_string(),
        ))
        .copied()
        .unwrap_or(0.0);
    let dns_failed = m
        .get(&(
            "proteus_dns_lookups_total".to_string(),
            r#"outcome="failed""#.to_string(),
        ))
        .copied()
        .unwrap_or(0.0);
    if dns_timeouts + dns_ok + dns_failed > 0.0 {
        if dns_timeouts > 0.0 {
            r.push(Check {
                rule_name: "ProteusDnsResolverWedged",
                severity: CheckSeverity::Warn,
                message: format!(
                    "{dns_timeouts} DNS lookup timeout(s) observed (out of {} total) — recursive resolver may be wedged",
                    (dns_timeouts + dns_ok + dns_failed) as u64
                ),
                equivalent_promql:
                    "rate(proteus_dns_lookups_total{outcome=\"timeout\"}[5m]) > 0",
            });
        } else {
            r.push(Check {
                rule_name: "ProteusDnsResolverWedged",
                severity: CheckSeverity::Pass,
                message: format!(
                    "no DNS lookup timeouts ({} lookups, {} failed)",
                    (dns_timeouts + dns_ok + dns_failed) as u64,
                    dns_failed as u64
                ),
                equivalent_promql: "",
            });
        }
    }

    // ──── Iter-32: ProteusCoverForwardRejecting ────
    //
    // Mirrors the bundled Prometheus rule (iter-26) that
    // alerts when the iter-20 cover-forward semaphore drops
    // rejections. Point-in-time: any non-zero value of the
    // rejections counter means the cap was hit at some point
    // since process start. Operators reading the alerts-check
    // output get the same surface signal they'd see from
    // their Prometheus stack — useful for the "no Prometheus
    // available, just curl /metrics + run alerts-check
    // locally" deploy path.
    if let Some(rejected) = g("proteus_cover_forwards_rejected_total") {
        if rejected > 0.0 {
            r.push(Check {
                rule_name: "ProteusCoverForwardRejecting",
                severity: CheckSeverity::Warn,
                message: format!(
                    "{rejected} cover-forward request(s) rejected since start — either `max_cover_forwards` cap too low OR cover endpoint slow/unhealthy (cover tasks not exiting → semaphore drained)"
                ),
                equivalent_promql: "rate(proteus_cover_forwards_rejected_total[5m]) > 0",
            });
        } else {
            r.push(Check {
                rule_name: "ProteusCoverForwardRejecting",
                severity: CheckSeverity::Pass,
                message: "no cover-forward rejections — cap holding".to_string(),
                equivalent_promql: "",
            });
        }
    }

    // ──── Iter-32: ProteusCoverForwardStorm (point-in-time approx) ────
    //
    // The bundled Prometheus rule is `rate(proteus_cover_forwards_total[5m]) > 100`
    // — a sustained-rate signal. We can't compute rate from a
    // single-scrape /metrics body without a baseline, so we
    // approximate: a HIGH absolute count of cover_forwards
    // since process start signals "this box has handled a lot
    // of probes — go look at recent rate via Prometheus." The
    // 10k threshold below is operator-tunable in the bundled
    // alert (100/sec × 60s × 1.6 minutes typical alert
    // latency = ~10k) and chosen here to match the alert's
    // intent without producing false positives on a freshly-
    // restarted box.
    if let Some(forwards) = g("proteus_cover_forwards_total") {
        // Threshold: 10k cumulative cover-forwards since start.
        // For long-running processes this is operator-relevant;
        // for processes < 1 hour old it's nearly always
        // unreached.
        const STORM_THRESHOLD: f64 = 10_000.0;
        if forwards >= STORM_THRESHOLD {
            r.push(Check {
                rule_name: "ProteusCoverForwardStorm",
                severity: CheckSeverity::Warn,
                message: format!(
                    "{} cumulative cover-forwards since start — this box is likely under sustained probing. Cross-reference proteus_probe_anomalies_fired_total for /24 prefix sources.",
                    forwards as u64
                ),
                equivalent_promql: "rate(proteus_cover_forwards_total[5m]) > 100",
            });
        } else {
            r.push(Check {
                rule_name: "ProteusCoverForwardStorm",
                severity: CheckSeverity::Pass,
                message: format!(
                    "{} cumulative cover-forwards (under {} threshold)",
                    forwards as u64, STORM_THRESHOLD as u64
                ),
                equivalent_promql: "",
            });
        }
    }

    r
}

/// CLI entry. Scrapes `url` (Bearer-token via `token`), evaluates
/// every supported alert, prints the report in the requested
/// format, and returns the exit code.
pub fn cli_run(
    url: &str,
    token: Option<&str>,
    timeout: Duration,
    format: &str,
) -> Result<i32, AdminError> {
    let body = http_get(url, token, timeout)?;
    let report = evaluate(&body);
    let stdout = std::io::stdout();
    let mut h = stdout.lock();
    match format {
        "json" => {
            use std::fmt::Write as _;
            let mut s = String::with_capacity(512 + 128 * report.checks.len());
            s.push_str(r#"{"kind":"alerts_check","checks":["#);
            for (i, c) in report.checks.iter().enumerate() {
                if i > 0 {
                    s.push(',');
                }
                let safe_msg = c.message.replace('\\', "\\\\").replace('"', "\\\"");
                let _ = write!(
                    s,
                    r#"{{"rule":"{}","severity":"{}","message":"{}","equivalent_promql":"{}"}}"#,
                    c.rule_name,
                    c.severity,
                    safe_msg,
                    c.equivalent_promql.replace('"', "\\\"")
                );
            }
            let (p, w, cr) = report.counts();
            let _ = write!(
                s,
                r#"],"totals":{{"pass":{p},"warn":{w},"crit":{cr}}},"exit_code":{ec}}}"#,
                ec = report.exit_code()
            );
            s.push('\n');
            write!(h, "{s}").map_err(AdminError::Write)?;
        }
        _ => {
            write!(h, "{report}").map_err(AdminError::Write)?;
        }
    }
    Ok(report.exit_code())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body_with(s: &str) -> String {
        // Minimum-valid /metrics-style body: comment lines + the
        // operator-supplied series. Mirrors what
        // ServerMetrics::prometheus emits.
        format!("# HELP test test\n# TYPE test gauge\n{s}\n")
    }

    #[test]
    fn parse_metrics_handles_label_free_and_labelled_series() {
        let body = body_with(
            "proteus_up 1\nproteus_panics_total 5\nproteus_dns_lookups_total{outcome=\"ok\"} 10",
        );
        let m = parse_metrics(&body);
        assert_eq!(
            m.get(&("proteus_up".to_string(), "".to_string())),
            Some(&1.0)
        );
        assert_eq!(
            m.get(&("proteus_panics_total".to_string(), "".to_string())),
            Some(&5.0)
        );
        assert_eq!(
            m.get(&(
                "proteus_dns_lookups_total".to_string(),
                r#"outcome="ok""#.to_string()
            )),
            Some(&10.0)
        );
    }

    #[test]
    fn parse_metrics_skips_comments_and_blanks() {
        let body = "# HELP foo bar\n\n# TYPE foo gauge\nfoo 42\n";
        let m = parse_metrics(body);
        assert_eq!(m.get(&("foo".to_string(), "".to_string())), Some(&42.0));
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn parse_metrics_ignores_unparseable_value() {
        let body = "good 1\nbad NOT_A_NUMBER\nalso_good 2\n";
        let m = parse_metrics(body);
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn evaluate_emits_crit_when_proteus_up_is_zero() {
        let body = body_with("proteus_up 0");
        let r = evaluate(&body);
        let unhealthy = r
            .checks
            .iter()
            .find(|c| c.rule_name == "ProteusServerUnhealthy")
            .expect("ProteusServerUnhealthy check must fire");
        assert_eq!(unhealthy.severity, CheckSeverity::Crit);
    }

    #[test]
    fn evaluate_emits_pass_when_proteus_up_is_one() {
        let body = body_with("proteus_up 1");
        let r = evaluate(&body);
        let unhealthy = r
            .checks
            .iter()
            .find(|c| c.rule_name == "ProteusServerUnhealthy")
            .expect("expected ProteusServerUnhealthy as PASS");
        assert_eq!(unhealthy.severity, CheckSeverity::Pass);
    }

    #[test]
    fn evaluate_emits_crit_when_panics_total_is_nonzero() {
        let body = body_with("proteus_panics_total 3");
        let r = evaluate(&body);
        let c = r
            .checks
            .iter()
            .find(|c| c.rule_name == "ProteusPanic")
            .unwrap();
        assert_eq!(c.severity, CheckSeverity::Crit);
        assert!(c.message.contains("3 panic"));
    }

    #[test]
    fn evaluate_emits_warn_when_previous_run_unclean() {
        let body = body_with("proteus_previous_run_unclean 1");
        let r = evaluate(&body);
        let c = r
            .checks
            .iter()
            .find(|c| c.rule_name == "ProteusUncleanShutdown")
            .unwrap();
        assert_eq!(c.severity, CheckSeverity::Warn);
    }

    #[test]
    fn evaluate_emits_crit_when_tls_cert_expired() {
        // Pick a notAfter well in the past.
        let body = body_with("proteus_tls_cert_not_after_unix_seconds 1000000000");
        let r = evaluate(&body);
        let c = r
            .checks
            .iter()
            .find(|c| c.rule_name == "ProteusTlsCertExpired")
            .unwrap();
        assert_eq!(c.severity, CheckSeverity::Crit);
        assert!(c.message.contains("EXPIRED"));
    }

    #[test]
    fn evaluate_emits_warn_when_tls_cert_in_renewal_window() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // 7 days in the future.
        let body = body_with(&format!(
            "proteus_tls_cert_not_after_unix_seconds {}",
            now + 7 * 86_400
        ));
        let r = evaluate(&body);
        let c = r
            .checks
            .iter()
            .find(|c| c.rule_name == "ProteusTlsCertExpiringSoon")
            .unwrap();
        assert_eq!(c.severity, CheckSeverity::Warn);
        assert!(c.message.contains("7 days") || c.message.contains("6 days"));
    }

    #[test]
    fn evaluate_emits_pass_when_tls_cert_far_in_future() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let body = body_with(&format!(
            "proteus_tls_cert_not_after_unix_seconds {}",
            now + 90 * 86_400
        ));
        let r = evaluate(&body);
        let c = r
            .checks
            .iter()
            .find(|c| c.rule_name == "ProteusTlsCertExpiringSoon")
            .unwrap();
        assert_eq!(c.severity, CheckSeverity::Pass);
    }

    #[test]
    fn evaluate_emits_crit_when_access_log_writer_dead() {
        let body = body_with("proteus_access_log_writer_alive 0");
        let r = evaluate(&body);
        let c = r
            .checks
            .iter()
            .find(|c| c.rule_name == "ProteusAccessLogWriterDead")
            .unwrap();
        assert_eq!(c.severity, CheckSeverity::Crit);
    }

    #[test]
    fn evaluate_emits_warn_when_dns_timeouts_observed() {
        let body = body_with(
            "proteus_dns_lookups_total{outcome=\"ok\"} 100\nproteus_dns_lookups_total{outcome=\"timeout\"} 5",
        );
        let r = evaluate(&body);
        let c = r
            .checks
            .iter()
            .find(|c| c.rule_name == "ProteusDnsResolverWedged")
            .unwrap();
        assert_eq!(c.severity, CheckSeverity::Warn);
    }

    #[test]
    fn evaluate_skips_access_log_check_when_metric_absent() {
        // No proteus_access_log_writer_alive line → no check
        // emitted (operator didn't configure access_log).
        let body = body_with("proteus_up 1");
        let r = evaluate(&body);
        let has_access_log_check = r
            .checks
            .iter()
            .any(|c| c.rule_name == "ProteusAccessLogWriterDead");
        assert!(
            !has_access_log_check,
            "access-log check must be skipped when the metric isn't emitted"
        );
    }

    #[test]
    fn exit_code_zero_when_no_crit() {
        let body =
            body_with("proteus_up 1\nproteus_panics_total 0\nproteus_previous_run_unclean 0");
        let r = evaluate(&body);
        assert_eq!(r.exit_code(), 0);
    }

    #[test]
    fn exit_code_one_when_any_crit() {
        let body = body_with("proteus_up 0");
        let r = evaluate(&body);
        assert_eq!(r.exit_code(), 1);
    }

    #[test]
    fn report_display_includes_summary_line() {
        let body = body_with("proteus_up 1\nproteus_panics_total 1");
        let r = evaluate(&body);
        let s = format!("{r}");
        assert!(s.contains("summary:"));
        assert!(s.contains("exit"));
    }

    // ──── Iter-32: ProteusCoverForwardRejecting checks ────

    /// Non-zero `cover_forwards_rejected_total` must fire the
    /// iter-26 alert as WARN. Without this evaluation the
    /// `proteus-server admin alerts-check` CLI would silently
    /// pass even when the iter-20 cover-forward semaphore was
    /// dropping rejections in production.
    #[test]
    fn iter32_evaluate_warns_when_cover_forwards_rejected_nonzero() {
        let body = body_with("proteus_cover_forwards_rejected_total 42");
        let r = evaluate(&body);
        let c = r
            .checks
            .iter()
            .find(|c| c.rule_name == "ProteusCoverForwardRejecting")
            .expect("ProteusCoverForwardRejecting check must fire");
        assert_eq!(c.severity, CheckSeverity::Warn);
        assert!(c.message.contains("42"));
    }

    /// Zero rejections → PASS (cap is holding, all good).
    #[test]
    fn iter32_evaluate_passes_when_cover_forwards_rejected_zero() {
        let body = body_with("proteus_cover_forwards_rejected_total 0");
        let r = evaluate(&body);
        let c = r
            .checks
            .iter()
            .find(|c| c.rule_name == "ProteusCoverForwardRejecting")
            .expect("ProteusCoverForwardRejecting check must fire even at zero");
        assert_eq!(c.severity, CheckSeverity::Pass);
    }

    /// Counter absent → check skipped (no metric → no
    /// alert). This matches the pattern other checks use for
    /// optional metrics.
    #[test]
    fn iter32_evaluate_skips_cover_forward_rejecting_when_metric_absent() {
        let body = body_with("proteus_up 1"); // no cover_forwards_rejected
        let r = evaluate(&body);
        assert!(
            r.checks
                .iter()
                .all(|c| c.rule_name != "ProteusCoverForwardRejecting"),
            "iter-32: should NOT emit a check when the metric is absent"
        );
    }

    // ──── Iter-32: ProteusCoverForwardStorm checks ────

    #[test]
    fn iter32_evaluate_warns_on_storm_threshold_exceeded() {
        let body = body_with("proteus_cover_forwards_total 50000");
        let r = evaluate(&body);
        let c = r
            .checks
            .iter()
            .find(|c| c.rule_name == "ProteusCoverForwardStorm")
            .expect("ProteusCoverForwardStorm check must fire");
        assert_eq!(c.severity, CheckSeverity::Warn);
        assert!(c.message.contains("50000"));
    }

    #[test]
    fn iter32_evaluate_passes_under_storm_threshold() {
        let body = body_with("proteus_cover_forwards_total 100");
        let r = evaluate(&body);
        let c = r
            .checks
            .iter()
            .find(|c| c.rule_name == "ProteusCoverForwardStorm")
            .expect("ProteusCoverForwardStorm check must fire even below threshold");
        assert_eq!(c.severity, CheckSeverity::Pass);
    }
}
