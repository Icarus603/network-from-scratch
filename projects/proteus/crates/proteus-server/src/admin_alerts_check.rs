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

    // ──── ProteusSighupReloadFailing (×4 limiter+firewall) ────
    // Four SIGHUP-reloadable surfaces, each backed by its own
    // (attempts_total, succeeded_total) counter pair. The TLS
    // file-watcher has its own dedicated alert above
    // (ProteusTlsAutoReloadFailing) because it's mtime-driven,
    // not SIGHUP-driven; these four are operator-edit driven and
    // share the same "silent edit didn't take effect" failure
    // mode the client-side ProteusClientPoolReloadFailing covers
    // for server_endpoints.
    //
    // WARN-not-CRIT because the previous-known-good config is
    // still running; the operator's edit is silently ineffective
    // but service isn't down.
    //
    // Suppress entirely when att == 0 (no SIGHUP yet), matching
    // the convention used for ProteusClientNoRecentDialSuccess /
    // ProteusClientPoolReloadFailing.
    for (rule_name, metric_prefix, friendly) in [
        (
            "ProteusFirewallReloadFailing",
            "proteus_firewall_reload",
            "firewall (allow/deny lists)",
        ),
        (
            "ProteusRateLimitReloadFailing",
            "proteus_rate_limit_reload",
            "global rate-limit config",
        ),
        (
            "ProteusUserRateLimitReloadFailing",
            "proteus_user_rate_limit_reload",
            "per-user rate-limit config",
        ),
        (
            "ProteusHandshakeBudgetReloadFailing",
            "proteus_handshake_budget_reload",
            "handshake budget config",
        ),
    ] {
        let att = g(&format!("{metric_prefix}_attempts_total")).unwrap_or(0.0);
        let ok = g(&format!("{metric_prefix}_succeeded_total")).unwrap_or(0.0);
        if att > 0.0 {
            let gap = att - ok;
            if gap > 0.0 {
                r.push(Check {
                    rule_name,
                    severity: CheckSeverity::Warn,
                    message: format!(
                        "{} reload attempt(s) on {friendly}, only {} succeeded ({} failed) — running config is still the pre-SIGHUP version. Check journalctl for the parse error.",
                        att as u64,
                        ok as u64,
                        gap as u64,
                    ),
                    equivalent_promql:
                        "(<prefix>_attempts_total - <prefix>_succeeded_total) > 0",
                });
            } else {
                r.push(Check {
                    rule_name,
                    severity: CheckSeverity::Pass,
                    message: format!(
                        "all {} {friendly} reload attempt(s) succeeded",
                        att as u64
                    ),
                    equivalent_promql: "",
                });
            }
        }
    }

    // ──── ProteusProbeAnomalyFired / Catastrophic ────
    //
    // Iter-81: per-/24 probe-anomaly attribution. Same shape
    // as the iter-76 SSRF check: cumulative counter →
    // PASS / WARN / CRIT tiers based on absolute count
    // (in-process check can't compute rate).
    if let Some(fired) = g("proteus_probe_anomalies_fired_total") {
        if fired > 50.0 {
            r.push(Check {
                rule_name: "ProteusProbeAnomalyCatastrophic",
                severity: CheckSeverity::Crit,
                message: format!(
                    "{fired} probe-anomaly fires since process start — sustained \
                     coordinated probing campaign. Identify offending /24(s) from \
                     access_log + structured probe_anomaly log lines, then \
                     `firewall.deny: [<cidr>/24]` + SIGHUP. Consider raising \
                     pow_difficulty + tightening max_cover_forwards."
                ),
                equivalent_promql: "rate(proteus_probe_anomalies_fired_total[5m]) > 1",
            });
        } else if fired > 0.0 {
            r.push(Check {
                rule_name: "ProteusProbeAnomalyFired",
                severity: CheckSeverity::Warn,
                message: format!(
                    "{fired} probe-anomaly fire(s) since process start — at least one \
                     /24 source range produced sustained cover-forward bursts. Use \
                     access_log to identify + firewall-deny."
                ),
                equivalent_promql: "rate(proteus_probe_anomalies_fired_total[5m]) > 0",
            });
        } else {
            r.push(Check {
                rule_name: "ProteusProbeAnomalyFired",
                severity: CheckSeverity::Pass,
                message: "no probe-anomaly fires observed".to_string(),
                equivalent_promql: "",
            });
        }
    }

    // ──── ProteusAbuseAlerts{ByteBudget,RateLimit,Bandwidth} ────
    //
    // Iter-79: per-user abuse-detector fires. Each surface ships
    // a cumulative counter; the in-process check surfaces ANY
    // non-zero as WARN (operator-facing signal of "investigate
    // user_id X" via access_log).
    for (rule_name, metric, friendly) in [
        (
            "ProteusAbuseAlertsByteBudget",
            "proteus_abuse_alerts_byte_budget_total",
            "byte-budget",
        ),
        (
            "ProteusAbuseAlertsRateLimit",
            "proteus_abuse_alerts_rate_limit_total",
            "rate-limit",
        ),
        (
            "ProteusAbuseAlertsBandwidth",
            "proteus_abuse_alerts_per_user_bandwidth_total",
            "bandwidth-rate",
        ),
    ] {
        if let Some(v) = g(metric) {
            if v > 0.0 {
                r.push(Check {
                    rule_name,
                    severity: CheckSeverity::Warn,
                    message: format!(
                        "{v} {friendly} abuse fire(s) since process start — the per-user \
                         {friendly} detector tripped repeatedly within its sliding window. \
                         Audit access_log for the offending user_id; rotate credential if \
                         compromise suspected."
                    ),
                    equivalent_promql: "rate({metric}[5m]) > 0",
                });
            } else {
                r.push(Check {
                    rule_name,
                    severity: CheckSeverity::Pass,
                    message: format!("no {friendly} abuse fires observed"),
                    equivalent_promql: "",
                });
            }
        }
    }

    // ──── ProteusSsrfAttemptsObserved / Catastrophic ────
    //
    // Iter-76: point-in-time approximation. We can't compute
    // rate(5m) without a TSDB; instead surface ANY non-zero
    // outbound_blocked counter as WARN, and flag a "high"
    // threshold (>100 cumulative blocks) as CRIT. Operators
    // running alerts-check on a fresh boot won't trip false
    // positives because both metrics start at zero.
    if let Some(blocked) = g("proteus_outbound_blocked_total") {
        if blocked > 100.0 {
            r.push(Check {
                rule_name: "ProteusSsrfAttemptsCatastrophic",
                severity: CheckSeverity::Crit,
                message: format!(
                    "{blocked} outbound-filter blocks since process start — sustained \
                     SSRF probing observed. Treat as credential compromise: rotate the \
                     affected user's ed25519 key, audit access_log for destination \
                     pattern, consider firewall deny on source IP."
                ),
                equivalent_promql: "rate(proteus_outbound_blocked_total[5m]) > 1",
            });
        } else if blocked > 0.0 {
            r.push(Check {
                rule_name: "ProteusSsrfAttemptsObserved",
                severity: CheckSeverity::Warn,
                message: format!(
                    "{blocked} outbound-filter block(s) since process start — SSRF or \
                     internal-network probing observed. Causes: (a) credential compromised \
                     + attacker probing internal network via proxy; (b) misconfigured \
                     client. Audit access_log for the destination + user_id."
                ),
                equivalent_promql: "rate(proteus_outbound_blocked_total[5m]) > 0",
            });
        } else {
            r.push(Check {
                rule_name: "ProteusSsrfAttemptsObserved",
                severity: CheckSeverity::Pass,
                message: "no SSRF / outbound-filter blocks observed".to_string(),
                equivalent_promql: "",
            });
        }
    }

    // ──── ProteusHandshakeLatencyHigh / Catastrophic ────
    //
    // Iter-74: point-in-time approximation of the Prometheus
    // `histogram_quantile(0.99, rate(... [5m]))` rule. We
    // can't compute a true p99 without the full bucket array
    // (the in-process evaluator runs one /metrics scrape, not a
    // TSDB query), so we approximate via `sum / count` (mean)
    // with a generous threshold ratio: if mean > 50 ms, the
    // p99 is almost certainly > 200 ms. If mean > 200 ms, the
    // p99 is almost certainly > 1 s.
    //
    // This catches the CPU-exhaustion attack signal (PoW-
    // bypass flooding ML-KEM Decap) without needing a real
    // Prometheus deployment.
    let hs_sum = g("proteus_handshake_duration_seconds_sum").unwrap_or(0.0);
    let hs_count = g("proteus_handshake_duration_seconds_count").unwrap_or(0.0);
    if hs_count > 0.0 {
        let mean_s = hs_sum / hs_count;
        let mean_ms = mean_s * 1000.0;
        // Catastrophic first — same metric, higher threshold.
        if mean_s > 0.2 {
            r.push(Check {
                rule_name: "ProteusHandshakeLatencyP99Catastrophic",
                severity: CheckSeverity::Crit,
                message: format!(
                    "handshake mean latency = {mean_ms:.1}ms (over {} handshakes); p99 \
                     is almost certainly above the 1 s catastrophic threshold. Clients \
                     with default ~10 s timeouts will start failing. Likely a CPU-\
                     exhaustion attack — raise pow_difficulty + SIGHUP",
                    hs_count as u64,
                ),
                equivalent_promql:
                    "histogram_quantile(0.99, rate(proteus_handshake_duration_seconds_bucket[5m])) > 1.0",
            });
        } else if mean_s > 0.05 {
            r.push(Check {
                rule_name: "ProteusHandshakeLatencyP99High",
                severity: CheckSeverity::Warn,
                message: format!(
                    "handshake mean latency = {mean_ms:.1}ms (over {} handshakes); p99 \
                     likely above the 200 ms watch threshold. Investigate: (a) PoW-bypass \
                     attack flooding ML-KEM Decap, (b) slow cover endpoint dragging \
                     auth-fail histogram, (c) VPS CPU/disk pressure",
                    hs_count as u64,
                ),
                equivalent_promql:
                    "histogram_quantile(0.99, rate(proteus_handshake_duration_seconds_bucket[5m])) > 0.2",
            });
        } else {
            r.push(Check {
                rule_name: "ProteusHandshakeLatencyP99High",
                severity: CheckSeverity::Pass,
                message: format!(
                    "handshake mean latency = {mean_ms:.1}ms (over {} handshakes); healthy",
                    hs_count as u64,
                ),
                equivalent_promql: "",
            });
        }
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

    // ──── iter-38: SIGHUP reload-failing checks (×4) ────
    //
    // The 4 SIGHUP-reloadable surfaces (firewall, rate_limit,
    // user_rate_limit, handshake_budget) each get a dedicated rule.
    // Mirrors the client-side ProteusClientPoolReloadFailing
    // contract: WARN-on-gap, PASS-on-no-gap with att>0, suppress
    // entirely on att == 0.

    #[test]
    fn iter38_evaluate_emits_warn_when_firewall_reload_failing() {
        let body = body_with(
            "proteus_up 1\nproteus_firewall_reload_attempts_total 7\nproteus_firewall_reload_succeeded_total 5",
        );
        let r = evaluate(&body);
        let c = r
            .checks
            .iter()
            .find(|c| c.rule_name == "ProteusFirewallReloadFailing")
            .expect("ProteusFirewallReloadFailing check must fire on gap > 0");
        assert_eq!(c.severity, CheckSeverity::Warn);
        assert!(c.message.contains("7 reload"), "{}", c.message);
        assert!(c.message.contains("5 succeeded"), "{}", c.message);
        assert!(c.message.contains("2 failed"), "{}", c.message);
        assert!(c.message.contains("firewall"), "{}", c.message);
    }

    #[test]
    fn iter38_evaluate_emits_warn_when_rate_limit_reload_failing() {
        let body = body_with(
            "proteus_up 1\nproteus_rate_limit_reload_attempts_total 3\nproteus_rate_limit_reload_succeeded_total 1",
        );
        let r = evaluate(&body);
        let c = r
            .checks
            .iter()
            .find(|c| c.rule_name == "ProteusRateLimitReloadFailing")
            .expect("ProteusRateLimitReloadFailing check must fire");
        assert_eq!(c.severity, CheckSeverity::Warn);
    }

    #[test]
    fn iter38_evaluate_emits_warn_when_user_rate_limit_reload_failing() {
        let body = body_with(
            "proteus_up 1\nproteus_user_rate_limit_reload_attempts_total 10\nproteus_user_rate_limit_reload_succeeded_total 9",
        );
        let r = evaluate(&body);
        let c = r
            .checks
            .iter()
            .find(|c| c.rule_name == "ProteusUserRateLimitReloadFailing")
            .expect("ProteusUserRateLimitReloadFailing check must fire");
        assert_eq!(c.severity, CheckSeverity::Warn);
    }

    #[test]
    fn iter38_evaluate_emits_warn_when_handshake_budget_reload_failing() {
        let body = body_with(
            "proteus_up 1\nproteus_handshake_budget_reload_attempts_total 2\nproteus_handshake_budget_reload_succeeded_total 0",
        );
        let r = evaluate(&body);
        let c = r
            .checks
            .iter()
            .find(|c| c.rule_name == "ProteusHandshakeBudgetReloadFailing")
            .expect("ProteusHandshakeBudgetReloadFailing check must fire");
        assert_eq!(c.severity, CheckSeverity::Warn);
    }

    #[test]
    fn iter38_evaluate_passes_when_all_reloads_succeeded() {
        let body = body_with(
            "proteus_up 1\nproteus_firewall_reload_attempts_total 4\nproteus_firewall_reload_succeeded_total 4",
        );
        let r = evaluate(&body);
        let c = r
            .checks
            .iter()
            .find(|c| c.rule_name == "ProteusFirewallReloadFailing")
            .expect("must emit PASS when gap == 0 and att > 0");
        assert_eq!(c.severity, CheckSeverity::Pass);
    }

    #[test]
    fn iter38_evaluate_suppresses_check_when_no_reload_attempted() {
        // att == 0 → no SIGHUP yet → check should NOT be emitted
        // (matching ProteusClientPoolReloadFailing convention).
        let body = body_with(
            "proteus_up 1\nproteus_firewall_reload_attempts_total 0\nproteus_firewall_reload_succeeded_total 0",
        );
        let r = evaluate(&body);
        let any = r
            .checks
            .iter()
            .any(|c| c.rule_name == "ProteusFirewallReloadFailing");
        assert!(
            !any,
            "must NOT emit ProteusFirewallReloadFailing when no reload attempted yet"
        );
    }

    #[test]
    fn iter38_reload_failing_warn_does_not_force_crit_exit() {
        // WARN-only — operator's edit silently didn't apply but
        // the previous-known-good config is still being served.
        // Must not escalate exit code from 0.
        let body = body_with(
            "proteus_up 1\nproteus_firewall_reload_attempts_total 5\nproteus_firewall_reload_succeeded_total 3\nproteus_rate_limit_reload_attempts_total 8\nproteus_rate_limit_reload_succeeded_total 4",
        );
        let r = evaluate(&body);
        assert_eq!(
            r.exit_code(),
            0,
            "reload-failing is WARN-only; must not force exit=1"
        );
        let (_, w, cr) = r.counts();
        assert!(w >= 2, "expected at least 2 WARN checks for 2 failing reloads");
        assert_eq!(cr, 0);
    }

    // ──── iter-81: probe-anomaly check ────

    #[test]
    fn iter81_no_probe_anomaly_passes() {
        let body = body_with("proteus_probe_anomalies_fired_total 0");
        let r = evaluate(&body);
        let pass = r
            .checks
            .iter()
            .find(|c| c.rule_name == "ProteusProbeAnomalyFired")
            .expect("rule must fire when metric present");
        assert_eq!(pass.severity, CheckSeverity::Pass);
    }

    #[test]
    fn iter81_single_24_burst_warns() {
        let body = body_with("proteus_probe_anomalies_fired_total 3");
        let r = evaluate(&body);
        let warn = r
            .checks
            .iter()
            .find(|c| c.rule_name == "ProteusProbeAnomalyFired")
            .expect("rule must fire");
        assert_eq!(warn.severity, CheckSeverity::Warn);
        assert!(warn.message.contains("3"));
        assert!(warn.message.contains("firewall-deny"));
    }

    #[test]
    fn iter81_campaign_level_crits() {
        let body = body_with("proteus_probe_anomalies_fired_total 200");
        let r = evaluate(&body);
        let crit = r
            .checks
            .iter()
            .find(|c| c.rule_name == "ProteusProbeAnomalyCatastrophic")
            .expect("catastrophic must fire on >50 anomalies");
        assert_eq!(crit.severity, CheckSeverity::Crit);
        assert!(crit.message.contains("200"));
        assert!(crit.message.contains("coordinated"));
    }

    #[test]
    fn iter81_missing_metric_suppresses_check() {
        let body = body_with("proteus_up 1");
        let r = evaluate(&body);
        let any = r.checks.iter().any(|c| {
            c.rule_name == "ProteusProbeAnomalyFired"
                || c.rule_name == "ProteusProbeAnomalyCatastrophic"
        });
        assert!(!any);
    }

    // ──── iter-79: per-user abuse-alerts checks ────

    /// Each surface independently: 0 → PASS.
    #[test]
    fn iter79_no_abuse_fires_passes_all_three() {
        let body = body_with(
            "proteus_abuse_alerts_byte_budget_total 0\n\
             proteus_abuse_alerts_rate_limit_total 0\n\
             proteus_abuse_alerts_per_user_bandwidth_total 0",
        );
        let r = evaluate(&body);
        for rule_name in [
            "ProteusAbuseAlertsByteBudget",
            "ProteusAbuseAlertsRateLimit",
            "ProteusAbuseAlertsBandwidth",
        ] {
            let check = r
                .checks
                .iter()
                .find(|c| c.rule_name == rule_name)
                .unwrap_or_else(|| panic!("{rule_name} check must fire"));
            assert_eq!(check.severity, CheckSeverity::Pass, "{rule_name}");
        }
    }

    /// Non-zero byte_budget fires → WARN for that surface only.
    #[test]
    fn iter79_byte_budget_fires_warns() {
        let body = body_with(
            "proteus_abuse_alerts_byte_budget_total 7\n\
             proteus_abuse_alerts_rate_limit_total 0\n\
             proteus_abuse_alerts_per_user_bandwidth_total 0",
        );
        let r = evaluate(&body);
        let warn = r
            .checks
            .iter()
            .find(|c| c.rule_name == "ProteusAbuseAlertsByteBudget")
            .unwrap();
        assert_eq!(warn.severity, CheckSeverity::Warn);
        assert!(warn.message.contains("7"));
        assert!(warn.message.contains("byte-budget"));
        // Rate-limit + bandwidth should still PASS.
        let rl = r
            .checks
            .iter()
            .find(|c| c.rule_name == "ProteusAbuseAlertsRateLimit")
            .unwrap();
        assert_eq!(rl.severity, CheckSeverity::Pass);
        let bw = r
            .checks
            .iter()
            .find(|c| c.rule_name == "ProteusAbuseAlertsBandwidth")
            .unwrap();
        assert_eq!(bw.severity, CheckSeverity::Pass);
    }

    /// All three firing → 3 WARN checks.
    #[test]
    fn iter79_all_three_surfaces_warn_independently() {
        let body = body_with(
            "proteus_abuse_alerts_byte_budget_total 3\n\
             proteus_abuse_alerts_rate_limit_total 5\n\
             proteus_abuse_alerts_per_user_bandwidth_total 1",
        );
        let r = evaluate(&body);
        let warns: Vec<_> = r
            .checks
            .iter()
            .filter(|c| {
                c.rule_name.starts_with("ProteusAbuseAlerts") && c.severity == CheckSeverity::Warn
            })
            .collect();
        assert_eq!(warns.len(), 3, "all three surfaces must WARN independently");
    }

    /// Metrics absent → checks suppressed.
    #[test]
    fn iter79_missing_metrics_suppress() {
        let body = body_with("proteus_up 1");
        let r = evaluate(&body);
        let any = r
            .checks
            .iter()
            .any(|c| c.rule_name.starts_with("ProteusAbuseAlerts"));
        assert!(!any, "no abuse metrics → no checks");
    }

    // ──── iter-76: SSRF / outbound-filter rejections ────

    /// Zero blocked → PASS.
    #[test]
    fn iter76_no_outbound_blocks_passes() {
        let body = body_with("proteus_outbound_blocked_total 0");
        let r = evaluate(&body);
        let pass = r
            .checks
            .iter()
            .find(|c| c.rule_name == "ProteusSsrfAttemptsObserved")
            .expect("rule must fire when metric present");
        assert_eq!(pass.severity, CheckSeverity::Pass);
    }

    /// Some blocks (1-100 cumulative) → WARN.
    #[test]
    fn iter76_some_outbound_blocks_warn() {
        let body = body_with("proteus_outbound_blocked_total 5");
        let r = evaluate(&body);
        let warn = r
            .checks
            .iter()
            .find(|c| c.rule_name == "ProteusSsrfAttemptsObserved")
            .expect("rule must fire");
        assert_eq!(warn.severity, CheckSeverity::Warn);
        assert!(warn.message.contains("5"));
        assert!(warn.message.contains("SSRF") || warn.message.contains("credential"));
    }

    /// >100 cumulative blocks → CRIT.
    #[test]
    fn iter76_many_outbound_blocks_crit() {
        let body = body_with("proteus_outbound_blocked_total 500");
        let r = evaluate(&body);
        let crit = r
            .checks
            .iter()
            .find(|c| c.rule_name == "ProteusSsrfAttemptsCatastrophic")
            .expect("catastrophic rule must fire on >100 blocks");
        assert_eq!(crit.severity, CheckSeverity::Crit);
        assert!(crit.message.contains("500"));
        assert!(crit.message.contains("rotate"));
    }

    /// Metric absent (fresh server, no SSRF surface ever exercised)
    /// → check suppressed.
    #[test]
    fn iter76_missing_metric_suppresses_check() {
        let body = body_with("proteus_up 1");
        let r = evaluate(&body);
        let any = r.checks.iter().any(|c| {
            c.rule_name == "ProteusSsrfAttemptsObserved"
                || c.rule_name == "ProteusSsrfAttemptsCatastrophic"
        });
        assert!(
            !any,
            "absent metric → no SSRF check should fire"
        );
    }

    // ──── iter-74: handshake latency check ────

    /// Healthy mean latency (10 ms over 100 handshakes) → PASS.
    #[test]
    fn iter74_handshake_latency_healthy_passes() {
        // sum/count = 1.0 / 100 = 10 ms mean.
        let body = body_with(
            "proteus_handshake_duration_seconds_sum 1.0\nproteus_handshake_duration_seconds_count 100",
        );
        let r = evaluate(&body);
        let pass = r
            .checks
            .iter()
            .find(|c| c.rule_name == "ProteusHandshakeLatencyP99High")
            .expect("rule must fire when handshake count > 0");
        assert_eq!(pass.severity, CheckSeverity::Pass);
        assert!(pass.message.contains("10.0ms"));
    }

    /// Mean 80 ms (= 8 / 100) → WARN (p99 likely above 200 ms).
    #[test]
    fn iter74_handshake_latency_warns_on_creep() {
        let body = body_with(
            "proteus_handshake_duration_seconds_sum 8.0\nproteus_handshake_duration_seconds_count 100",
        );
        let r = evaluate(&body);
        let warn = r
            .checks
            .iter()
            .find(|c| c.rule_name == "ProteusHandshakeLatencyP99High")
            .expect("rule must fire");
        assert_eq!(warn.severity, CheckSeverity::Warn);
        assert!(warn.message.contains("80.0ms"));
        assert!(warn.message.contains("PoW-bypass"));
    }

    /// Mean 500 ms → CRIT (catastrophic). Operator wakes up.
    #[test]
    fn iter74_handshake_latency_catastrophic_crits() {
        let body = body_with(
            "proteus_handshake_duration_seconds_sum 50.0\nproteus_handshake_duration_seconds_count 100",
        );
        let r = evaluate(&body);
        let crit = r
            .checks
            .iter()
            .find(|c| c.rule_name == "ProteusHandshakeLatencyP99Catastrophic")
            .expect("catastrophic rule must fire on >200ms mean");
        assert_eq!(crit.severity, CheckSeverity::Crit);
        assert!(crit.message.contains("500.0ms"));
        assert!(crit.message.contains("attack"));
    }

    /// Zero handshakes → check suppressed entirely (no signal
    /// to evaluate). Same convention as
    /// ProteusClientNoRecentDialSuccess when attempts == 0.
    #[test]
    fn iter74_handshake_latency_no_handshakes_suppresses() {
        let body = body_with("proteus_up 1");
        let r = evaluate(&body);
        let any = r.checks.iter().any(|c| {
            c.rule_name == "ProteusHandshakeLatencyP99High"
                || c.rule_name == "ProteusHandshakeLatencyP99Catastrophic"
        });
        assert!(
            !any,
            "no handshakes → no latency check should fire"
        );
    }
}
