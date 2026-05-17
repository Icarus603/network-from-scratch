//! Coverage test for the bundled Prometheus alert rules file.
//!
//! Parses `deploy/prometheus/proteus-alerts.yaml` at test time
//! and asserts:
//!   1. The file is valid YAML in Prometheus rule-group shape
//!      (top-level `groups:`, each group has `rules:`, each rule
//!      has `alert:` + `expr:`).
//!   2. Every production-stability metric documented in README
//!      (panic counter, restart tracker, DNS resolver stats,
//!      log throttle, access-log writer health, TLS cert
//!      expiry) is referenced by at least one alert's `expr`.
//!   3. Every rule has the four mandatory fields needed for an
//!      operator-friendly page: `alert`, `expr`, `labels.severity`,
//!      `annotations.summary`.
//!
//! Without this, a future iteration could add a new metric +
//! forget to add the alert, and the operator would have to
//! discover the gap from production breakage.
//!
//! Test does NOT use Prometheus's own `promtool check rules`
//! because that needs the promtool binary at test time. The
//! structural parse here catches every regression the test was
//! designed for.

use std::collections::HashSet;
use std::path::PathBuf;

fn alerts_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // crates/
    p.pop(); // proteus/
    p.push("deploy");
    p.push("prometheus");
    p.push("proteus-alerts.yaml");
    p
}

fn read_alerts() -> serde_yaml::Value {
    let body =
        std::fs::read_to_string(alerts_path()).unwrap_or_else(|e| panic!("read alerts file: {e}"));
    serde_yaml::from_str(&body).unwrap_or_else(|e| panic!("parse alerts yaml: {e}"))
}

fn flatten_rules(v: &serde_yaml::Value) -> Vec<&serde_yaml::Value> {
    let mut out = Vec::new();
    let Some(groups) = v.get("groups").and_then(|g| g.as_sequence()) else {
        return out;
    };
    for group in groups {
        if let Some(rules) = group.get("rules").and_then(|r| r.as_sequence()) {
            for rule in rules {
                out.push(rule);
            }
        }
    }
    out
}

#[test]
fn alerts_file_parses_as_prometheus_rule_groups() {
    let v = read_alerts();
    let groups = v
        .get("groups")
        .and_then(|g| g.as_sequence())
        .expect("top-level `groups:` must be a sequence");
    assert!(
        !groups.is_empty(),
        "alerts file must contain at least one group"
    );
    for group in groups {
        let name = group
            .get("name")
            .and_then(|n| n.as_str())
            .expect("every group needs a `name:`");
        assert!(
            !name.is_empty(),
            "group name must be non-empty (Prometheus rejects empty)"
        );
        // Every group must have a non-empty rules block.
        assert!(
            group
                .get("rules")
                .and_then(|r| r.as_sequence())
                .is_some_and(|r| !r.is_empty()),
            "group {name:?} has empty/missing rules:"
        );
    }
}

#[test]
fn every_rule_has_alert_expr_severity_summary() {
    let v = read_alerts();
    let rules = flatten_rules(&v);
    assert!(!rules.is_empty(), "no rules parsed");
    for rule in &rules {
        let alert_name = rule
            .get("alert")
            .and_then(|a| a.as_str())
            .unwrap_or_else(|| panic!("rule missing `alert:` field: {rule:?}"));
        assert!(
            rule.get("expr").and_then(|e| e.as_str()).is_some(),
            "{alert_name}: missing `expr:`"
        );
        let severity = rule
            .get("labels")
            .and_then(|l| l.get("severity"))
            .and_then(|s| s.as_str())
            .unwrap_or_else(|| panic!("{alert_name}: missing labels.severity"));
        assert!(
            ["critical", "warning", "info"].contains(&severity),
            "{alert_name}: severity must be critical/warning/info, got {severity:?}"
        );
        assert!(
            rule.get("annotations")
                .and_then(|a| a.get("summary"))
                .and_then(|s| s.as_str())
                .is_some_and(|s| !s.is_empty()),
            "{alert_name}: missing annotations.summary"
        );
    }
}

#[test]
fn every_documented_metric_is_referenced_by_at_least_one_alert() {
    // The README documents these metrics as the production-
    // critical surface. Each MUST appear in at least one
    // alert's `expr:` so a future operator dropping the metric
    // also breaks the alert (loud failure at deploy time vs.
    // silent loss of observability at runtime).
    let must_have_alert_for: HashSet<&str> = [
        "proteus_up",
        "proteus_panics_total",
        "proteus_restarts_total",
        "proteus_previous_run_unclean",
        "proteus_tls_cert_not_after_unix_seconds",
        "proteus_tls_cert_watcher_auto_reload_failed_total",
        "proteus_dns_lookups_total",
        "proteus_log_throttle_suppressed_total",
        "proteus_access_log_writer_alive",
        "proteus_access_log_records_total",
        // Iter-26: bundled-alerts coverage now includes the
        // cover-forward observability surface. Iter-20 added
        // the rejection counter + iter-26 added the matching
        // alert rules (ProteusCoverForwardRejecting,
        // ProteusCoverForwardStorm). Without this entry the
        // alerts could be silently removed in a future
        // refactor.
        "proteus_cover_forwards_rejected_total",
        "proteus_cover_forwards_total",
    ]
    .into_iter()
    .collect();

    let v = read_alerts();
    let rules = flatten_rules(&v);
    let all_exprs: String = rules
        .iter()
        .filter_map(|r| r.get("expr").and_then(|e| e.as_str()))
        .collect::<Vec<_>>()
        .join("\n");

    let mut missing = Vec::new();
    for metric in &must_have_alert_for {
        if !all_exprs.contains(*metric) {
            missing.push(*metric);
        }
    }
    assert!(
        missing.is_empty(),
        "documented metrics with no alert coverage: {missing:?}\n\
         All `expr:` blocks:\n{all_exprs}"
    );
}

#[test]
fn critical_severity_rules_all_have_descriptions() {
    // Pages need actionable descriptions — "the thing is broken"
    // without "here's what to do" wastes operator time at 3am.
    let v = read_alerts();
    for rule in flatten_rules(&v) {
        let severity = rule
            .get("labels")
            .and_then(|l| l.get("severity"))
            .and_then(|s| s.as_str())
            .unwrap_or("");
        if severity == "critical" {
            let alert = rule.get("alert").and_then(|a| a.as_str()).unwrap_or("?");
            let desc = rule
                .get("annotations")
                .and_then(|a| a.get("description"))
                .and_then(|d| d.as_str())
                .unwrap_or("");
            assert!(
                !desc.is_empty() && desc.len() > 40,
                "critical alert {alert}: description is missing or too short ({} chars). Pages must include actionable remediation.",
                desc.len()
            );
        }
    }
}

#[test]
fn no_duplicate_alert_names_across_groups() {
    // Prometheus accepts duplicates but mixing them is operator-
    // hostile (which one fired? which annotation is current?).
    let v = read_alerts();
    let mut seen = HashSet::new();
    for rule in flatten_rules(&v) {
        if let Some(name) = rule.get("alert").and_then(|a| a.as_str()) {
            assert!(
                seen.insert(name.to_string()),
                "duplicate alert name {name:?} across groups"
            );
        }
    }
}
