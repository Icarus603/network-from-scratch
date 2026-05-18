//! Coverage test for the bundled client-side Prometheus alert
//! rules file. Symmetric with the server-side
//! `prometheus_alert_rules_coverage.rs` in proteus-server.
//!
//! Parses `deploy/prometheus/proteus-client-alerts.yaml` at test
//! time and asserts:
//!   1. The file is valid YAML in Prometheus rule-group shape.
//!   2. Every client-facing production-stability metric
//!      documented in the admin.rs `to_prometheus` block is
//!      referenced by ≥1 alert's `expr`.
//!   3. Every rule has alert / expr / labels.severity /
//!      annotations.summary — the four mandatory fields for an
//!      operator-friendly page.
//!   4. Critical-severity alerts all have ≥40-char descriptions.
//!   5. No duplicate alert names across groups.
//!   6. No alert NAME collides with the server-side rules file
//!      — Prometheus accepts duplicates but mixing them is
//!      operator-hostile.

use std::collections::HashSet;
use std::path::PathBuf;

fn alerts_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // crates/
    p.pop(); // proteus/
    p.push("deploy");
    p.push("prometheus");
    p.push("proteus-client-alerts.yaml");
    p
}

fn server_alerts_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("deploy");
    p.push("prometheus");
    p.push("proteus-alerts.yaml");
    p
}

fn read_yaml(p: &PathBuf) -> serde_yaml::Value {
    let body = std::fs::read_to_string(p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()));
    serde_yaml::from_str(&body).unwrap_or_else(|e| panic!("parse {}: {e}", p.display()))
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
    let v = read_yaml(&alerts_path());
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
            name.starts_with("proteus-client"),
            "client alert group {name:?} must use `proteus-client-*` prefix to avoid colliding with server groups"
        );
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
    let v = read_yaml(&alerts_path());
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
fn every_documented_client_metric_has_at_least_one_alert() {
    // These are the production-critical client metrics
    // documented in proteus-client::admin::ClientStatusSnapshot::to_prometheus
    // and used by the in-process `proteus-client alerts-check`
    // evaluator. Every one MUST be referenced by at least one
    // alert's `expr` so a future iteration dropping a metric
    // also breaks the alert (loud CI failure vs silent loss of
    // observability).
    let must_have_alert_for: HashSet<&str> = [
        "proteus_client_up",
        "proteus_client_dials_attempted_total",
        "proteus_client_dials_succeeded_total",
        "proteus_client_dials_failed_total",
        "proteus_client_last_dial_success_unix_seconds",
        "proteus_client_carrier_suppressed",
        "proteus_client_endpoint_suppressed",
        "proteus_client_bootstrap_via_system_resolver_total",
        "proteus_client_pool_reload_attempts_total",
        "proteus_client_pool_reload_succeeded_total",
        // Iter-101: client-side panic-hook counter. The
        // ProteusClientPanic alert fires on rate > 0; if a
        // future iteration drops the metric (or renames it
        // via the panic-hook crate refactor) this test breaks
        // loudly.
        "proteus_panics_total",
    ]
    .into_iter()
    .collect();

    let v = read_yaml(&alerts_path());
    let all_exprs: String = flatten_rules(&v)
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
        "client metrics with no alert coverage: {missing:?}\nAll exprs:\n{all_exprs}"
    );
}

#[test]
fn critical_severity_rules_all_have_descriptions() {
    let v = read_yaml(&alerts_path());
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
                "critical alert {alert}: description too short ({} chars). Pages must include actionable remediation.",
                desc.len()
            );
        }
    }
}

#[test]
fn no_duplicate_alert_names_within_client_file() {
    let v = read_yaml(&alerts_path());
    let mut seen = HashSet::new();
    for rule in flatten_rules(&v) {
        if let Some(name) = rule.get("alert").and_then(|a| a.as_str()) {
            assert!(
                seen.insert(name.to_string()),
                "duplicate alert name {name:?} within client alerts"
            );
        }
    }
}

#[test]
fn no_alert_name_collides_with_server_side_rules() {
    // Operators loading BOTH rule files into the same Prometheus
    // need every alert name globally unique — otherwise
    // `up{alertname="X"}` returns ambiguous results.
    let client = read_yaml(&alerts_path());
    let server = read_yaml(&server_alerts_path());
    let client_names: HashSet<String> = flatten_rules(&client)
        .iter()
        .filter_map(|r| r.get("alert").and_then(|a| a.as_str()).map(String::from))
        .collect();
    let server_names: HashSet<String> = flatten_rules(&server)
        .iter()
        .filter_map(|r| r.get("alert").and_then(|a| a.as_str()).map(String::from))
        .collect();
    let collisions: Vec<_> = client_names.intersection(&server_names).cloned().collect();
    assert!(
        collisions.is_empty(),
        "alert-name collision between client and server rule files: {collisions:?}"
    );
}

#[test]
fn all_client_alert_names_use_proteus_client_prefix() {
    // Operators grepping `alertname=~"ProteusClient.*"` should
    // get the full set; any client-side rule that doesn't follow
    // the prefix convention breaks that workflow.
    let v = read_yaml(&alerts_path());
    for rule in flatten_rules(&v) {
        let name = rule.get("alert").and_then(|a| a.as_str()).unwrap_or("");
        assert!(
            name.starts_with("ProteusClient"),
            "client alert name {name:?} must use `ProteusClient*` prefix"
        );
    }
}
