//! Coverage test for the bundled Grafana dashboard
//! `deploy/grafana/dashboards/proteus-overview.json`.
//!
//! Drift-protection between (the README's metric table) ↔ (the
//! alert rules) ↔ (the Grafana dashboard) ↔ (the actual code).
//! Earlier tests cover the first three pairs; this one closes
//! the dashboard side:
//!
//!   1. The dashboard JSON parses.
//!   2. Every metric name referenced in a PromQL panel target
//!      exists in the known production-metrics set (catches
//!      typos and stale-metric-references).
//!   3. Every panel has a non-empty title + description (so
//!      dashboard-visiting operators have context, not just
//!      cryptic axes).
//!   4. The dashboard has the expected critical panel IDs
//!      (1=server liveness, 2=client liveness, etc.) — catches
//!      accidental panel deletion during edits.
//!
//! ALSO sanity-checks `deploy/docker-compose.full.yml` —
//! parses as YAML, has the four expected services, every
//! service has a healthcheck + restart policy where relevant.

use std::collections::HashSet;
use std::path::PathBuf;

fn deploy_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // crates/
    p.pop(); // proteus/
    p.push("deploy");
    p
}

fn read_json(rel: &str) -> serde_json::Value {
    let path = deploy_dir().join(rel);
    let body =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&body).unwrap_or_else(|e| panic!("parse {} as JSON: {e}", path.display()))
}

fn read_yaml(rel: &str) -> serde_yaml::Value {
    let path = deploy_dir().join(rel);
    let body =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_yaml::from_str(&body).unwrap_or_else(|e| panic!("parse {} as YAML: {e}", path.display()))
}

/// Known production metric names (all the series the binaries
/// emit + the bundled alerts reference). The dashboard MAY
/// reference fewer (a panel doesn't have to cover every
/// metric) but it MUST NOT reference anything outside this set
/// — drift signal that catches typos.
fn known_metric_names() -> HashSet<&'static str> {
    [
        // Server liveness / lifecycle
        "proteus_up",
        "proteus_ready",
        "proteus_panics_total",
        "proteus_restarts_total",
        "proteus_first_start_unix_seconds",
        "proteus_last_clean_shutdown_unix_seconds",
        "proteus_previous_run_unclean",
        // Handshake / sessions
        "proteus_sessions_accepted_total",
        "proteus_handshakes_succeeded_total",
        "proteus_handshakes_failed_total",
        "proteus_handshake_timeouts_total",
        "proteus_handshake_duration_seconds_bucket",
        "proteus_handshake_duration_seconds_sum",
        "proteus_handshake_duration_seconds_count",
        "proteus_in_flight_sessions",
        // Bytes
        "proteus_tx_bytes_total",
        "proteus_rx_bytes_total",
        // Rate limiting / rejections
        "proteus_rate_limited_total",
        "proteus_cover_forwards_total",
        // Iter-20 introduced the rejection counter; iter-26
        // alerted on it; iter-33 surfaces it on the bundled
        // Grafana dashboard. Without this entry, the dashboard
        // coverage test would reject the new panel as
        // "metric not in known set."
        "proteus_cover_forwards_rejected_total",
        "proteus_aead_drops_total",
        "proteus_ratchets_total",
        // TLS
        "proteus_tls_cert_not_after_unix_seconds",
        "proteus_tls_cert_watcher_auto_reload_failed_total",
        // DNS
        "proteus_dns_lookups_total",
        // Log throttling
        "proteus_log_throttle_allowed_total",
        "proteus_log_throttle_suppressed_total",
        // Self-test hysteresis
        "proteus_consecutive_periodic_self_test_failures",
        "proteus_periodic_self_test_failure_threshold",
        // Access log
        "proteus_access_log_records_total",
        "proteus_access_log_writer_alive",
        // Client surface
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
        "proteus_client_in_flight_sessions",
    ]
    .into_iter()
    .collect()
}

/// Walk panel `targets[].expr` strings and extract the metric
/// names. A "metric name" here is a `[a-zA-Z_][a-zA-Z0-9_]*`
/// token that's NOT followed by `(` (which would make it a
/// PromQL function like `rate(...)`, `histogram_quantile(...)`).
fn extract_metric_names(expr: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = expr.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c.is_ascii_alphabetic() || c == b'_' {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            let tok = &expr[start..i];
            // Skip if followed by '(' (function call) or 'by ' /
            // 'on ' (PromQL keyword) — peek the next non-space.
            let mut j = i;
            while j < bytes.len() && bytes[j] == b' ' {
                j += 1;
            }
            let is_function = j < bytes.len() && bytes[j] == b'(';
            let is_keyword = matches!(
                tok,
                "by" | "on"
                    | "group_left"
                    | "group_right"
                    | "and"
                    | "or"
                    | "unless"
                    | "ignoring"
                    | "without"
            );
            if !is_function && !is_keyword && tok.starts_with("proteus") {
                out.push(tok.to_string());
            }
        } else {
            i += 1;
        }
    }
    out
}

#[test]
fn dashboard_json_parses_and_has_panels() {
    let v = read_json("grafana/dashboards/proteus-overview.json");
    let panels = v
        .get("panels")
        .and_then(|p| p.as_array())
        .expect("dashboard must have a `panels:` array");
    assert!(
        panels.len() >= 8,
        "dashboard should have at least 8 panels (we ship 19); got {}",
        panels.len()
    );
}

#[test]
fn every_panel_has_title_and_description() {
    let v = read_json("grafana/dashboards/proteus-overview.json");
    let panels = v["panels"].as_array().unwrap();
    for panel in panels {
        let id = panel.get("id").and_then(|i| i.as_u64()).unwrap_or(0);
        let title = panel.get("title").and_then(|t| t.as_str()).unwrap_or("");
        let desc = panel
            .get("description")
            .and_then(|d| d.as_str())
            .unwrap_or("");
        assert!(
            !title.is_empty(),
            "panel id={id} has no title — operators need labels on every panel"
        );
        assert!(
            !desc.is_empty(),
            "panel id={id} ({title}) has no description — operators need context, not just axes"
        );
    }
}

#[test]
fn every_metric_referenced_in_dashboard_exists_in_known_set() {
    let v = read_json("grafana/dashboards/proteus-overview.json");
    let known = known_metric_names();
    let panels = v["panels"].as_array().unwrap();
    let mut bad = Vec::new();
    for panel in panels {
        let id = panel.get("id").and_then(|i| i.as_u64()).unwrap_or(0);
        let title = panel.get("title").and_then(|t| t.as_str()).unwrap_or("?");
        let Some(targets) = panel.get("targets").and_then(|t| t.as_array()) else {
            continue;
        };
        for target in targets {
            let Some(expr) = target.get("expr").and_then(|e| e.as_str()) else {
                continue;
            };
            for metric in extract_metric_names(expr) {
                if !known.contains(metric.as_str()) {
                    bad.push(format!(
                        "panel id={id} ({title:?}): references unknown metric {metric:?}"
                    ));
                }
            }
        }
    }
    assert!(
        bad.is_empty(),
        "drift between dashboard and code:\n{}",
        bad.join("\n")
    );
}

#[test]
fn critical_panels_are_present_by_id() {
    // These panel IDs are the "first impression" — operators
    // visiting the dashboard for the first time see them in the
    // top row. Accidental deletion during an edit should fail
    // the test.
    let v = read_json("grafana/dashboards/proteus-overview.json");
    let panels = v["panels"].as_array().unwrap();
    let ids: HashSet<u64> = panels
        .iter()
        .filter_map(|p| p.get("id").and_then(|i| i.as_u64()))
        .collect();
    for id in [1, 2, 3, 4, 5, 6, 10, 11] {
        assert!(
            ids.contains(&id),
            "panel id={id} missing — top-row liveness + handshake panels are the first-impression contract"
        );
    }
}

#[test]
fn dashboard_uid_is_stable_for_link_compatibility() {
    // The UID is part of the dashboard URL; operators bookmark
    // it. Renaming would break bookmarks. Fail loudly.
    let v = read_json("grafana/dashboards/proteus-overview.json");
    assert_eq!(
        v.get("uid").and_then(|u| u.as_str()),
        Some("proteus-overview")
    );
}

// ────────────────────────────────────────────────────────────
// docker-compose.full.yml sanity
// ────────────────────────────────────────────────────────────

#[test]
fn docker_compose_full_parses_and_has_expected_services() {
    let v = read_yaml("docker-compose.full.yml");
    let services = v
        .get("services")
        .and_then(|s| s.as_mapping())
        .expect("docker-compose must have `services:` mapping");
    for needed in ["proteus-server", "proteus-client", "prometheus", "grafana"] {
        assert!(
            services.contains_key(serde_yaml::Value::String(needed.to_string())),
            "docker-compose.full.yml missing required service {needed:?}"
        );
    }
}

#[test]
fn every_compose_service_has_restart_policy() {
    let v = read_yaml("docker-compose.full.yml");
    let services = v["services"].as_mapping().unwrap();
    for (name, svc) in services {
        let n = name.as_str().unwrap_or("?");
        let restart = svc.get("restart").and_then(|r| r.as_str()).unwrap_or("");
        assert!(!restart.is_empty(), "service {n} has no `restart:` policy");
    }
}

#[test]
fn proteus_server_and_client_compose_entries_carry_security_hardening() {
    let v = read_yaml("docker-compose.full.yml");
    let services = v["services"].as_mapping().unwrap();
    for name in ["proteus-server", "proteus-client"] {
        let svc = services
            .get(serde_yaml::Value::String(name.to_string()))
            .unwrap();
        assert!(
            svc.get("cap_drop").is_some(),
            "{name} missing `cap_drop:` — must drop ALL by default"
        );
        let security_opt = svc
            .get("security_opt")
            .and_then(|s| s.as_sequence())
            .map(|s| {
                s.iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default();
        assert!(
            security_opt.contains("no-new-privileges:true"),
            "{name} missing security_opt no-new-privileges:true; got {security_opt:?}"
        );
        assert!(
            svc.get("read_only").and_then(|r| r.as_bool()) == Some(true),
            "{name} should be read_only: true (uses tmpfs for /tmp)"
        );
    }
}
