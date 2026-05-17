//! Integration test for the rejection-log-throttle public surface
//! exposed by `proteus_transport_alpha::server`.
//!
//! Drives the snapshot / drain-rollups / Prometheus helpers and
//! asserts the shape dashboards depend on. We can't easily
//! exercise the accept-loop call sites in a unit test without
//! spinning up a real server, but the public API is the operator-
//! facing contract — if this passes, the metrics block + log
//! rollups behave correctly.

use proteus_transport_alpha::server::{
    rejection_log_throttle_drain_rollups, rejection_log_throttle_prometheus,
    rejection_log_throttle_snapshot,
};

#[test]
fn snapshot_lists_all_three_known_call_sites() {
    let snap = rejection_log_throttle_snapshot();
    let sites: Vec<&'static str> = snap.iter().map(|(s, _, _)| *s).collect();
    // These three labels are the operator-facing contract — keep
    // them stable; renaming would break dashboards.
    for needle in [
        "firewall_denied",
        "handshake_budget_exhausted",
        "max_connections_reached",
    ] {
        assert!(
            sites.contains(&needle),
            "snapshot missing site {needle:?}; got {sites:?}"
        );
    }
}

#[test]
fn prometheus_rendering_contains_both_metric_families_and_every_site() {
    let body = rejection_log_throttle_prometheus();
    for needle in [
        "# HELP proteus_log_throttle_allowed_total",
        "# TYPE proteus_log_throttle_allowed_total counter",
        "# HELP proteus_log_throttle_suppressed_total",
        "# TYPE proteus_log_throttle_suppressed_total counter",
        r#"site="firewall_denied""#,
        r#"site="handshake_budget_exhausted""#,
        r#"site="max_connections_reached""#,
    ] {
        assert!(body.contains(needle), "missing {needle:?} in:\n{body}");
    }
}

#[test]
fn drain_rollups_is_idempotent_when_no_suppressions() {
    // The throttle statics are process-global. We can't easily
    // assert specific counts without polluting other tests, but
    // we CAN assert that calling drain_rollups twice in a row
    // returns no entries the second time (the first call may
    // have drained stuff from other tests' executions).
    let _first = rejection_log_throttle_drain_rollups();
    let second = rejection_log_throttle_drain_rollups();
    assert!(
        second.is_empty(),
        "second drain in a row must be empty; got {second:?}"
    );
}
