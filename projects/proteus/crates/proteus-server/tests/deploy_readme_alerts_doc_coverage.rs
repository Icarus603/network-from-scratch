//! Iter-118: deploy/README.md operator-facing alerts
//! documentation coverage.
//!
//! Pre-iter-118 the bundled `proteus-alerts.yaml` (40+ rules) +
//! `proteus-client-alerts.yaml` (10 rules) + the in-process
//! `alerts-check` evaluators were undocumented in the deploy
//! guide. An operator following the deploy README would never
//! learn that the runtime ships alert rules + a no-Prometheus
//! evaluator. The new "Prometheus alerts" + "In-process
//! alerts-check (no Prometheus needed)" sections close that
//! gap; this test pins their headings so a future README
//! refactor can't silently drop them.

use std::path::PathBuf;

fn deploy_readme_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // crates/
    p.pop(); // proteus/
    p.push("deploy");
    p.push("README.md");
    p
}

fn read_readme() -> String {
    let p = deploy_readme_path();
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

#[test]
fn readme_documents_prometheus_alerts_section() {
    let body = read_readme();
    assert!(
        body.contains("### Prometheus alerts"),
        "deploy/README.md must document the bundled alerts file"
    );
    // Must mention both rule files by path.
    assert!(
        body.contains("deploy/prometheus/proteus-alerts.yaml"),
        "must reference the server-side alerts YAML"
    );
    assert!(
        body.contains("deploy/prometheus/proteus-client-alerts.yaml"),
        "must reference the client-side alerts YAML"
    );
    // Must explain severity grammar.
    assert!(
        body.contains("critical")
            && body.contains("warning")
            && body.contains("paging-grade"),
        "must explain severity grammar (critical / warning + paging-grade)"
    );
}

#[test]
fn readme_documents_alerts_check_evaluator() {
    let body = read_readme();
    assert!(
        body.contains("### In-process `alerts-check`"),
        "deploy/README.md must document the no-Prometheus evaluator"
    );
    // Must show concrete commands for BOTH binaries.
    assert!(
        body.contains("proteus-server admin alerts-check"),
        "must show server-side command"
    );
    assert!(
        body.contains("proteus-client alerts-check"),
        "must show client-side command"
    );
    // Must explain exit-code semantics.
    assert!(
        body.contains("Exits 0 on PASS+WARN-only, 1 on any CRIT"),
        "must explain exit-code semantics for scripted gating"
    );
}

#[test]
fn readme_alerts_section_calls_out_headline_attack_signals() {
    let body = read_readme();
    // The most operationally critical alerts the operator
    // SHOULD recognise by name when paged. If these go missing
    // from the README the operator loses the "what is this
    // alert telling me" muscle memory.
    for headline in [
        "ProteusAeadDropsCatastrophic",
        "ProteusSsrfAttemptsCatastrophic",
        "ProteusHandshakeLatencyP99Catastrophic",
        "ProteusTlsCertExpired",
        "ProteusPanic",
    ] {
        assert!(
            body.contains(headline),
            "deploy/README.md must call out the headline alert {headline:?} so operators \
             know what they're being paged about"
        );
    }
}
