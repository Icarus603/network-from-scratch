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

/// Iter-122/123: security checklist must promote the 5-command
/// preflight gate to the top and reference the iter-118+/120
/// commands explicitly. Pre-iter-122 the checklist had 9 ad-
/// hoc items but no canonical preflight sequence; operators
/// had to thread the deploy guide manually.
///
/// Iter-123 fix: the README originally documented
/// `proteus-server host-preflight` / `proteus-client host-preflight`,
/// but those subcommands do not exist — the real names are
/// `proteus-server preflight check-host` (server) and
/// `proteus-client check-host` (client). An operator copy-pasting
/// the old recipe would hit "unrecognized subcommand" on the very
/// first preflight call. The test now pins the REAL command names
/// and `tests/deploy_readme_commands_actually_exist.rs` shells out
/// to both binaries to prove each documented command is recognized.
#[test]
fn iter122_security_checklist_promotes_preflight_gate() {
    let body = read_readme();
    assert!(
        body.contains("### Mandatory preflight gate"),
        "security checklist must have a Mandatory preflight gate section"
    );
    // The 5 canonical commands must all appear in the gate
    // sequence so an operator running `cat README.md | grep
    // proteus-` gets a copy-pasteable recipe.
    for cmd in [
        "proteus-server validate",
        "proteus-server preflight check-host",
        "proteus-client validate",
        "proteus-client check-host",
        "proteus-client connect-test --all-endpoints",
    ] {
        assert!(
            body.contains(cmd),
            "Mandatory preflight gate must include {cmd:?}"
        );
    }
    // Must reference the ~130 trap-class count so operators
    // know the preflight isn't decorative.
    assert!(
        body.contains("130 documented operator-trap classes"),
        "checklist must call out the trap-class scale (130 checks)"
    );
}

/// Iter-121: threat-surface section must enumerate the
/// post-iter-67 attack-class defenses (SSRF, AEAD-tampering,
/// open-relay coherence, zero-value foot-guns, cert expiry,
/// admin endpoint exposure). Pre-iter-121 the threat-surface
/// section listed only the M1 baseline (6 defenses); 120+
/// iterations of operator-trap and attack-detection work were
/// undocumented as operator-facing security guarantees.
#[test]
fn iter121_threat_surface_lists_operator_trap_class_defenses() {
    let body = read_readme();
    // SSRF / cloud metadata.
    assert!(
        body.contains("SSRF") && body.contains("169.254.169.254"),
        "threat surface must call out SSRF + cloud-metadata defense"
    );
    // AEAD tampering / MITM signal.
    assert!(
        body.contains("MITM tampering") && body.contains("proteus_aead_drops_total"),
        "must call out AEAD tampering detection"
    );
    // Catastrophic open-relay coherence.
    assert!(
        body.contains("open-relay") && body.contains("client_allowlist"),
        "must call out the iter-97 catastrophic-open-relay check"
    );
    // Zero-value foot-gun gates.
    assert!(
        body.contains("zero-value safety disable"),
        "must call out the ~130 zero-value-disable preflight gates"
    );
    // Cert-expiry preflight + runtime coverage.
    assert!(
        body.contains("TLS cert expiry") && body.contains("ProteusTlsCert"),
        "must call out cert-expiry preflight + runtime defenses"
    );
    // Admin endpoint wildcard-bind FAIL.
    assert!(
        body.contains("admin endpoint exposure"),
        "must call out the iter-71/73 admin-endpoint wildcard-bind FAIL"
    );
}

/// Iter-120 (revised iter-123): host-posture preflight +
/// connect-test must be documented alongside validate so operators
/// know the full pre-deploy smoke checklist.
///
/// Iter-123 fix: the original assertion `body.contains("proteus-server
/// host-preflight")` passed because the README had the string, but
/// the binary has no such subcommand — clap exits 2 with
/// "unrecognized subcommand 'host-preflight'". The real CLI shape is
/// `proteus-server preflight check-host` (under the `preflight`
/// umbrella, alongside `check-ip-reputation` + `all`) and
/// `proteus-client check-host` (top-level, no umbrella). The test
/// now pins the REAL command names; the new
/// `deploy_readme_commands_actually_exist.rs` integration test
/// shells out to both binaries to prove every documented command is
/// recognized.
#[test]
fn iter120_readme_documents_host_preflight_and_connect_test() {
    let body = read_readme();
    assert!(
        body.contains("### Host-posture preflight"),
        "deploy/README.md must document the host-posture preflight subcommand"
    );
    assert!(
        body.contains("### Live handshake smoke"),
        "deploy/README.md must document the connect-test subcommand"
    );
    // Both binaries' host-posture commands shown — using the REAL
    // CLI names (iter-123 fix; the prior "host-preflight" strings
    // were aspirational, not real).
    assert!(
        body.contains("proteus-server preflight check-host"),
        "server-side `preflight check-host` command must be shown"
    );
    assert!(
        body.contains("proteus-client check-host"),
        "client-side top-level `check-host` command must be shown"
    );
    // connect-test --all-endpoints shown (the recommended form
    // for multi-VPS HA deploys — iter-42).
    assert!(
        body.contains("proteus-client connect-test --all-endpoints"),
        "must show --all-endpoints form for HA pools"
    );
    // 5-command pre-deploy smoke checklist enumerated.
    assert!(
        body.contains("production ready") && body.contains("FAIL"),
        "must enumerate the 5-command pre-deploy checklist + pass/fail gate"
    );
    // Iter-123: the README MUST call out the asymmetric subcommand
    // naming explicitly. Operators who skim the recipe and grep for
    // "host-preflight" need a signpost that the server uses
    // `preflight check-host` and the client uses bare `check-host`.
    assert!(
        body.contains("asymmetric subcommand naming"),
        "must call out the asymmetric CLI naming (server `preflight check-host` \
         vs. client `check-host`) so operators don't grep for a unified name \
         that doesn't exist"
    );
}

/// Iter-119: the Grafana dashboard section must reference the
/// bundled JSON file by path + explain how to import.
#[test]
fn iter119_readme_documents_grafana_dashboard() {
    let body = read_readme();
    assert!(
        body.contains("### Grafana dashboard"),
        "deploy/README.md must document the bundled Grafana dashboard"
    );
    // Must reference the JSON by exact path so operators can
    // find it.
    assert!(
        body.contains("deploy/grafana/dashboards/proteus-overview.json"),
        "must reference the dashboard JSON by path"
    );
    // Must show the provisioning recipe (a real operator workflow,
    // not just "import via UI").
    assert!(
        body.contains("provisioning/dashboards/"),
        "must explain provisioning workflow alongside UI import"
    );
    // Must enumerate panel families so operators know what they
    // get without opening the JSON.
    for family in [
        "Liveness",
        "Throughput",
        "Cover-forward",
        "Per-user observability",
        "Attack signals",
    ] {
        assert!(
            body.contains(family),
            "must enumerate the {family:?} dashboard panel family"
        );
    }
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
