//! Iter-132: `proteus-client validate` must accept BOTH
//! `--config <path>` (symmetric with the server-side
//! `proteus-server validate --config <path>`) AND a positional
//! `<path>` argument (backward-compat with pre-iter-132 scripts).
//!
//! Pre-iter-132 the client took ONLY the positional form. The
//! deploy/README.md 5-command preflight gate (iter-122) used
//! `proteus-client validate --config ~/.proteus/client.yaml`,
//! which failed at clap with exit 2 + "unexpected argument
//! '--config'" — silently breaking the canonical preflight
//! sequence for every operator who copy-pasted the recipe.
//!
//! The iter-123 executable-contract test (`deploy_readme_commands_
//! actually_exist`) missed this because it only invoked `--help`
//! on each subcommand, which doesn't trigger the arg parser for
//! the subcommand's own flags. Iter-132 closes that gap with a
//! direct invocation test.
//!
//! This test lives in the client crate so it can use
//! `CARGO_BIN_EXE_proteus-client` directly.

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_proteus-client");

fn fresh_yaml_path(tag: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "proteus-iter132-{tag}-{}-{}.yaml",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    p
}

/// A minimal-but-invalid yaml file. `validate` will parse it and
/// emit a FAIL (likely "missing field") but the IMPORTANT bit for
/// iter-132 is that the CLI gets PAST clap parsing — i.e. that
/// `--config` and positional `<path>` are both accepted.
fn write_throwaway_yaml(p: &std::path::Path) {
    std::fs::write(p, "# iter-132 test yaml; intentionally minimal\n").unwrap();
}

#[test]
fn iter132_client_validate_accepts_dash_dash_config_flag() {
    let p = fresh_yaml_path("config-flag");
    write_throwaway_yaml(&p);
    let out = Command::new(BIN)
        .args(["validate", "--config"])
        .arg(&p)
        .output()
        .expect("spawn proteus-client");
    let stderr = String::from_utf8_lossy(&out.stderr);
    // Exit 1 = "validate ran, FAILed" (expected — our yaml is
    // missing required fields). Exit 2 = "clap rejected the
    // args" (the pre-iter-132 bug). We want exit 1, NOT 2.
    assert_ne!(
        out.status.code(),
        Some(2),
        "client validate --config <path> must NOT be rejected by clap; \
         pre-iter-132 it was rejected as 'unexpected argument'. \
         stderr={stderr}"
    );
    // And the stderr must NOT contain the clap "unexpected
    // argument" message, even if exit happens to be 2 in some
    // other variant.
    assert!(
        !stderr.contains("unexpected argument '--config'"),
        "must not fail with 'unexpected argument --config'; stderr={stderr}"
    );
    let _ = std::fs::remove_file(&p);
}

#[test]
fn iter132_client_validate_still_accepts_positional_path() {
    let p = fresh_yaml_path("positional");
    write_throwaway_yaml(&p);
    let out = Command::new(BIN)
        .args(["validate"])
        .arg(&p)
        .output()
        .expect("spawn proteus-client");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_ne!(
        out.status.code(),
        Some(2),
        "positional path must keep working for backward-compat; \
         pre-iter-132 scripts use this form. stderr={stderr}"
    );
    let _ = std::fs::remove_file(&p);
}

#[test]
fn iter132_client_validate_rejects_both_forms_simultaneously() {
    // Using both should be a clap usage error (conflicts_with).
    let p = fresh_yaml_path("both");
    write_throwaway_yaml(&p);
    let out = Command::new(BIN)
        .args(["validate", "--config"])
        .arg(&p)
        .arg(&p) // also as positional
        .output()
        .expect("spawn proteus-client");
    assert_eq!(
        out.status.code(),
        Some(2),
        "using both --config AND positional must fail with exit 2 \
         (clap usage error). stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_file(&p);
}

#[test]
fn iter132_client_validate_rejects_neither_form_with_actionable_error() {
    // No args at all. Must exit 2 with a helpful message naming
    // BOTH supported forms — so an operator who forgot to pass
    // anything understands what's available.
    let out = Command::new(BIN)
        .args(["validate"])
        .output()
        .expect("spawn proteus-client");
    assert_eq!(
        out.status.code(),
        Some(2),
        "no-arg validate must exit 2; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--config") && stderr.contains("positional"),
        "error must name BOTH supported forms (--config + positional) \
         so the operator can pick: stderr={stderr}"
    );
}

#[test]
fn iter132_canonical_preflight_gate_form_from_deploy_readme_works() {
    // The exact form used in deploy/README.md's iter-122
    // mandatory preflight gate. If this test fails, the README
    // recipe is broken.
    let p = fresh_yaml_path("gate-form");
    write_throwaway_yaml(&p);
    let out = Command::new(BIN)
        .args(["validate", "--config"])
        .arg(&p)
        .output()
        .expect("spawn proteus-client");
    assert_ne!(
        out.status.code(),
        Some(2),
        "the exact `proteus-client validate --config <path>` form \
         from deploy/README.md's 5-command preflight gate must not \
         be rejected by clap. If this fails, every operator who \
         copy-pastes the gate recipe gets a broken deploy. \
         stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_file(&p);
}
