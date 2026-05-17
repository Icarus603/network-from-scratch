//! Structural invariants for the bundled systemd unit files.
//!
//! Operators routinely edit `proteus-server.service` and
//! `proteus-client.service` via `systemctl edit` or to drop in
//! environment-specific overrides. Accidentally removing a
//! critical directive (Type=notify, WatchdogSec=, MemoryMax=)
//! re-introduces a previously-fixed production gap silently —
//! systemctl never warns on missing recommended directives, only
//! on syntactically broken ones.
//!
//! This test parses both bundled unit files at build time and
//! asserts every directive we care about IS present + has a
//! plausible value. It does NOT use systemd's own validator
//! (that requires libsystemd-dev at test time, and the bundled
//! files are deliberately portable to non-systemd test runners
//! e.g. macOS dev boxes); it does the minimum INI-style parse
//! that catches every regression the test was designed for.
//!
//! Test fixtures: the unit files themselves live under
//! `deploy/systemd/` (workspace-relative). We resolve via
//! `CARGO_MANIFEST_DIR` so the test runs regardless of cwd.

use std::collections::HashMap;
use std::path::PathBuf;

/// Parse a `.service` file into a `(section -> directive -> value)`
/// map. Multi-value directives (e.g. `SystemCallFilter=` appearing
/// twice) take the LAST value — matches systemd's semantics for
/// most directives. Returns `None` on basic syntactic problems
/// (unterminated section header etc.).
fn parse_unit(body: &str) -> HashMap<String, HashMap<String, String>> {
    let mut out: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut current_section = String::new();
    for raw in body.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            current_section = name.to_string();
            out.entry(current_section.clone()).or_default();
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            out.entry(current_section.clone())
                .or_default()
                .insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    out
}

fn deploy_dir() -> PathBuf {
    // CARGO_MANIFEST_DIR points at crates/proteus-server/. Walk
    // up to the proteus root, then into deploy/systemd.
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // crates/
    p.pop(); // proteus/
    p.push("deploy");
    p.push("systemd");
    p
}

fn read_unit(name: &str) -> HashMap<String, HashMap<String, String>> {
    let path = deploy_dir().join(name);
    let body =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    parse_unit(&body)
}

fn assert_present(unit: &HashMap<String, HashMap<String, String>>, section: &str, key: &str) {
    assert!(
        unit.get(section)
            .and_then(|s| s.get(key))
            .is_some_and(|v| !v.is_empty()),
        "{section}/{key} must be set in the unit file (missing or empty)"
    );
}

fn assert_value(
    unit: &HashMap<String, HashMap<String, String>>,
    section: &str,
    key: &str,
    expected: &str,
) {
    let actual = unit
        .get(section)
        .and_then(|s| s.get(key))
        .unwrap_or_else(|| panic!("{section}/{key} missing"));
    assert_eq!(
        actual, expected,
        "{section}/{key} expected {expected:?}, got {actual:?}"
    );
}

// ────────────────────────────────────────────────────────────
// proteus-server.service
// ────────────────────────────────────────────────────────────

#[test]
fn server_unit_uses_type_notify_with_watchdog() {
    let u = read_unit("proteus-server.service");
    assert_value(&u, "Service", "Type", "notify");
    assert_value(&u, "Service", "NotifyAccess", "main");
    assert_present(&u, "Service", "WatchdogSec");
    // ExecReload must call kill -HUP — operator uses
    // `systemctl reload` which depends on this directive.
    assert_present(&u, "Service", "ExecReload");
    assert!(
        u["Service"]["ExecReload"].contains("HUP")
            && u["Service"]["ExecReload"].contains("$MAINPID"),
        "ExecReload must send SIGHUP to MAINPID: got {:?}",
        u["Service"]["ExecReload"]
    );
}

#[test]
fn server_unit_has_memory_and_tasks_caps() {
    // OOM safety — without these, an unbounded leak / DoS can
    // OOM the entire host. MemoryMax is the hard cap, TasksMax
    // is the cgroup-level fork-bomb defense (complementary to
    // LimitNPROC which is process-level).
    let u = read_unit("proteus-server.service");
    assert_present(&u, "Service", "MemoryMax");
    assert_present(&u, "Service", "MemoryHigh");
    assert_present(&u, "Service", "TasksMax");
    // OOMScoreAdjust should be negative so the kernel prefers
    // killing other processes during system-wide pressure.
    assert_present(&u, "Service", "OOMScoreAdjust");
    let oom = u["Service"]["OOMScoreAdjust"]
        .parse::<i32>()
        .expect("OOMScoreAdjust must parse as i32");
    assert!(
        oom < 0,
        "OOMScoreAdjust should be < 0 (lower = preferred-victim later); got {oom}"
    );
}

#[test]
fn server_unit_keeps_hardening_directives() {
    let u = read_unit("proteus-server.service");
    // Each of these is a hard-won production-stability or
    // attack-surface-reduction directive; deleting one silently
    // regresses. Test asserts they're STILL there.
    for key in [
        "NoNewPrivileges",
        "ProtectSystem",
        "ProtectHome",
        "ProtectKernelTunables",
        "ProtectKernelModules",
        "ProtectControlGroups",
        "MemoryDenyWriteExecute",
        "RestrictNamespaces",
        "LockPersonality",
        "SystemCallArchitectures",
    ] {
        assert_present(&u, "Service", key);
    }
    // CAP_NET_BIND_SERVICE for binding 443 as non-root.
    assert!(
        u["Service"]["AmbientCapabilities"].contains("CAP_NET_BIND_SERVICE"),
        "server must carry CAP_NET_BIND_SERVICE"
    );
}

#[test]
fn server_unit_state_directory_matches_recommended_restart_state_file() {
    // The README + server.example.yaml suggest
    // `restart_state_file: /var/lib/proteus/restart_state.json`.
    // The unit must wire StateDirectory=proteus so systemd
    // auto-creates /var/lib/proteus with 0750 ownership.
    let u = read_unit("proteus-server.service");
    assert_value(&u, "Service", "StateDirectory", "proteus");
    assert_value(&u, "Service", "StateDirectoryMode", "0750");
}

// ────────────────────────────────────────────────────────────
// proteus-client.service
// ────────────────────────────────────────────────────────────

#[test]
fn client_unit_file_exists() {
    // Basic file-existence sanity — the rest of the test
    // module assumes this passed.
    let path = deploy_dir().join("proteus-client.service");
    assert!(
        path.exists(),
        "{} must exist (operator deploy story)",
        path.display()
    );
}

#[test]
fn client_unit_uses_type_notify_with_watchdog() {
    let u = read_unit("proteus-client.service");
    assert_value(&u, "Service", "Type", "notify");
    assert_value(&u, "Service", "NotifyAccess", "main");
    assert_present(&u, "Service", "WatchdogSec");
    assert_present(&u, "Service", "ExecReload");
    assert!(
        u["Service"]["ExecReload"].contains("HUP")
            && u["Service"]["ExecReload"].contains("$MAINPID"),
        "ExecReload must send SIGHUP to MAINPID"
    );
}

#[test]
fn client_unit_has_memory_and_tasks_caps() {
    let u = read_unit("proteus-client.service");
    assert_present(&u, "Service", "MemoryMax");
    assert_present(&u, "Service", "MemoryHigh");
    assert_present(&u, "Service", "TasksMax");
    assert_present(&u, "Service", "OOMScoreAdjust");
}

#[test]
fn client_unit_does_not_carry_net_bind_capability() {
    // SOCKS5 binds 127.0.0.1:1080 (unprivileged) by default.
    // The client unit must NOT carry CAP_NET_BIND_SERVICE —
    // minimum-privilege default for a userspace SOCKS5 proxy.
    let u = read_unit("proteus-client.service");
    let ambient = u["Service"]
        .get("AmbientCapabilities")
        .map(|s| s.as_str())
        .unwrap_or("");
    assert!(
        !ambient.contains("CAP_NET_BIND_SERVICE"),
        "client must not carry CAP_NET_BIND_SERVICE; got AmbientCapabilities={ambient:?}"
    );
    let bounding = u["Service"]
        .get("CapabilityBoundingSet")
        .map(|s| s.as_str())
        .unwrap_or("");
    assert!(
        !bounding.contains("CAP_NET_BIND_SERVICE"),
        "client bounding set must not allow CAP_NET_BIND_SERVICE; got {bounding:?}"
    );
}

#[test]
fn client_unit_keeps_hardening_directives_symmetric_with_server() {
    let u = read_unit("proteus-client.service");
    for key in [
        "NoNewPrivileges",
        "ProtectSystem",
        "ProtectHome",
        "ProtectKernelTunables",
        "ProtectKernelModules",
        "ProtectControlGroups",
        "MemoryDenyWriteExecute",
        "RestrictNamespaces",
        "LockPersonality",
        "SystemCallArchitectures",
    ] {
        assert_present(&u, "Service", key);
    }
}

// ────────────────────────────────────────────────────────────
// parse_unit unit tests (the parser itself)
// ────────────────────────────────────────────────────────────

#[test]
fn parse_unit_handles_comments_and_blanks() {
    let body = "# top-level comment\n[Service]\n\n# inside-section comment\nFoo=bar\n";
    let u = parse_unit(body);
    assert_eq!(u["Service"]["Foo"], "bar");
    assert!(!u.contains_key(""), "no rogue empty section");
}

#[test]
fn parse_unit_overrides_duplicate_keys_with_last_value() {
    let body = "[Service]\nFoo=a\nFoo=b\nFoo=c\n";
    let u = parse_unit(body);
    assert_eq!(u["Service"]["Foo"], "c");
}

#[test]
fn parse_unit_skips_lines_without_equals() {
    let body = "[Service]\nFoo=bar\nthis is not a directive\nBaz=qux\n";
    let u = parse_unit(body);
    assert_eq!(u["Service"]["Foo"], "bar");
    assert_eq!(u["Service"]["Baz"], "qux");
}
