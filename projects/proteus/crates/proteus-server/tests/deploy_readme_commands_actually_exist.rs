//! Iter-123: every command line documented in deploy/README.md
//! must be RECOGNIZED by the actual binary. Pre-iter-123 the
//! README told operators to run `proteus-server host-preflight`
//! and `proteus-client host-preflight`, but neither subcommand
//! existed — clap returned exit 2 with "unrecognized subcommand".
//! The earlier iter-118+120 contract tests passed because they
//! only grepped the README for the string; they had no way to
//! tell aspiration from reality.
//!
//! This test closes the gap by shelling out to BOTH binaries
//! with `--help` on every documented subcommand. Any FAIL means
//! either the README documents a non-existent command, or a
//! subcommand has been renamed since the README was written.
//!
//! The discovery is mechanical: regex-scan the README for
//! `proteus-server <subcommand>` / `proteus-client <subcommand>`
//! occurrences in fenced bash blocks, then run each. The set of
//! "subcommands to skip" is intentionally small — only commands
//! the operator should NEVER run as part of preflight (`run`,
//! `keygen`, etc. are validated separately).
//!
//! Why this matters for production:
//! - An operator following the README's mandatory preflight gate
//!   would have hit "unrecognized subcommand" on the very first
//!   call. The deployment would be blocked at step 2 of 5 with
//!   no obvious recovery path (clap's "tip: a similar subcommand
//!   exists: 'preflight'" is helpful but easy to miss).
//! - For a security-critical proxy whose README is the canonical
//!   operator surface, the README contract MUST be executable.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;

const SERVER_BIN: &str = env!("CARGO_BIN_EXE_proteus-server");

/// `CARGO_BIN_EXE_*` only resolves binaries from the same crate,
/// so we locate the client binary by walking up from the server's
/// `target/{profile}/proteus-server` to the sibling
/// `proteus-client` file. This mirrors the layout cargo always
/// produces for a workspace.
fn client_bin_path() -> std::path::PathBuf {
    let server = std::path::PathBuf::from(SERVER_BIN);
    let parent = server.parent().expect("CARGO_BIN_EXE_proteus-server has no parent");
    let candidate = parent.join("proteus-client");
    assert!(
        candidate.exists(),
        "expected sibling proteus-client binary at {}; build it first with \
         `cargo build --bin proteus-client` (in release/debug matching this test)",
        candidate.display()
    );
    candidate
}

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

/// Pull out every `proteus-server <subcommand>` or
/// `proteus-client <subcommand>` reference **from fenced bash
/// blocks only** (not prose). Prose mentions like "use the
/// `proteus-server status` command to …" are extraction noise —
/// what matters for operator gating is whether the
/// copy-pasteable code blocks all parse. Subcommand chains up to
/// 3 levels: `preflight check-host`, `admin alerts-check`.
/// Returns `(binary, subcommand_chain)` pairs.
fn extract_documented_commands(body: &str) -> BTreeSet<(String, Vec<String>)> {
    let mut found = BTreeSet::new();
    let mut in_bash = false;
    for raw_line in body.lines() {
        let line = raw_line.trim_start();
        // Track fence boundaries. We only treat ```bash and ```sh
        // (and ```shell) as "code we should be able to run".
        // Other fences (yaml, json, text, no-language) are
        // ignored — prose-adjacent.
        if let Some(rest) = line.strip_prefix("```") {
            if in_bash {
                in_bash = false;
            } else {
                let tag = rest.trim().to_ascii_lowercase();
                if matches!(tag.as_str(), "bash" | "sh" | "shell") {
                    in_bash = true;
                }
            }
            continue;
        }
        if !in_bash {
            continue;
        }
        // Strip a leading shell comment `#` — we don't want to
        // run `# this is a comment`.
        let line = line.trim_end();
        if line.starts_with('#') {
            continue;
        }
        for (bin_name, bin_tag) in
            [("proteus-server", "proteus-server"), ("proteus-client", "proteus-client")]
        {
            if let Some(idx) = line.find(bin_tag) {
                // Require that the char before the binary name is
                // a word boundary (start-of-line, whitespace, or
                // shell separator) — avoid catching `not-proteus-server`.
                if idx > 0 {
                    let prev = line.as_bytes()[idx - 1];
                    if !matches!(prev, b' ' | b'\t' | b';' | b'|' | b'&' | b'(' | b'`') {
                        continue;
                    }
                }
                let rest = &line[idx + bin_tag.len()..];
                let mut tokens = Vec::new();
                for tok in rest.split_whitespace() {
                    // Stop at first option/flag/redirect/pipe/
                    // line-continuation / path / etc.
                    if tok.starts_with('-')
                        || tok.starts_with('|')
                        || tok.starts_with('>')
                        || tok.starts_with('<')
                        || tok.starts_with('&')
                        || tok.starts_with(';')
                        || tok.starts_with('$')
                        || tok.starts_with('`')
                        || tok.starts_with('/')
                        || tok.starts_with('~')
                        || tok.starts_with('"')
                        || tok.starts_with('\'')
                        || tok.starts_with('#')
                        || tok.starts_with('\\')
                        || tok.contains('=')
                    {
                        break;
                    }
                    // The first token after the binary must look
                    // like a subcommand (lowercase + hyphens). If
                    // it doesn't, we're in prose-disguised-as-code
                    // (rare in fenced bash but possible) and we
                    // skip the whole reference.
                    if !tok
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c == '-')
                    {
                        break;
                    }
                    tokens.push(tok.to_string());
                    if tokens.len() >= 3 {
                        break;
                    }
                }
                if !tokens.is_empty() {
                    found.insert((bin_name.to_string(), tokens));
                }
            }
        }
    }
    found
}

/// Subcommands we don't try to invoke even though they appear in
/// the README — usually because they're the "long-running daemon"
/// command (`run`) or take a positional `--out` we don't want to
/// create temp dirs for.
fn skip_command(bin: &str, chain: &[String]) -> bool {
    let head = chain.first().map(String::as_str).unwrap_or("");
    // Bare `run` / `keygen` — daemon + side-effectful, --help is
    // covered by other tests.
    if matches!(head, "run") {
        return true;
    }
    // Some README mentions appear inside prose like "use
    // `proteus-server help`" — `help` IS a clap-generated
    // subcommand but listing every one is noise.
    if matches!(head, "help") {
        return true;
    }
    // Iter-123 specifically excludes: prose references where the
    // README writes "the server's `validate` command" without
    // intending a literal shell invocation. The regex catches
    // those — but `--help` succeeds for any real subcommand and
    // fails for typos, so we still INVOKE them as a smoke test.
    let _ = bin;
    false
}

/// Returns `Some(stderr)` if `<bin> <chain...> --help` fails to
/// be recognized (exit != 0 OR clap's "unrecognized" message).
fn invoke_help(bin_path: &str, chain: &[String]) -> Option<String> {
    let mut cmd = Command::new(bin_path);
    for arg in chain {
        cmd.arg(arg);
    }
    cmd.arg("--help");
    let output = cmd.output().expect("spawn binary");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    // clap recognises the subcommand chain iff exit 0 (--help
    // prints to stdout and exits 0).
    if !output.status.success() {
        return Some(format!("exit={:?} stderr={stderr}", output.status.code()));
    }
    if stderr.contains("unrecognized subcommand") || stderr.contains("invalid value") {
        return Some(format!("clap rejected: {stderr}"));
    }
    None
}

#[test]
fn iter123_every_readme_command_is_recognized_by_clap() {
    let body = read_readme();
    let commands = extract_documented_commands(&body);
    assert!(
        !commands.is_empty(),
        "extractor found no `proteus-{{server,client}} <cmd>` references — \
         either the README is empty or the extractor regex is wrong"
    );

    // The canonical preflight gate commands MUST be present. If
    // any of these go missing from the README the security
    // checklist is broken; if any are present but not recognized
    // by clap, the operator can't actually run them.
    let must_be_present = [
        ("proteus-server", vec!["validate"]),
        ("proteus-server", vec!["preflight", "check-host"]),
        ("proteus-client", vec!["validate"]),
        ("proteus-client", vec!["check-host"]),
        ("proteus-client", vec!["connect-test"]),
    ];
    for (bin, chain) in &must_be_present {
        let chain_vec: Vec<String> = chain.iter().map(|s| s.to_string()).collect();
        assert!(
            commands.contains(&(bin.to_string(), chain_vec.clone())),
            "README must document `{} {}` (preflight gate canonical command)",
            bin,
            chain.join(" ")
        );
    }

    let client_bin = client_bin_path();
    let client_bin_str = client_bin.to_string_lossy().into_owned();
    // Invoke `--help` for each unique (bin, chain) pair. Collect
    // ALL failures so the test report tells the operator every
    // broken command in one run, not just the first.
    let mut failures = Vec::new();
    let mut invoked = 0usize;
    for (bin, chain) in &commands {
        if skip_command(bin, chain) {
            continue;
        }
        let bin_path: &str = match bin.as_str() {
            "proteus-server" => SERVER_BIN,
            "proteus-client" => &client_bin_str,
            _ => unreachable!("extractor only emits two binary names"),
        };
        invoked += 1;
        if let Some(reason) = invoke_help(bin_path, chain) {
            failures.push(format!("  - `{} {}`: {}", bin, chain.join(" "), reason));
        }
    }
    // Refuse to pass trivially if the extractor regressed and
    // started returning zero invokable commands. 5 = the minimum
    // (the canonical preflight gate set above) — any healthy
    // README will exercise at least 10.
    assert!(
        invoked >= 5,
        "extractor invoked only {invoked} commands; the canonical preflight gate \
         alone is 5 — extractor regression suspected"
    );

    assert!(
        failures.is_empty(),
        "deploy/README.md documents {} command line(s) that the actual binary \
         doesn't recognise — every preflight gate FAILs at clap before doing \
         any work. Broken commands:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Iter-123 narrow regression test: the specific
/// `host-preflight` bug we just fixed must stay fixed. If the
/// README ever reintroduces `proteus-server host-preflight` or
/// `proteus-client host-preflight` (e.g. because someone reverts
/// a refactor without re-reading clap's command surface), this
/// test fails immediately with a copy-pasteable explanation.
#[test]
fn iter123_readme_does_not_reintroduce_phantom_host_preflight_subcommand() {
    let body = read_readme();
    for phantom in [
        "proteus-server host-preflight",
        "proteus-client host-preflight",
    ] {
        assert!(
            !body.contains(phantom),
            "deploy/README.md contains `{phantom}` but no such subcommand exists. \
             The real CLI shape is `proteus-server preflight check-host` and \
             `proteus-client check-host` (see iter-123 in CHANGELOG.md). If you \
             renamed/added a subcommand, update both the README and the \
             `iter120_readme_documents_host_preflight_and_connect_test` test."
        );
    }
}
