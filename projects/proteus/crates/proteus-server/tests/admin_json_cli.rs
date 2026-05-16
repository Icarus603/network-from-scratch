//! Integration test for `--format json` on the admin subcommands.
//!
//! Verifies the binary emits a well-formed JSON document that any
//! standard parser would accept (we don't pull in serde_json — we
//! shape-check the output, then sanity-check key/value presence).

use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use proteus_transport_alpha::metrics::ServerMetrics;
use proteus_transport_alpha::metrics_http;
use tokio::net::TcpListener;
use tokio::time::timeout;

const STEP: Duration = Duration::from_secs(15);

fn tmpdir(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "proteus-admin-json-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        tag,
    ));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// Shape-check a JSON document: braces balanced, quotes balanced
/// outside escape sequences. Cheap structural sanity that catches
/// the most common emission bugs (truncated output, unclosed
/// strings, trailing comma → not parseable).
fn is_balanced_json_object(s: &str) -> bool {
    let s = s.trim();
    if !s.starts_with('{') || !s.ends_with('}') {
        return false;
    }
    let mut depth = 0i32;
    let mut in_str = false;
    let mut escape = false;
    for c in s.chars() {
        if escape {
            escape = false;
            continue;
        }
        if in_str {
            if c == '\\' {
                escape = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            '"' => in_str = true,
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            _ => {}
        }
    }
    depth == 0 && !in_str
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_status_json_format_emits_well_formed_document() {
    let metrics = Arc::new(ServerMetrics::default());
    metrics
        .sessions_accepted
        .fetch_add(42, std::sync::atomic::Ordering::Relaxed);
    metrics
        .firewall_denied
        .fetch_add(7, std::sync::atomic::Ordering::Relaxed);
    metrics
        .alive
        .store(true, std::sync::atomic::Ordering::Relaxed);
    metrics
        .ready
        .store(true, std::sync::atomic::Ordering::Relaxed);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_task = tokio::spawn(metrics_http::serve_on_listener(
        listener,
        Arc::clone(&metrics),
    ));
    tokio::task::yield_now().await;

    let bin = env!("CARGO_BIN_EXE_proteus-server");
    let url = format!("http://{addr}/metrics");
    let output = timeout(
        STEP,
        tokio::task::spawn_blocking(move || {
            Command::new(bin)
                .args(["admin", "status", "--url"])
                .arg(&url)
                .arg("--timeout-secs")
                .arg("5")
                .arg("--format")
                .arg("json")
                .output()
                .expect("spawn proteus-server admin status --format json")
        }),
    )
    .await
    .expect("admin command timed out")
    .expect("join");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // Single line + trailing newline.
    let trimmed = stdout.trim_end_matches('\n');
    assert!(
        !trimmed.contains('\n'),
        "JSON output should be one line: {stdout}"
    );
    assert!(
        is_balanced_json_object(trimmed),
        "JSON should be balanced: {trimmed}"
    );
    // Key fields present.
    assert!(stdout.contains("\"alive\":true"));
    assert!(stdout.contains("\"ready\":true"));
    assert!(stdout.contains("\"sessions_accepted\":42"));
    assert!(stdout.contains("\"firewall_denied\":7"));
    assert!(stdout.contains("\"total_rejected\":7"));
    assert!(stdout.contains("\"other\":"));
    // Must NOT contain the text-mode banner.
    assert!(
        !stdout.contains("============="),
        "JSON output should not contain text banner: {stdout}"
    );

    server_task.abort();
}

#[test]
fn admin_diff_json_format_emits_balanced_document() {
    let dir = tmpdir("diff-json");
    let before = dir.join("before");
    let after = dir.join("after");

    std::fs::write(
        &before,
        "proteus_up 1\n\
         proteus_ready 1\n\
         proteus_sessions_accepted_total 100\n\
         proteus_firewall_denied_total 10\n",
    )
    .unwrap();
    std::fs::write(
        &after,
        "proteus_up 1\n\
         proteus_ready 1\n\
         proteus_sessions_accepted_total 130\n\
         proteus_firewall_denied_total 15\n",
    )
    .unwrap();

    let bin = env!("CARGO_BIN_EXE_proteus-server");
    let output = Command::new(bin)
        .args(["admin", "diff", "--before"])
        .arg(&before)
        .arg("--after")
        .arg(&after)
        .arg("--interval-secs")
        .arg("30.0")
        .arg("--format")
        .arg("json")
        .output()
        .expect("spawn proteus-server admin diff --format json");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let trimmed = stdout.trim_end_matches('\n');
    assert!(is_balanced_json_object(trimmed), "unbalanced: {trimmed}");
    assert!(stdout.contains("\"interval_secs\":30."));
    assert!(stdout.contains("\"sessions_accepted\":30"));
    assert!(stdout.contains("\"firewall_denied\":5"));
    assert!(stdout.contains("\"total_rejected\":5"));
    assert!(stdout.contains("\"counter_reset\":false"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn admin_status_rejects_invalid_format() {
    let bin = env!("CARGO_BIN_EXE_proteus-server");
    let output = Command::new(bin)
        .args(["admin", "status", "--url", "http://127.0.0.1:1/"])
        .arg("--format")
        .arg("yaml")
        .output()
        .expect("spawn proteus-server admin status --format yaml");
    assert!(
        !output.status.success(),
        "invalid format MUST cause non-zero exit"
    );
}
