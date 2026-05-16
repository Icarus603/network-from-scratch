//! End-to-end test for `proteus-server admin status`.
//!
//! Boots an in-process metrics HTTP server (the same library code
//! the real binary uses), then spawns the actual `proteus-server`
//! binary as `admin status --url …`. Verifies the printed snapshot
//! contains the expected fields. Covers both the auth path (token
//! file) and the unauthenticated path.

use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use proteus_transport_alpha::metrics::ServerMetrics;
use proteus_transport_alpha::metrics_http::{self, MetricsAuth};
use tokio::net::TcpListener;
use tokio::time::timeout;

const STEP: Duration = Duration::from_secs(15);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_status_unauthenticated_prints_snapshot() {
    let metrics = Arc::new(ServerMetrics::default());
    metrics
        .sessions_accepted
        .fetch_add(11, std::sync::atomic::Ordering::Relaxed);
    metrics
        .handshakes_succeeded
        .fetch_add(7, std::sync::atomic::Ordering::Relaxed);
    metrics
        .firewall_denied
        .fetch_add(3, std::sync::atomic::Ordering::Relaxed);
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
                .output()
                .expect("spawn proteus-server admin status")
        }),
    )
    .await
    .expect("admin command timed out")
    .expect("join");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "exit code != 0\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("LIVE / READY"), "stdout:\n{stdout}");
    assert!(stdout.contains("sessions_accepted_total"));
    assert!(stdout.contains("11"));
    assert!(stdout.contains("handshakes_succeeded_total"));
    assert!(stdout.contains("firewall_denied"));

    server_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_status_with_bearer_token_succeeds() {
    let metrics = Arc::new(ServerMetrics::default());
    metrics
        .alive
        .store(true, std::sync::atomic::Ordering::Relaxed);
    metrics
        .ready
        .store(true, std::sync::atomic::Ordering::Relaxed);

    let token_str = "test-token-aaaaaaaaaaaaaa";
    let auth = MetricsAuth::new(token_str);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_task = tokio::spawn(metrics_http::serve_on_listener_with_auth(
        listener,
        Arc::clone(&metrics),
        auth,
    ));
    tokio::task::yield_now().await;

    // Write a token file the CLI can load.
    let tmpdir = std::env::temp_dir().join(format!(
        "proteus-admin-cli-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&tmpdir);
    std::fs::create_dir_all(&tmpdir).unwrap();
    let token_path = tmpdir.join("metrics.token");
    std::fs::write(&token_path, format!("{token_str}\n")).unwrap();

    let bin = env!("CARGO_BIN_EXE_proteus-server");
    let url = format!("http://{addr}/metrics");
    let token_arg = token_path.clone();
    let output = timeout(
        STEP,
        tokio::task::spawn_blocking(move || {
            Command::new(bin)
                .args(["admin", "status", "--url"])
                .arg(&url)
                .arg("--token-file")
                .arg(&token_arg)
                .arg("--timeout-secs")
                .arg("5")
                .output()
                .expect("spawn proteus-server admin status")
        }),
    )
    .await
    .expect("admin command timed out")
    .expect("join");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "exit code != 0\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("LIVE / READY"));

    server_task.abort();
    let _ = std::fs::remove_dir_all(&tmpdir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_status_with_wrong_token_returns_nonzero() {
    let metrics = Arc::new(ServerMetrics::default());
    let auth = MetricsAuth::new("real-token-xxxxxx");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_task = tokio::spawn(metrics_http::serve_on_listener_with_auth(
        listener,
        Arc::clone(&metrics),
        auth,
    ));
    tokio::task::yield_now().await;

    let tmpdir = std::env::temp_dir().join(format!(
        "proteus-admin-cli-wrong-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&tmpdir);
    std::fs::create_dir_all(&tmpdir).unwrap();
    let token_path = tmpdir.join("metrics.token");
    std::fs::write(&token_path, b"wrong-token\n").unwrap();

    let bin = env!("CARGO_BIN_EXE_proteus-server");
    let url = format!("http://{addr}/metrics");
    let token_arg = token_path.clone();
    let output = timeout(
        STEP,
        tokio::task::spawn_blocking(move || {
            Command::new(bin)
                .args(["admin", "status", "--url"])
                .arg(&url)
                .arg("--token-file")
                .arg(&token_arg)
                .arg("--timeout-secs")
                .arg("5")
                .output()
                .expect("spawn proteus-server admin status")
        }),
    )
    .await
    .expect("admin command timed out")
    .expect("join");

    assert!(
        !output.status.success(),
        "wrong token MUST cause non-zero exit"
    );

    server_task.abort();
    let _ = std::fs::remove_dir_all(&tmpdir);
}
