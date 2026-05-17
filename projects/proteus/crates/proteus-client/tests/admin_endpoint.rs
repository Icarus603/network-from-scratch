//! End-to-end test for the client-side admin endpoint.
//!
//! Spins up the admin HTTP server with a real CarrierHealth +
//! EndpointPool wired in, drives a couple of state transitions via
//! the public APIs, then issues real `tokio::net::TcpStream` GETs
//! against `/healthz`, `/status`, and `/status.json`. This validates
//! the *full chain* from atomic state → snapshot → HTTP body that the
//! unit tests can only assert in pieces.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};

use proteus_client::admin::{self, AliveFlag};
use proteus_client::carrier_health::CarrierHealth;
use proteus_client::endpoint_pool::EndpointPool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Fetch the full HTTP response body from `127.0.0.1:port + path`.
/// Returns the body string (after the `\r\n\r\n` header break).
async fn fetch_body(port: u16, path: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect to admin endpoint");
    let req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.expect("write GET");
    let mut buf = Vec::with_capacity(4096);
    stream.read_to_end(&mut buf).await.expect("read response");
    let s = String::from_utf8(buf).expect("UTF-8 response");
    let break_at = s.find("\r\n\r\n").expect("status/body boundary");
    s[break_at + 4..].to_string()
}

/// Same but returns the status line (the first line) for tests that
/// need to assert 200 vs 503 vs 404.
async fn fetch_status_line(port: u16, path: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect to admin endpoint");
    let req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.expect("write GET");
    let mut buf = Vec::with_capacity(4096);
    stream.read_to_end(&mut buf).await.expect("read response");
    let s = String::from_utf8(buf).expect("UTF-8 response");
    s.lines().next().unwrap_or("").to_string()
}

/// Find an available ephemeral port by binding 0 and dropping. Used
/// so the admin endpoint and the OS race ≤ a few microseconds — the
/// admin `serve()` re-binds before tests can race for it.
async fn pick_free_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral");
    let p = l.local_addr().expect("local_addr").port();
    drop(l);
    p
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_healthz_starts_503_and_flips_to_200_when_alive() {
    let alive: AliveFlag = Arc::new(AtomicBool::new(false));
    let port = pick_free_port().await;
    let bind = format!("127.0.0.1:{port}");

    let alive_for_serve = Arc::clone(&alive);
    let server_task = tokio::spawn(async move {
        let _ = admin::serve(bind, alive_for_serve, None, false, None).await;
    });

    // Give the listener a beat to bind.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // alive=false → expect 503.
    let status = fetch_status_line(port, "/healthz").await;
    assert!(
        status.starts_with("HTTP/1.1 503"),
        "expected 503 before alive flip, got: {status}"
    );

    // Flip alive→true and re-scrape.
    alive.store(true, std::sync::atomic::Ordering::Relaxed);
    let status = fetch_status_line(port, "/healthz").await;
    assert!(
        status.starts_with("HTTP/1.1 200"),
        "expected 200 after alive flip, got: {status}"
    );
    let body = fetch_body(port, "/healthz").await;
    assert_eq!(body, "alive\n");

    server_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_status_text_surfaces_healthy_carrier_and_pool() {
    let alive: AliveFlag = Arc::new(AtomicBool::new(true));
    let carrier = Arc::new(CarrierHealth::new());
    let pool = Arc::new(
        EndpointPool::new(vec!["primary:8443".into(), "backup:8443".into()]).expect("pool builds"),
    );
    let port = pick_free_port().await;
    let bind = format!("127.0.0.1:{port}");

    let alive_for_serve = Arc::clone(&alive);
    let carrier_for_serve = Arc::clone(&carrier);
    let pool_for_serve = Arc::clone(&pool);
    let server_task = tokio::spawn(async move {
        let _ = admin::serve(
            bind,
            alive_for_serve,
            Some(carrier_for_serve),
            true,
            Some(pool_for_serve),
        )
        .await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let body = fetch_body(port, "/status").await;
    assert!(body.contains("Status: alive"), "missing alive: {body}");
    assert!(
        body.contains("Carrier (β): healthy"),
        "missing healthy carrier: {body}"
    );
    assert!(
        body.contains("EndpointPool: 2 entries"),
        "missing pool count: {body}"
    );
    assert!(
        body.contains("[0] primary:8443: healthy, streak=0"),
        "missing primary entry: {body}"
    );
    assert!(
        body.contains("[1] backup:8443: healthy, streak=0"),
        "missing backup entry: {body}"
    );

    server_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_status_text_surfaces_suppressed_carrier_after_failures() {
    let alive: AliveFlag = Arc::new(AtomicBool::new(true));
    let carrier = Arc::new(CarrierHealth::with_threshold(2));
    // Drive β into suppression BEFORE spinning the server so the
    // first scrape sees the suppressed state.
    let t = Instant::now();
    carrier.record_beta_failure(t);
    carrier.record_beta_failure(t);
    assert!(
        carrier.is_suppressed(t),
        "test setup: carrier should be suppressed after 2 failures"
    );
    let port = pick_free_port().await;
    let bind = format!("127.0.0.1:{port}");

    let alive_for_serve = Arc::clone(&alive);
    let carrier_for_serve = Arc::clone(&carrier);
    let server_task = tokio::spawn(async move {
        let _ = admin::serve(bind, alive_for_serve, Some(carrier_for_serve), true, None).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let body = fetch_body(port, "/status").await;
    assert!(
        body.contains("Carrier (β): SUPPRESSED"),
        "missing SUPPRESSED state in body: {body}"
    );
    assert!(
        body.contains("s remaining"),
        "missing remaining-seconds annotation: {body}"
    );
    // Streak should appear as 2 (we did exactly 2 failures).
    assert!(
        body.contains("failure_streak: 2"),
        "wrong failure_streak in body: {body}"
    );

    server_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_status_json_round_trips_through_real_socket() {
    let alive: AliveFlag = Arc::new(AtomicBool::new(true));
    let pool = Arc::new(EndpointPool::new(vec!["a:1".into(), "b:2".into()]).expect("pool builds"));
    let port = pick_free_port().await;
    let bind = format!("127.0.0.1:{port}");

    let alive_for_serve = Arc::clone(&alive);
    let pool_for_serve = Arc::clone(&pool);
    let server_task = tokio::spawn(async move {
        let _ = admin::serve(bind, alive_for_serve, None, false, Some(pool_for_serve)).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let body = fetch_body(port, "/status.json").await;
    // JSON parseability spot-checks (no serde dep — we use raw
    // substring assertions for the fields we care about).
    assert!(body.starts_with('{'), "JSON should start with {{: {body}");
    assert!(body.ends_with("}\n"), "JSON should end with }}\\n: {body}");
    assert!(
        body.contains(r#""alive":true"#),
        "alive field missing: {body}"
    );
    assert!(
        body.contains(r#""carrier":null"#),
        "carrier null missing: {body}"
    );
    assert!(
        body.contains(r#""addr":"a:1""#),
        "a:1 entry missing: {body}"
    );
    assert!(
        body.contains(r#""addr":"b:2""#),
        "b:2 entry missing: {body}"
    );

    server_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_random_path_returns_404() {
    let alive: AliveFlag = Arc::new(AtomicBool::new(true));
    let port = pick_free_port().await;
    let bind = format!("127.0.0.1:{port}");

    let alive_for_serve = Arc::clone(&alive);
    let server_task = tokio::spawn(async move {
        let _ = admin::serve(bind, alive_for_serve, None, false, None).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let status = fetch_status_line(port, "/admin").await;
    assert!(
        status.starts_with("HTTP/1.1 404"),
        "expected 404 on random path, got: {status}"
    );

    server_task.abort();
}
