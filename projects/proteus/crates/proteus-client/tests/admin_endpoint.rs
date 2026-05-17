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
use proteus_client::ctx::ClientCtx;
use proteus_client::endpoint_pool::EndpointPool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_status_with_ctx_surfaces_concurrency_and_dials() {
    // Full e2e of the new serve_with_ctx path: build a real ctx with
    // a slot semaphore + dial counter bumps, scrape /status + /status.json,
    // assert the concurrency view and dial counters round-trip
    // through the live HTTP path.
    let alive: AliveFlag = Arc::new(AtomicBool::new(true));
    let ctx = Arc::new(ClientCtx::new(
        Arc::new(CarrierHealth::new()),
        None,
        Some(Arc::new(Semaphore::new(8))),
        8,
        true, // β configured
    ));
    // Simulate 5 dials: 3 succeed, 2 fail.
    for _ in 0..5 {
        ctx.record_dial_attempt();
    }
    for _ in 0..3 {
        ctx.record_dial_success();
    }
    for _ in 0..2 {
        ctx.record_dial_failure();
    }
    // Hold one permit so /status sees in_flight=1.
    let _permit = ctx
        .session_slots
        .as_ref()
        .unwrap()
        .clone()
        .acquire_owned()
        .await
        .expect("acquire permit");

    let port = pick_free_port().await;
    let bind = format!("127.0.0.1:{port}");
    let alive_for_serve = Arc::clone(&alive);
    let ctx_for_serve = Arc::clone(&ctx);
    let server_task = tokio::spawn(async move {
        let _ = admin::serve_with_ctx(bind, alive_for_serve, ctx_for_serve).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let body = fetch_body(port, "/status").await;
    assert!(
        body.contains("Concurrency: 1/8 in-flight"),
        "missing concurrency block: {body}"
    );
    assert!(
        body.contains("Dials: 5 attempted (3 ok, 2 failed)"),
        "missing dials line: {body}"
    );

    let json = fetch_body(port, "/status.json").await;
    assert!(
        json.contains(r#""concurrency":{"in_flight":1,"max_inflight":8}"#),
        "missing concurrency object in json: {json}"
    );
    assert!(
        json.contains(r#""dials":{"attempted":5,"succeeded":3,"failed":2}"#),
        "missing dials object in json: {json}"
    );

    server_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_status_with_ctx_omits_concurrency_when_cap_disabled() {
    let alive: AliveFlag = Arc::new(AtomicBool::new(true));
    let ctx = Arc::new(ClientCtx::new(
        Arc::new(CarrierHealth::new()),
        None,
        None, // no cap
        0,
        false, // β unconfigured → carrier view collapses to None
    ));
    let port = pick_free_port().await;
    let bind = format!("127.0.0.1:{port}");
    let alive_for_serve = Arc::clone(&alive);
    let ctx_for_serve = Arc::clone(&ctx);
    let server_task = tokio::spawn(async move {
        let _ = admin::serve_with_ctx(bind, alive_for_serve, ctx_for_serve).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let body = fetch_body(port, "/status").await;
    // Cap disabled: text rendering shows the disabled note.
    assert!(body.contains("Concurrency: cap disabled"), "{body}");
    // β unconfigured: carrier row collapses to "not configured".
    assert!(
        body.contains("Carrier (β): not configured"),
        "missing not-configured carrier line: {body}"
    );

    let json = fetch_body(port, "/status.json").await;
    assert!(json.contains(r#""concurrency":null"#), "{json}");
    assert!(json.contains(r#""carrier":null"#), "{json}");
    assert!(
        json.contains(r#""dials":{"attempted":0,"succeeded":0,"failed":0}"#),
        "{json}"
    );

    server_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_metrics_endpoint_returns_prometheus_exposition() {
    // Full e2e of the /metrics route over a real socket. Confirms
    // the Prometheus body crosses the HTTP boundary intact AND has
    // the expected content-type for Prometheus scraper compatibility.
    let alive: AliveFlag = Arc::new(AtomicBool::new(true));
    let pool = Arc::new(
        proteus_client::endpoint_pool::EndpointPool::new(vec![
            "primary:8443".into(),
            "backup:8443".into(),
        ])
        .expect("pool"),
    );
    // Bump primary's cumulative counters via the public API so the
    // Prometheus body has measurable per-endpoint values.
    let h0 = pool.endpoint_health(0).unwrap();
    h0.record_attempt();
    h0.record_attempt();
    h0.record_attempt();
    h0.record_success();
    h0.record_success();
    h0.record_failure(std::time::Instant::now());

    let ctx = Arc::new(ClientCtx::new(
        Arc::new(CarrierHealth::new()),
        Some(Arc::clone(&pool)),
        Some(Arc::new(Semaphore::new(16))),
        16,
        true,
    ));
    // Global dial counters too.
    ctx.record_dial_attempt();
    ctx.record_dial_attempt();
    ctx.record_dial_success();

    let port = pick_free_port().await;
    let bind = format!("127.0.0.1:{port}");
    let alive_for_serve = Arc::clone(&alive);
    let ctx_for_serve = Arc::clone(&ctx);
    let server_task = tokio::spawn(async move {
        let _ = admin::serve_with_ctx(bind, alive_for_serve, ctx_for_serve).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Issue a real Prometheus scrape and verify the body.
    let body = fetch_body(port, "/metrics").await;
    // Headline gauges.
    assert!(body.contains("proteus_client_up 1"), "missing up=1: {body}");
    // Global dial counters.
    assert!(
        body.contains("proteus_client_dials_attempted_total 2"),
        "missing global dials: {body}"
    );
    assert!(
        body.contains("proteus_client_dials_succeeded_total 1"),
        "missing global successes: {body}"
    );
    // Concurrency.
    assert!(
        body.contains("proteus_client_in_flight_sessions 0"),
        "missing in-flight gauge: {body}"
    );
    assert!(
        body.contains("proteus_client_max_inflight_sessions 16"),
        "missing max-inflight gauge: {body}"
    );
    // Per-endpoint counters with labels.
    assert!(
        body.contains(r#"proteus_client_endpoint_attempts_total{addr="primary:8443"} 3"#),
        "missing per-endpoint attempts: {body}"
    );
    assert!(
        body.contains(r#"proteus_client_endpoint_successes_total{addr="primary:8443"} 2"#),
        "missing per-endpoint successes: {body}"
    );
    assert!(
        body.contains(r#"proteus_client_endpoint_failures_total{addr="primary:8443"} 1"#),
        "missing per-endpoint failures: {body}"
    );
    // Backup entry — no activity yet, but the counter rows must
    // still exist with value 0 (per-entry gauges are emitted for
    // every entry, not just the active ones — that's what makes
    // Grafana "rate of zero" alerts work).
    assert!(
        body.contains(r#"proteus_client_endpoint_attempts_total{addr="backup:8443"} 0"#),
        "missing zero-valued backup attempts row: {body}"
    );

    server_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_metrics_content_type_is_prometheus_compatible() {
    // Prometheus scrapers verify the Content-Type matches
    // `text/plain; version=0.0.4` (or compatible). A wrong header
    // causes silent scrape failures.
    let alive: AliveFlag = Arc::new(AtomicBool::new(true));
    let ctx = Arc::new(ClientCtx::new(
        Arc::new(CarrierHealth::new()),
        None,
        None,
        0,
        false,
    ));
    let port = pick_free_port().await;
    let bind = format!("127.0.0.1:{port}");
    let alive_for_serve = Arc::clone(&alive);
    let ctx_for_serve = Arc::clone(&ctx);
    let server_task = tokio::spawn(async move {
        let _ = admin::serve_with_ctx(bind, alive_for_serve, ctx_for_serve).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Read the FULL response (headers + body) so we can inspect
    // Content-Type.
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let req =
        format!("GET /metrics HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.expect("write GET");
    let mut buf = Vec::with_capacity(4096);
    stream.read_to_end(&mut buf).await.expect("read response");
    let s = String::from_utf8(buf).expect("UTF-8 response");
    assert!(
        s.contains("Content-Type: text/plain; version=0.0.4"),
        "missing Prometheus content-type header: {s}"
    );

    server_task.abort();
}
