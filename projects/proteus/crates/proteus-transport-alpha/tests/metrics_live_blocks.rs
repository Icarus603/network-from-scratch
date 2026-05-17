//! Integration test for `serve_with_auth_full_v12`'s
//! `live_blocks` injection — proves the closures supplied at
//! construction time are invoked on every `/metrics` request and
//! their output is concatenated into the scrape body.
//!
//! The panic-counter wiring is the canonical use case; here we
//! drive it with a synthetic closure (AtomicU64 incremented on
//! each render) so the test stays isolated from the real
//! `proteus-panic-hook` global state.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use proteus_transport_alpha::metrics::ServerMetrics;
use proteus_transport_alpha::metrics_http::{serve_with_auth_full_v12, LiveMetricsBlock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn fetch_metrics(addr: std::net::SocketAddr) -> String {
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    String::from_utf8_lossy(&buf).to_string()
}

#[tokio::test]
async fn live_metrics_block_is_invoked_on_every_scrape_and_appended_to_body() {
    // Build a fresh metrics struct + a live-block closure that
    // increments a counter and renders a Prometheus-shaped line.
    let metrics = Arc::new(ServerMetrics::default());
    metrics
        .alive
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let invocations = Arc::new(AtomicU64::new(0));
    let inv_for_closure = Arc::clone(&invocations);
    let block: Arc<LiveMetricsBlock> = Arc::new(move || {
        let n = inv_for_closure.fetch_add(1, Ordering::Relaxed) + 1;
        format!(
            "# HELP test_live_block_invocations Synthetic counter incremented on each scrape.\n\
             # TYPE test_live_block_invocations counter\n\
             test_live_block_invocations {n}\n"
        )
    });

    // Bind to an ephemeral port via 127.0.0.1:0 — we ask the
    // serve function to bind, then capture the addr by spawning
    // the server BEFORE we issue any GETs. The v12 fn takes a
    // string addr; for a deterministic port we pre-bind, drop,
    // then race-bind isn't safe — use the standard pattern of
    // letting serve bind 127.0.0.1:0 and look up later via
    // `local_addr()`. v12 doesn't expose the listener
    // post-bind, so we just retry-connect on a fixed port range.
    //
    // Simpler: race the bind by binding ourselves first to get a
    // free port, drop, then immediately pass it back. Tiny race
    // window but acceptable for a deterministic test.
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);

    let metrics_for_server = Arc::clone(&metrics);
    let server_task = tokio::spawn(async move {
        let _ = serve_with_auth_full_v12(
            &addr.to_string(),
            metrics_for_server,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            vec![block],
        )
        .await;
    });

    // Wait for the listener to come up. 50ms is plenty on
    // loopback; the test isn't latency-sensitive.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Scrape 1 — closure should have fired once and the body
    // should contain the synthetic line with value `1`.
    let body1 = fetch_metrics(addr).await;
    assert!(
        body1.contains("test_live_block_invocations 1"),
        "first scrape missing live block output:\n{body1}"
    );
    assert!(
        body1.contains("# TYPE test_live_block_invocations counter"),
        "first scrape missing # TYPE line"
    );
    // Core Prometheus block from ServerMetrics should also be
    // present — verifies live block APPENDS, not REPLACES.
    assert!(
        body1.contains("proteus_sessions_accepted_total"),
        "first scrape missing core metrics body"
    );

    // Scrape 2 — closure fires again, value increments.
    let body2 = fetch_metrics(addr).await;
    assert!(
        body2.contains("test_live_block_invocations 2"),
        "second scrape should see counter=2:\n{body2}"
    );
    assert_eq!(
        invocations.load(Ordering::Relaxed),
        2,
        "closure should have been invoked exactly twice"
    );

    server_task.abort();
}

#[tokio::test]
async fn empty_live_blocks_vec_does_not_append_anything() {
    let metrics = Arc::new(ServerMetrics::default());
    metrics
        .alive
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);
    let metrics_for_server = Arc::clone(&metrics);
    let server_task = tokio::spawn(async move {
        let _ = serve_with_auth_full_v12(
            &addr.to_string(),
            metrics_for_server,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Vec::new(),
        )
        .await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let body = fetch_metrics(addr).await;
    // Sanity: core body present, no synthetic block.
    assert!(body.contains("proteus_sessions_accepted_total"));
    assert!(!body.contains("test_live_block_invocations"));
    server_task.abort();
}
