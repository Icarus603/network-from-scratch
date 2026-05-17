//! End-to-end test: the /metrics endpoint exposes the probe-anomaly
//! detector's diagnostic gauges + recent-fires labelled lines after
//! a real cover-forward burst trips the detector.
//!
//! ## What this pins
//!
//! Without this test, the metrics-export wiring could silently
//! regress in three ways and the operator would lose visibility:
//!
//!   1. `ServerCtx::probe_anomaly()` accessor returns None → no
//!      detector reference threaded into `serve_with_auth_full`.
//!   2. `serve_with_auth_full` forgets to pass the detector to
//!      `render_full`.
//!   3. `render_full` forgets to call `prometheus_extension`.
//!
//! Any of the three would leave the bare `probe_anomalies_fired_total`
//! counter visible but the labelled `proteus_probe_anomaly_recent_secs`
//! lines absent — the operator could see "we got 5 fires today" but
//! NOT "from which /24". The actionable-IP information would be
//! buried in log streams instead of immediately visible on the
//! Prometheus dashboard.

use std::sync::Arc;
use std::time::Duration;

use proteus_transport_alpha::metrics::ServerMetrics;
use proteus_transport_alpha::metrics_http;
use proteus_transport_alpha::probe_anomaly::ProbeAnomalyDetector;
use proteus_transport_alpha::server::{self, ServerCtx, ServerKeys};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const STEP: Duration = Duration::from_secs(15);

async fn spawn_drain_cover() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = timeout(Duration::from_millis(100), stream.read(&mut buf)).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    addr
}

async fn probe_once(proxy_addr: std::net::SocketAddr) {
    let Ok(Ok(mut stream)) = timeout(STEP, TcpStream::connect(proxy_addr)).await else {
        return;
    };
    let _ = stream.write_all(&[0x55, 0x00]).await;
    let _ = stream.flush().await;
    let mut buf = [0u8; 4096];
    while let Ok(Ok(n)) = timeout(Duration::from_millis(500), stream.read(&mut buf)).await {
        if n == 0 {
            break;
        }
    }
}

async fn http_get(addr: std::net::SocketAddr, path: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let req = format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut body = String::new();
    stream.read_to_string(&mut body).await.unwrap();
    body
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn metrics_endpoint_exposes_probe_anomaly_recent_fires_after_burst() {
    let cover_addr = spawn_drain_cover().await;

    // Threshold = 3 in 30 s window — small enough to fire fast in
    // the test.
    let detector = Arc::new(ProbeAnomalyDetector::new(Duration::from_secs(30), 3, 1024));
    let metrics = Arc::new(ServerMetrics::default());
    let server_keys = ServerKeys::generate();
    let ctx = Arc::new(
        ServerCtx::new(server_keys)
            .with_cover(cover_addr.to_string())
            .with_probe_anomaly_detector(Arc::clone(&detector))
            .with_metrics(Arc::clone(&metrics)),
    );

    // Bind the proxy.
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let server_ctx = Arc::clone(&ctx);
    let server_task = tokio::spawn(server::serve(
        proxy_listener,
        server_ctx,
        |_session| async {},
    ));

    // Bind the metrics endpoint via the FULL variant — this is the
    // codepath that should include the probe-anomaly extension.
    let metrics_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let metrics_addr = metrics_listener.local_addr().unwrap();
    let metrics_for_task = Arc::clone(&metrics);
    let detector_for_task = Arc::clone(&detector);
    let metrics_task = tokio::spawn(async move {
        let _ = metrics_http::serve_on_listener_full(
            metrics_listener,
            metrics_for_task,
            None,
            Some(detector_for_task),
        )
        .await;
    });

    // Drive 5 probes from loopback (one /24) → 3rd at threshold
    // fires the detector. 4-5 are silent (fire-once-per-burst) but
    // the ring buffer still has the one entry.
    for _ in 0..5 {
        probe_once(proxy_addr).await;
    }

    // Give the spawned cover-forward tasks a beat to write the
    // metric. Poll up to 5s for fired count > 0.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while metrics
        .probe_anomalies_fired
        .load(std::sync::atomic::Ordering::Relaxed)
        == 0
        && std::time::Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Scrape /metrics — the FULL handler must include the detector
    // extension lines.
    let body = http_get(metrics_addr, "/metrics").await;

    // Bare counter present (verifies the existing wiring).
    assert!(
        body.contains("proteus_probe_anomalies_fired_total 1"),
        "expected fired counter at 1 in /metrics body:\n{body}",
    );

    // Detector extension gauges present.
    assert!(
        body.contains("# TYPE proteus_probe_anomaly_tracked_prefixes gauge"),
        "missing tracked_prefixes HELP/TYPE; body:\n{body}"
    );
    assert!(
        body.contains("# TYPE proteus_probe_anomaly_dropped_inserts_total counter"),
        "missing dropped_inserts_total HELP/TYPE; body:\n{body}"
    );
    assert!(
        body.contains("# TYPE proteus_probe_anomaly_recent_secs gauge"),
        "missing recent_secs HELP/TYPE; body:\n{body}"
    );

    // The recent-fires line must carry the loopback /24 label.
    // Loopback = 127.0.0.1; /24 prefix renders as 127.0.0.0/24.
    assert!(
        body.contains("proteus_probe_anomaly_recent_secs{prefix=\"127.0.0.0/24\"}"),
        "expected labelled recent_secs line for 127.0.0.0/24; body:\n{body}",
    );

    server_task.abort();
    metrics_task.abort();
}

/// Back-compat sanity: the legacy `serve_on_listener` (no detector
/// ref) must still serve /metrics and just OMIT the detector
/// extension lines — operators who haven't migrated to the FULL
/// variant don't get a hard error, they just don't see the new
/// signals.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn legacy_serve_path_works_without_probe_anomaly_extension() {
    let metrics = Arc::new(ServerMetrics::default());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let metrics_for_task = Arc::clone(&metrics);
    let task = tokio::spawn(async move {
        let _ = metrics_http::serve_on_listener(listener, metrics_for_task).await;
    });

    let body = http_get(addr, "/metrics").await;
    // Bare counter must be there.
    assert!(body.contains("proteus_cover_forwards_total"));
    // Probe-anomaly extension lines must NOT be there (back-compat
    // path doesn't have a detector to query).
    assert!(
        !body.contains("proteus_probe_anomaly_tracked_prefixes"),
        "legacy serve path leaked detector extension lines without a detector configured"
    );
    task.abort();
}
