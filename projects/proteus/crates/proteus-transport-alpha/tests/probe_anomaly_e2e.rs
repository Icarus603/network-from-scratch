//! End-to-end test for the probe-anomaly detector wiring.
//!
//! Pins the load-bearing property: when a single source-IP /24 sends
//! N+ failed-handshake probes within the sliding window, the
//! `proteus_probe_anomalies_fired_total` Prometheus counter
//! increments exactly ONCE for the burst (fire-once semantics) AND
//! a structured WARN log line is emitted (verified indirectly via
//! the counter — the log surface is operator-visible separately).
//!
//! Why this is a separate test from `probe_anomaly::tests`:
//!
//! The unit tests in `probe_anomaly::tests` verify the detector's
//! state machine in isolation (record_at → Option<key>). This file
//! verifies the *wiring*: that `route_to_cover_or_drop` and the
//! handshake-failure cover branch in `server.rs` both reach the
//! detector with the right peer address, that the detector's
//! Some(key) signal becomes a metric increment, and that the metric
//! increments at the right point in the burst.

use std::sync::Arc;
use std::time::Duration;

use proteus_transport_alpha::metrics::ServerMetrics;
use proteus_transport_alpha::probe_anomaly::ProbeAnomalyDetector;
use proteus_transport_alpha::server::{self, ServerCtx, ServerKeys};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const STEP: Duration = Duration::from_secs(15);

/// Spawn a no-op cover server (accepts + immediately drops). The
/// cover server's behavior doesn't matter here — we're measuring
/// the anomaly detector's count of cover-forward triggers, not the
/// success of the forward itself.
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

/// Drive one auth-failed probe: TCP connect, send bytes that don't
/// parse as a Proteus ClientHello frame, drop. Same shape as
/// cover_forward.rs's existing test scaffolding.
async fn probe_once(proxy_addr: std::net::SocketAddr) {
    let Ok(Ok(mut stream)) = timeout(STEP, TcpStream::connect(proxy_addr)).await else {
        return;
    };
    let _ = stream.write_all(&[0x55, 0x00]).await;
    let _ = stream.flush().await;
    // Read until EOF so the cover-forward completes its full cycle
    // (and the metric increments).
    let mut buf = [0u8; 4096];
    while let Ok(Ok(n)) = timeout(Duration::from_millis(500), stream.read(&mut buf)).await {
        if n == 0 {
            break;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probe_anomaly_fires_once_per_burst_after_threshold_probes_from_same_src() {
    let cover_addr = spawn_drain_cover().await;

    // Detector: threshold = 3 within a 30s window. Low threshold so
    // the test stays fast; the production default is 8 in 300s.
    let detector = Arc::new(ProbeAnomalyDetector::new(Duration::from_secs(30), 3, 1024));
    let metrics = Arc::new(ServerMetrics::default());
    let server_keys = ServerKeys::generate();
    let ctx = Arc::new(
        ServerCtx::new(server_keys)
            .with_cover(cover_addr.to_string())
            .with_probe_anomaly_detector(Arc::clone(&detector))
            .with_metrics(Arc::clone(&metrics)),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let server_ctx = Arc::clone(&ctx);
    let server_task = tokio::spawn(server::serve(listener, server_ctx, |_session| async {}));

    // 5 probes from this single loopback src (all hash to the same
    // /24 = 127.0.0.0/24). Threshold = 3 → the 3rd probe MUST fire.
    // The 4th and 5th MUST be silent (fire-once-per-burst).
    for _ in 0..5 {
        probe_once(proxy_addr).await;
    }

    // Give the spawned cover-forward tasks a beat to write the
    // metric. The increment happens inside the cover-forward task
    // (not at probe submission), so we need to wait until the
    // cover-forward has called record_at.
    //
    // Use a polling loop with a tight upper bound rather than a
    // sleep, so the test stays fast on healthy machines AND robust
    // under heavy parallel-test contention.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while metrics
        .probe_anomalies_fired
        .load(std::sync::atomic::Ordering::Relaxed)
        == 0
        && std::time::Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Give a small grace period to detect any erroneous extra fires.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let fired = metrics
        .probe_anomalies_fired
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        fired, 1,
        "expected exactly 1 anomaly fire across 5 probes from same /24 \
         (fire-once-per-burst at threshold=3); got {fired}",
    );

    // Sanity: the detector recorded 5 events for the /24 (capped at
    // threshold = 3 in the deque, but the alerted flag is set).
    let tracked = detector.tracked();
    assert!(
        tracked >= 1,
        "detector should be tracking ≥1 prefix; got {tracked}"
    );

    server_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probe_anomaly_silent_when_detector_unset() {
    let cover_addr = spawn_drain_cover().await;
    let metrics = Arc::new(ServerMetrics::default());
    let server_keys = ServerKeys::generate();
    // NO `with_probe_anomaly_detector(...)` — detector unset.
    let ctx = Arc::new(
        ServerCtx::new(server_keys)
            .with_cover(cover_addr.to_string())
            .with_metrics(Arc::clone(&metrics)),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let server_ctx = Arc::clone(&ctx);
    let server_task = tokio::spawn(server::serve(listener, server_ctx, |_session| async {}));

    // 10 probes — well above any reasonable threshold.
    for _ in 0..10 {
        probe_once(proxy_addr).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    let fired = metrics
        .probe_anomalies_fired
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        fired, 0,
        "detector is unset — counter MUST stay at 0; got {fired}"
    );

    // cover_forwards counter SHOULD have incremented (the cover-
    // forward path itself runs; only the anomaly count is silent
    // when the detector is absent).
    let cover = metrics
        .cover_forwards
        .load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        cover >= 1,
        "cover_forwards should still increment when detector is unset; got {cover}",
    );

    server_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probe_anomaly_does_not_fire_below_threshold() {
    let cover_addr = spawn_drain_cover().await;
    let detector = Arc::new(ProbeAnomalyDetector::new(Duration::from_secs(30), 5, 1024));
    let metrics = Arc::new(ServerMetrics::default());
    let server_keys = ServerKeys::generate();
    let ctx = Arc::new(
        ServerCtx::new(server_keys)
            .with_cover(cover_addr.to_string())
            .with_probe_anomaly_detector(Arc::clone(&detector))
            .with_metrics(Arc::clone(&metrics)),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let server_ctx = Arc::clone(&ctx);
    let server_task = tokio::spawn(server::serve(listener, server_ctx, |_session| async {}));

    // 4 probes — below threshold = 5.
    for _ in 0..4 {
        probe_once(proxy_addr).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    let fired = metrics
        .probe_anomalies_fired
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        fired, 0,
        "4 probes < threshold = 5; counter MUST stay at 0; got {fired}",
    );

    server_task.abort();
}
