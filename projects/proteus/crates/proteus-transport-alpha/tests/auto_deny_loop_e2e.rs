//! End-to-end test for the probe-anomaly → auto-deny → admission
//! short-circuit loop.
//!
//! ## What this pins (the load-bearing chain)
//!
//! 1. A burst of cover-forward-triggering probes from one /24
//!    pushes the probe-anomaly detector past its threshold.
//! 2. On the fire, `record_probe_anomaly` inserts the /24 into the
//!    `AutoDenyList` with the configured TTL.
//! 3. Subsequent connections from that /24 hit
//!    `admission_ok::auto_deny.is_denied(...)` BEFORE the firewall
//!    snapshot, increment the `firewall_denied` counter, and route
//!    to cover without paying any further admission cost.
//!
//! Without this chain working end-to-end, the operator-opt-in
//! auto-deny knob is silent — they get the YAML field but it
//! does nothing. This test catches any breakage in the wiring.

use std::sync::Arc;
use std::time::Duration;

use proteus_transport_alpha::auto_deny::AutoDenyList;
use proteus_transport_alpha::metrics::ServerMetrics;
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auto_deny_engages_after_probe_anomaly_burst() {
    let cover_addr = spawn_drain_cover().await;

    // Threshold = 3 → 3rd probe fires the detector + populates
    // auto-deny. TTL = 5 minutes (production-realistic; the test
    // doesn't wait long enough for expiry).
    let detector = Arc::new(ProbeAnomalyDetector::new(Duration::from_secs(30), 3, 1024));
    let auto_deny = Arc::new(AutoDenyList::new(Duration::from_secs(300), 1024));
    let metrics = Arc::new(ServerMetrics::default());
    let server_keys = ServerKeys::generate();
    let ctx = Arc::new(
        ServerCtx::new(server_keys)
            .with_cover(cover_addr.to_string())
            .with_probe_anomaly_detector(Arc::clone(&detector))
            .with_auto_deny_list(Arc::clone(&auto_deny))
            .with_metrics(Arc::clone(&metrics)),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let server_ctx = Arc::clone(&ctx);
    let server_task = tokio::spawn(server::serve(listener, server_ctx, |_session| async {}));

    // Pre-burst sanity: the auto-deny list should be empty AND the
    // firewall_denied counter should be 0.
    assert_eq!(auto_deny.tracked(), 0);
    assert_eq!(
        metrics
            .firewall_denied
            .load(std::sync::atomic::Ordering::Relaxed),
        0,
    );

    // Burst: 4 probes from the same loopback /24. The 3rd fires
    // the detector → inserts 127.0.0.0/24 into auto-deny. The 4th
    // is the recovery probe (probe-anomaly fire-once-per-burst
    // semantics) AND now lands on the auto-denied path.
    for _ in 0..4 {
        probe_once(proxy_addr).await;
    }

    // Give the spawned cover-forward tasks a beat to update state.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while metrics
        .probe_anomalies_fired
        .load(std::sync::atomic::Ordering::Relaxed)
        == 0
        && std::time::Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Settle.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Anomaly fired exactly once.
    assert_eq!(
        metrics
            .probe_anomalies_fired
            .load(std::sync::atomic::Ordering::Relaxed),
        1,
    );
    // Auto-deny now contains the loopback /24.
    assert!(
        auto_deny.tracked() >= 1,
        "auto-deny ring should have ≥1 entry"
    );
    assert!(auto_deny.inserted_total() >= 1);

    // Pre-existing firewall_denied count (counted from the 4th
    // probe in the burst — that one hit auto-deny on the way in).
    let pre_count = metrics
        .firewall_denied
        .load(std::sync::atomic::Ordering::Relaxed);

    // 3 follow-up probes — every one should short-circuit at
    // auto-deny and bump firewall_denied. They land on the cover
    // path so they still complete TCP-wise; we just verify the
    // counter moved.
    for _ in 0..3 {
        probe_once(proxy_addr).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    let post_count = metrics
        .firewall_denied
        .load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        post_count >= pre_count + 3,
        "expected firewall_denied to advance by ≥3 from 3 follow-up probes; \
         pre={pre_count} post={post_count}"
    );

    server_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auto_deny_silent_when_not_wired() {
    // Same shape but no `with_auto_deny_list` — verifies the
    // detector still works AND the firewall_denied counter does
    // NOT advance (the cover-forward path still runs but goes
    // through the full admission flow without short-circuit).
    let cover_addr = spawn_drain_cover().await;

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

    for _ in 0..6 {
        probe_once(proxy_addr).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Anomaly fired.
    assert!(
        metrics
            .probe_anomalies_fired
            .load(std::sync::atomic::Ordering::Relaxed)
            >= 1
    );
    // But firewall_denied counter is still 0 — without auto-deny
    // wired, follow-up probes complete the admission flow normally
    // (and get cover-forwarded, which counts as cover_forwards
    // not firewall_denied).
    assert_eq!(
        metrics
            .firewall_denied
            .load(std::sync::atomic::Ordering::Relaxed),
        0,
        "firewall_denied should stay 0 when auto-deny is not wired",
    );

    server_task.abort();
}
