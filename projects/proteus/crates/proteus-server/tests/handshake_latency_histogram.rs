//! End-to-end test for handshake-latency histogram observation.
//!
//! Drives a real Proteus α handshake against an in-process
//! server, then asserts that the `handshake_duration_seconds`
//! histogram on `ServerMetrics` recorded the observation. This
//! is the contract operators dashboard on — `histogram_quantile`
//! over the bucket counters MUST return meaningful values once
//! handshakes have completed.

use std::sync::Arc;
use std::time::Duration;

use proteus_server::relay::{self, RelayConfig};
use proteus_transport_alpha::client::{self, ClientConfig};
use proteus_transport_alpha::metrics::ServerMetrics;
use proteus_transport_alpha::server::{self, ServerCtx, ServerKeys};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const STEP: Duration = Duration::from_secs(15);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn handshake_latency_histogram_records_a_real_handshake() {
    // Stand up a Proteus α server.
    let server_keys = ServerKeys::generate();
    let mlkem_pk_bytes = server_keys.mlkem_pk_bytes.clone();
    let pq_fingerprint = server_keys.pq_fingerprint;
    let server_x25519_pub = server_keys.x25519_pub;
    let server_metrics = Arc::new(ServerMetrics::default());
    let ctx = Arc::new(ServerCtx::new(server_keys).with_metrics(Arc::clone(&server_metrics)));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let server_ctx = Arc::clone(&ctx);

    let relay_cfg = RelayConfig {
        idle_timeout: Some(Duration::from_secs(5)),
        metrics: Some(Arc::clone(&server_metrics)),
        access_log: None,
        max_session_bytes: None,
        abuse_detector_byte_budget: None,
        abuse_fires: None,
        user_quarantine: None,
        quarantine_on_byte_budget: false,
        outbound_filter: None,
        dns_resolver_stats: None,
        pad_quantum: None,
    };
    let metrics_for_handler = Arc::clone(&server_metrics);
    let server_task = tokio::spawn(server::serve(listener, server_ctx, move |session| {
        let cfg = relay_cfg.clone();
        let m = Arc::clone(&metrics_for_handler);
        async move {
            // Mirror main.rs's observe_handshake_latency call.
            if let Some(d) = session.handshake_duration {
                m.handshake_duration_seconds.observe(d);
            }
            let _ = relay::handle_session(session, cfg).await;
        }
    }));

    // Snapshot the histogram BEFORE the handshake — should be empty.
    let count_before = server_metrics.handshake_duration_seconds.count();
    assert_eq!(count_before, 0, "fresh histogram must start at 0");

    // Drive a real client handshake.
    let mut rng = rand_core::OsRng;
    let client_id_sk = proteus_crypto::sig::generate(&mut rng);
    let client_cfg = ClientConfig {
        server_mlkem_pk_bytes: mlkem_pk_bytes,
        server_x25519_pub,
        server_pq_fingerprint: pq_fingerprint,
        client_id_sk,
        user_id: *b"latency1",
        pow_difficulty: 0,
        profile_hint: proteus_wire::ProfileHint::Alpha,
    };
    let stream = TcpStream::connect(proxy_addr).await.unwrap();
    let session = timeout(STEP, client::handshake_over_tcp(stream, &client_cfg))
        .await
        .expect("connect timed out")
        .expect("handshake ok");

    // Give the server-side on_session closure a moment to fire
    // its observe_handshake_latency call.
    for _ in 0..50 {
        if server_metrics.handshake_duration_seconds.count() > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let count_after = server_metrics.handshake_duration_seconds.count();
    assert_eq!(
        count_after, 1,
        "histogram must record exactly 1 observation; got {count_after}"
    );

    // Sum should be positive (some non-zero handshake time).
    let sum = server_metrics.handshake_duration_seconds.sum_seconds();
    assert!(sum > 0.0, "histogram sum must be > 0; got {sum}");
    // And it should be well under 5 seconds (loopback is fast).
    assert!(sum < 5.0, "loopback handshake took >5s? sum={sum}");

    // Verify the per-bucket counts are coherent: the highest
    // bucket should contain the observation, the +Inf bucket
    // should equal _count.
    let snap = server_metrics.handshake_duration_seconds.snapshot();
    let inf_count = snap.last().unwrap().1;
    assert_eq!(inf_count, 1);

    // Render the Prometheus block and verify the canonical
    // shape: HELP + TYPE + bucket lines + _sum + _count.
    let prom = server_metrics.prometheus();
    assert!(
        prom.contains("# TYPE proteus_handshake_duration_seconds histogram"),
        "missing histogram TYPE: {prom}"
    );
    assert!(
        prom.contains("proteus_handshake_duration_seconds_count 1"),
        "missing _count: {prom}"
    );

    drop(session);
    server_task.abort();
}
