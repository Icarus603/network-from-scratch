//! End-to-end /metrics exposition test.
//!
//! Every metric we *advertise* in the deployment docs must actually
//! appear in the exposition text. This test bumps every counter (and
//! flips every gauge) then verifies each line is present.
//!
//! Catches the class of bug where adding a new counter field to
//! `ServerMetrics` is not paired with a new entry in
//! `ServerMetrics::prometheus()`. Such a desync would silently
//! "lose" the new metric without anyone noticing until production
//! alerting fires on a counter that's wired but never emitted.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use proteus_transport_alpha::metrics::{ServerMetrics, SessionMetricsSnapshot};
use proteus_transport_alpha::metrics_http;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const STEP: Duration = Duration::from_secs(5);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_advertised_counter_is_in_exposition() {
    let metrics = Arc::new(ServerMetrics::default());

    // Touch every field. Use distinct prime-ish numbers so a swapped
    // field-to-format-string mapping would surface as a wrong value.
    metrics.sessions_accepted.fetch_add(101, Ordering::Relaxed);
    metrics
        .handshakes_succeeded
        .fetch_add(103, Ordering::Relaxed);
    metrics.handshakes_failed.fetch_add(107, Ordering::Relaxed);
    metrics.handshake_timeouts.fetch_add(109, Ordering::Relaxed);
    metrics.rate_limited.fetch_add(113, Ordering::Relaxed);
    metrics
        .conn_limit_rejected
        .fetch_add(127, Ordering::Relaxed);
    metrics.firewall_denied.fetch_add(131, Ordering::Relaxed);
    metrics
        .handshake_budget_rejected
        .fetch_add(167, Ordering::Relaxed);
    metrics.user_rate_rejected.fetch_add(173, Ordering::Relaxed);
    metrics.cover_forwards.fetch_add(137, Ordering::Relaxed);
    metrics.total_tx_bytes.fetch_add(139, Ordering::Relaxed);
    metrics.total_rx_bytes.fetch_add(149, Ordering::Relaxed);
    metrics.total_aead_drops.fetch_add(151, Ordering::Relaxed);
    metrics.total_ratchets.fetch_add(157, Ordering::Relaxed);
    metrics
        .session_idle_reaped
        .fetch_add(163, Ordering::Relaxed);
    metrics
        .session_byte_budget_exhausted
        .fetch_add(179, Ordering::Relaxed);
    metrics
        .abuse_alerts_byte_budget
        .fetch_add(191, Ordering::Relaxed);
    metrics
        .abuse_alerts_rate_limit
        .fetch_add(193, Ordering::Relaxed);
    metrics.in_flight_sessions.fetch_add(7, Ordering::Relaxed);
    metrics.alive.store(true, Ordering::Relaxed);
    metrics.ready.store(true, Ordering::Relaxed);

    // Also exercise merge_session so the totals reflect a session.
    metrics.merge_session(&SessionMetricsSnapshot {
        tx_bytes: 1,
        rx_bytes: 2,
        ..SessionMetricsSnapshot::default()
    });

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(metrics_http::serve_on_listener(
        listener,
        Arc::clone(&metrics),
    ));
    tokio::task::yield_now().await;

    // Scrape /metrics.
    let mut sock = timeout(STEP, TcpStream::connect(addr))
        .await
        .unwrap()
        .unwrap();
    sock.write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    sock.read_to_end(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf);

    // Every metric must appear with both HELP and value lines.
    let must_have: &[(&str, u64)] = &[
        ("proteus_sessions_accepted_total", 101),
        ("proteus_handshakes_succeeded_total", 103),
        ("proteus_handshakes_failed_total", 107),
        ("proteus_handshake_timeouts_total", 109),
        ("proteus_rate_limited_total", 113),
        ("proteus_conn_limit_rejected_total", 127),
        ("proteus_firewall_denied_total", 131),
        ("proteus_handshake_budget_rejected_total", 167),
        ("proteus_user_rate_rejected_total", 173),
        ("proteus_cover_forwards_total", 137),
        // total_tx/rx_bytes get +1, +2 from merge_session above.
        ("proteus_tx_bytes_total", 140),
        ("proteus_rx_bytes_total", 151),
        ("proteus_aead_drops_total", 151),
        ("proteus_ratchets_total", 157),
        ("proteus_session_idle_reaped_total", 163),
        ("proteus_session_byte_budget_exhausted_total", 179),
        ("proteus_abuse_alerts_byte_budget_total", 191),
        ("proteus_abuse_alerts_rate_limit_total", 193),
        ("proteus_in_flight_sessions", 7),
        ("proteus_up", 1),
        ("proteus_ready", 1),
    ];

    for (name, expected) in must_have {
        let help = format!("# HELP {name} ");
        let type_ = format!("# TYPE {name} ");
        let value = format!("{name} {expected}");
        assert!(
            response.contains(&help),
            "missing HELP line for {name}; full response:\n{response}"
        );
        assert!(
            response.contains(&type_),
            "missing TYPE line for {name}; full response:\n{response}"
        );
        assert!(
            response.contains(&value),
            "missing or wrong value line for {name} (expected {expected}); full response:\n{response}"
        );
    }

    task.abort();
}
