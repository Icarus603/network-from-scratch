//! End-to-end test for β-side probe-anomaly detector wiring.
//!
//! Mirrors α's `probe_anomaly_e2e.rs` but exercises the QUIC carrier.
//! β has no raw cover-forward path (the QUIC handshake completed
//! before we discover the auth failure — there's no plaintext TCP
//! byte stream below it to splice), so β-side rejection is `conn.
//! close(0, b"")` instead of a cover splice. Without this commit's
//! `record_probe_anomaly` wiring, a prober that exclusively probes
//! the β carrier from one /24 would never trigger the anomaly
//! counter even though α probes from the same /24 would — that
//! asymmetry was the threat that motivated this test.
//!
//! ## What this pins
//!
//! With the detector installed AND a real β server running, N+
//! failed-handshake probes from the same loopback src cause the
//! `proteus_probe_anomalies_fired_total` Prometheus counter to
//! increment EXACTLY ONCE for the burst (fire-once semantics).
//! Below threshold → counter stays at 0.
//!
//! The failure we use is the simplest: dial via QUIC with the
//! correct ALPN, then NEVER open the bidi stream → the β server
//! hits the bi-stream-timeout branch. That branch was one of the
//! six β failure-close-sites this commit wires.

use std::sync::Arc;
use std::time::Duration;

use proteus_transport_alpha::metrics::ServerMetrics;
use proteus_transport_alpha::probe_anomaly::ProbeAnomalyDetector;
use proteus_transport_alpha::server::{ServerCtx, ServerKeys};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::time::timeout;

const STEP: Duration = Duration::from_secs(15);

/// Drive one β-side probe: complete the QUIC handshake but NEVER
/// open a bidi stream. The server hits its bi-stream-timeout branch
/// after `handshake_deadline` and closes — which (with this
/// commit's wiring) fires the probe-anomaly recording.
async fn probe_via_quic_no_bi_stream(
    server_addr: std::net::SocketAddr,
    cert_der: CertificateDer<'static>,
) {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let mut client_cfg =
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(roots)
            .with_no_client_auth();
    client_cfg.alpn_protocols = vec![proteus_transport_beta::ALPN.to_vec()];
    let crypto = Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(client_cfg).unwrap());
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(crypto));

    let Ok(Ok(conn)) = timeout(STEP, endpoint.connect(server_addr, "localhost").unwrap()).await
    else {
        return;
    };
    // Deliberately do NOT open a bidi stream. Wait for the server's
    // CONNECTION_CLOSE to land — confirms the server's
    // bi-stream-timeout branch ran (and thus the detector recorded).
    let _ = timeout(Duration::from_secs(3), conn.closed()).await;
    drop(endpoint);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn beta_probe_anomaly_fires_once_per_burst_from_same_src() {
    let ck = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(ck.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));

    // Aggressive 300 ms handshake deadline so the test stays fast —
    // each probe takes one deadline to fire the bi-stream-timeout
    // branch. Threshold = 3 events in 30 s window.
    let detector = Arc::new(ProbeAnomalyDetector::new(Duration::from_secs(30), 3, 1024));
    let metrics = Arc::new(ServerMetrics::default());
    let server_keys = ServerKeys::generate();
    let ctx = Arc::new(
        ServerCtx::new(server_keys)
            .with_probe_anomaly_detector(Arc::clone(&detector))
            .with_metrics(Arc::clone(&metrics))
            .with_handshake_deadline(Duration::from_millis(300)),
    );

    let bind: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let endpoint =
        proteus_transport_beta::server::make_endpoint(bind, vec![cert_der.clone()], key_der)
            .expect("make_endpoint");
    let server_local = endpoint.local_addr().expect("local_addr");
    let server_ctx = Arc::clone(&ctx);
    let server_task = tokio::spawn(async move {
        let _ =
            proteus_transport_beta::server::serve(endpoint, server_ctx, |_session| async {}).await;
    });

    // 5 probes from this single loopback src — same /24 = 127.0.0.0/24,
    // threshold = 3 → expect exactly 1 anomaly fire.
    for _ in 0..5 {
        probe_via_quic_no_bi_stream(server_local, cert_der.clone()).await;
    }

    // Give the server's spawned tasks a beat to write the metric.
    // Poll up to 5 s — fast on a healthy box, robust under parallel
    // test contention.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while metrics
        .probe_anomalies_fired
        .load(std::sync::atomic::Ordering::Relaxed)
        == 0
        && std::time::Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Grace period to detect any erroneous extra fires.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let fired = metrics
        .probe_anomalies_fired
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        fired, 1,
        "β: expected exactly 1 anomaly fire across 5 bi-stream-timeout probes from same /24 \
         (fire-once-per-burst at threshold = 3); got {fired}"
    );

    server_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn beta_probe_anomaly_silent_when_detector_unset() {
    let ck = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(ck.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));

    let metrics = Arc::new(ServerMetrics::default());
    let server_keys = ServerKeys::generate();
    // NO `with_probe_anomaly_detector(...)` — detector unset.
    let ctx = Arc::new(
        ServerCtx::new(server_keys)
            .with_metrics(Arc::clone(&metrics))
            .with_handshake_deadline(Duration::from_millis(300)),
    );

    let bind: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let endpoint =
        proteus_transport_beta::server::make_endpoint(bind, vec![cert_der.clone()], key_der)
            .expect("make_endpoint");
    let server_local = endpoint.local_addr().expect("local_addr");
    let server_ctx = Arc::clone(&ctx);
    let server_task = tokio::spawn(async move {
        let _ =
            proteus_transport_beta::server::serve(endpoint, server_ctx, |_session| async {}).await;
    });

    // 6 probes — well above any reasonable threshold.
    for _ in 0..6 {
        probe_via_quic_no_bi_stream(server_local, cert_der.clone()).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    let fired = metrics
        .probe_anomalies_fired
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        fired, 0,
        "β: detector unset — counter MUST stay at 0; got {fired}"
    );

    // The bi-stream-timeout counter SHOULD have incremented — proves
    // the failure path itself ran (we just didn't surface it as an
    // anomaly because the detector wasn't installed).
    let timeouts = metrics
        .handshake_timeouts
        .load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        timeouts >= 1,
        "β: handshake_timeouts counter should have incremented; got {timeouts}"
    );

    server_task.abort();
}
