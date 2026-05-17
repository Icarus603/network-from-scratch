//! End-to-end integration test for `proteus-server admin
//! alerts-check`.
//!
//! Stands up a tiny in-process HTTP server that serves a fixed
//! `/metrics` body, then drives the CLI's evaluation path
//! (via the public `admin_alerts_check::cli_run`) and asserts
//! the rendered output + exit code for synthetic scenarios:
//!
//!   * all-green (proteus_up=1, no panics, no expired cert)
//!   * cert-expired (CRIT path, exit code 1)
//!   * panic counter non-zero (CRIT)
//!   * dns-resolver timeouts observed (WARN)
//!
//! The HTTP stub is a single-shot accept-and-write — same
//! pattern as the existing admin_status_cli.rs harness.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use proteus_server::admin_alerts_check::{evaluate, CheckSeverity};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn serve_metrics_once(body: String) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let body = Arc::new(body);
    tokio::spawn(async move {
        // Accept up to a few requests so the same stub serves
        // the alerts-check + any retry the caller does.
        for _ in 0..4 {
            let (mut sock, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => return,
            };
            // Drain the request head.
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.shutdown().await;
        }
    });
    addr
}

fn evaluate_with_synthetic_body(body: &str) -> proteus_server::admin_alerts_check::Report {
    evaluate(body)
}

#[tokio::test]
async fn all_green_body_yields_exit_zero_and_only_pass_checks() {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let body = format!(
        "proteus_up 1\n\
         proteus_panics_total 0\n\
         proteus_previous_run_unclean 0\n\
         proteus_tls_cert_not_after_unix_seconds {}\n\
         proteus_tls_cert_watcher_auto_reload_failed_total 0\n\
         proteus_access_log_writer_alive 1\n\
         proteus_dns_lookups_total{{outcome=\"ok\"}} 100\n\
         proteus_dns_lookups_total{{outcome=\"timeout\"}} 0\n",
        now + 90 * 86_400
    );
    let r = evaluate_with_synthetic_body(&body);
    assert_eq!(r.exit_code(), 0);
    assert_eq!(r.counts().2, 0, "no CRIT expected; got {:?}", r.checks);
    // We expect at least ProteusServerUnhealthy + ProteusPanic +
    // ProteusUncleanShutdown + ProteusTlsCertExpiringSoon +
    // ProteusTlsAutoReloadFailing + ProteusAccessLogWriterDead +
    // ProteusDnsResolverWedged → all PASS.
    assert!(
        r.checks.len() >= 6,
        "expected ≥6 checks; got {:?}",
        r.checks
    );
}

#[tokio::test]
async fn expired_cert_yields_exit_one_with_crit_severity() {
    let body =
        "proteus_up 1\nproteus_panics_total 0\nproteus_tls_cert_not_after_unix_seconds 1000000000\n";
    let r = evaluate_with_synthetic_body(body);
    assert_eq!(r.exit_code(), 1);
    let c = r
        .checks
        .iter()
        .find(|c| c.rule_name == "ProteusTlsCertExpired")
        .expect("ProteusTlsCertExpired must fire");
    assert_eq!(c.severity, CheckSeverity::Crit);
    assert!(c.message.contains("EXPIRED"));
}

#[tokio::test]
async fn nonzero_panic_counter_yields_crit() {
    let body = "proteus_up 1\nproteus_panics_total 7\n";
    let r = evaluate_with_synthetic_body(body);
    assert_eq!(r.exit_code(), 1);
    let c = r
        .checks
        .iter()
        .find(|c| c.rule_name == "ProteusPanic")
        .unwrap();
    assert_eq!(c.severity, CheckSeverity::Crit);
    assert!(c.message.contains("7"));
}

#[tokio::test]
async fn dns_timeout_yields_warn_not_crit() {
    let body = "proteus_up 1\nproteus_panics_total 0\nproteus_dns_lookups_total{outcome=\"ok\"} 50\nproteus_dns_lookups_total{outcome=\"timeout\"} 3\n";
    let r = evaluate_with_synthetic_body(body);
    // WARN does NOT fail exit code.
    assert_eq!(r.exit_code(), 0);
    let c = r
        .checks
        .iter()
        .find(|c| c.rule_name == "ProteusDnsResolverWedged")
        .unwrap();
    assert_eq!(c.severity, CheckSeverity::Warn);
}

#[tokio::test]
async fn end_to_end_cli_run_against_stub_metrics_server() {
    // Full CLI loop: stub serves `/metrics`, cli_run does the
    // HTTP GET + parse + evaluate + render. Exit code should
    // reflect the synthetic body's CRIT presence.
    let body = "proteus_up 0\nproteus_panics_total 0\n".to_string();
    let addr = serve_metrics_once(body).await;
    // Give the listener a moment.
    tokio::time::sleep(Duration::from_millis(20)).await;
    let url = format!("http://{addr}/metrics");
    // cli_run is sync; run on a blocking thread so we don't
    // block the runtime if it does any sync I/O.
    let exit = tokio::task::spawn_blocking(move || {
        proteus_server::admin_alerts_check::cli_run(&url, None, Duration::from_secs(2), "json")
    })
    .await
    .unwrap()
    .expect("cli_run should succeed (the stub answers 200)");
    assert_eq!(exit, 1, "proteus_up=0 must yield exit 1");
}

#[tokio::test]
async fn end_to_end_cli_run_returns_zero_on_clean_body() {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let body = format!(
        "proteus_up 1\nproteus_panics_total 0\nproteus_tls_cert_not_after_unix_seconds {}\n",
        now + 90 * 86_400
    );
    let addr = serve_metrics_once(body).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    let url = format!("http://{addr}/metrics");
    let exit = tokio::task::spawn_blocking(move || {
        proteus_server::admin_alerts_check::cli_run(&url, None, Duration::from_secs(2), "text")
    })
    .await
    .unwrap()
    .expect("cli_run should succeed");
    assert_eq!(exit, 0);
}
