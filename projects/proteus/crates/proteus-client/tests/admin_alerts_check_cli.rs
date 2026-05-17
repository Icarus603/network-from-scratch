//! End-to-end integration test for `proteus-client alerts-check`.
//! Stands up a tiny in-process HTTP server serving a fixed
//! `/metrics` body, then drives `cli_run` and asserts the exit
//! code matches the synthetic body's CRIT presence.
//!
//! Symmetric with `crates/proteus-server/tests/admin_alerts_check_cli.rs`.

use std::sync::Arc;
use std::time::Duration;

use proteus_client::admin_alerts_check::{cli_run, evaluate, CheckSeverity};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn serve_metrics_once(body: String) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let body = Arc::new(body);
    tokio::spawn(async move {
        for _ in 0..4 {
            let (mut sock, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => return,
            };
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

#[tokio::test]
async fn end_to_end_cli_run_returns_one_when_client_not_alive() {
    let body = "proteus_client_up 0\n".to_string();
    let addr = serve_metrics_once(body).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    let url = format!("http://{addr}/");
    let exit = cli_run(&url, Duration::from_secs(2), "json").await.unwrap();
    assert_eq!(exit, 1, "proteus_client_up=0 → exit 1");
}

#[tokio::test]
async fn end_to_end_cli_run_returns_zero_on_clean_body() {
    let body = "proteus_client_up 1\nproteus_client_dials_attempted_total 0\n".to_string();
    let addr = serve_metrics_once(body).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    let url = format!("http://{addr}/");
    let exit = cli_run(&url, Duration::from_secs(2), "text").await.unwrap();
    assert_eq!(exit, 0);
}

#[tokio::test]
async fn end_to_end_cli_run_returns_one_when_all_endpoints_suppressed() {
    let body = "proteus_client_up 1\nproteus_client_endpoint_suppressed{addr=\"a\"} 1\nproteus_client_endpoint_suppressed{addr=\"b\"} 1\n".to_string();
    let addr = serve_metrics_once(body).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    let url = format!("http://{addr}/");
    let exit = cli_run(&url, Duration::from_secs(2), "json").await.unwrap();
    assert_eq!(exit, 1);
}

#[tokio::test]
async fn evaluate_classifies_doh_leak_as_warn_not_crit() {
    let body =
        "proteus_client_up 1\nproteus_client_bootstrap_via_ip_literal_total 0\nproteus_client_bootstrap_via_system_resolver_total 3\n";
    let report = evaluate(body);
    assert_eq!(report.exit_code(), 0, "WARN must not flip exit-code to 1");
    let doh = report
        .checks
        .iter()
        .find(|c| c.rule_name == "ProteusClientBootstrapViaSystemResolver")
        .unwrap();
    assert_eq!(doh.severity, CheckSeverity::Warn);
}
