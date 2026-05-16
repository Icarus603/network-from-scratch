//! Minimal HTTP `/metrics` endpoint for Prometheus scrape.
//!
//! Deliberately hand-rolled (no external HTTP framework) — this is
//! a single-purpose endpoint that serves text/plain exposition format
//! per [Prometheus 0.0.4](https://prometheus.io/docs/instrumenting/exposition_formats/).
//!
//! Usage from the server binary:
//! ```ignore
//! let metrics = Arc::new(ServerMetrics::default());
//! tokio::spawn(metrics_http::serve("127.0.0.1:9090", Arc::clone(&metrics)));
//! ```
//!
//! Bind only to a private interface; the endpoint has no
//! authentication.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{info, warn};

use crate::metrics::ServerMetrics;

/// Spawn an HTTP listener that serves `GET /metrics` from `metrics`.
/// Returns when the listener errors (which under normal operation
/// never happens — the task is meant to run for the lifetime of the
/// server).
pub async fn serve(addr: &str, metrics: Arc<ServerMetrics>) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!(addr = %listener.local_addr()?, "metrics endpoint bound");
    loop {
        let (stream, _peer) = listener.accept().await?;
        let metrics = Arc::clone(&metrics);
        tokio::spawn(handle_connection(stream, metrics));
    }
}

/// Same as [`serve`] but the caller supplies an already-bound listener
/// (e.g. so a test can pick `127.0.0.1:0` and read the local addr).
pub async fn serve_on_listener(
    listener: TcpListener,
    metrics: Arc<ServerMetrics>,
) -> std::io::Result<()> {
    loop {
        let (stream, _peer) = listener.accept().await?;
        let metrics = Arc::clone(&metrics);
        tokio::spawn(handle_connection(stream, metrics));
    }
}

async fn handle_connection(mut stream: tokio::net::TcpStream, metrics: Arc<ServerMetrics>) {
    let mut req = [0u8; 2048];
    let _ = match stream.read(&mut req).await {
        Ok(n) => n,
        Err(_) => return,
    };
    let head = std::str::from_utf8(&req).unwrap_or("");
    let (status_line, body) = render(head, &metrics);
    let response = format!(
        "{status_line}\
         Content-Type: text/plain; version=0.0.4\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n\
         {body}",
        body.len()
    );
    if let Err(e) = stream.write_all(response.as_bytes()).await {
        warn!(error = %e, "metrics write failed");
    }
    let _ = stream.shutdown().await;
}

/// Pure routing: given the request head and the metrics, return
/// `(status_line, body)`. Public so it can be unit-tested without
/// spinning up a TCP listener.
#[must_use]
pub fn render(request_head: &str, metrics: &ServerMetrics) -> (&'static str, String) {
    if request_head.starts_with("GET /metrics ") || request_head.starts_with("GET /metrics?") {
        ("HTTP/1.1 200 OK\r\n", metrics.prometheus())
    } else {
        ("HTTP/1.1 404 Not Found\r\n", "not found\n".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;
    use tokio::net::TcpStream;
    use tokio::time::{timeout, Duration};

    #[test]
    fn render_200_on_get_metrics_with_trailing_space() {
        let m = ServerMetrics::default();
        m.sessions_accepted.fetch_add(7, Ordering::Relaxed);
        let (status, body) = render("GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n", &m);
        assert!(status.starts_with("HTTP/1.1 200"));
        assert!(body.contains("proteus_sessions_accepted_total 7"));
    }

    #[test]
    fn render_200_on_get_metrics_with_query_string() {
        let m = ServerMetrics::default();
        let (status, body) = render("GET /metrics?debug=1 HTTP/1.1\r\n\r\n", &m);
        assert!(status.starts_with("HTTP/1.1 200"));
        assert!(body.contains("# HELP proteus_sessions_accepted_total"));
    }

    #[test]
    fn render_404_on_root() {
        let m = ServerMetrics::default();
        let (status, body) = render("GET / HTTP/1.1\r\n\r\n", &m);
        assert_eq!(status, "HTTP/1.1 404 Not Found\r\n");
        assert_eq!(body, "not found\n");
    }

    #[test]
    fn render_404_on_post() {
        let m = ServerMetrics::default();
        let (status, _body) = render("POST /metrics HTTP/1.1\r\n\r\n", &m);
        assert!(status.starts_with("HTTP/1.1 404"));
    }

    #[test]
    fn render_404_on_metrics_substring_path() {
        let m = ServerMetrics::default();
        // /metricsleak should NOT match /metrics — the trailing space
        // / query-string check is what enforces this.
        let (status, _body) = render("GET /metricsleak HTTP/1.1\r\n\r\n", &m);
        assert!(status.starts_with("HTTP/1.1 404"));
    }

    /// End-to-end: bind a listener on a free port, spawn the server,
    /// open a TCP client, send `GET /metrics`, verify the response
    /// contains the Prometheus exposition.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn end_to_end_scrape() {
        let metrics = Arc::new(ServerMetrics::default());
        metrics
            .handshakes_succeeded
            .fetch_add(42, Ordering::Relaxed);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_metrics = Arc::clone(&metrics);
        let server_task = tokio::spawn(serve_on_listener(listener, server_metrics));

        // Spin briefly so the accept loop is polled.
        tokio::task::yield_now().await;

        let mut sock = timeout(Duration::from_secs(5), TcpStream::connect(addr))
            .await
            .expect("connect timeout")
            .expect("connect ok");
        sock.write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        sock.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("Content-Type: text/plain"));
        assert!(response.contains("proteus_handshakes_succeeded_total 42"));

        server_task.abort();
    }
}
