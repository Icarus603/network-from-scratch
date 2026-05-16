//! Minimal HTTP endpoints for Prometheus scrape + container probes.
//!
//! Deliberately hand-rolled (no external HTTP framework) — three
//! orthogonal single-purpose endpoints:
//!
//! - `GET /metrics`  → Prometheus 0.0.4 text exposition.
//! - `GET /healthz`  → 200 if `metrics.alive`, 503 otherwise.
//!   Container/orchestrator **liveness** probe — a 503 here means the
//!   runtime should restart us.
//! - `GET /readyz`   → 200 if `metrics.ready`, 503 otherwise.
//!   Load-balancer **readiness** probe — a 503 here means stop sending
//!   new traffic but don't kill the process. We deliberately flip this
//!   to `false` during graceful drain so the LB drains us before
//!   SIGTERM finishes.
//!
//! Body of each probe is a single short status line for human
//! debugging via `curl`.
//!
//! Reference: [Prometheus exposition formats](https://prometheus.io/docs/instrumenting/exposition_formats/),
//! Kubernetes [probe HTTP semantics](https://kubernetes.io/docs/concepts/configuration/liveness-readiness-startup-probes/).
//!
//! Usage from the server binary:
//! ```ignore
//! let metrics = Arc::new(ServerMetrics::default());
//! tokio::spawn(metrics_http::serve("127.0.0.1:9090", Arc::clone(&metrics)));
//! ```
//!
//! Bind only to a private interface; the endpoint has no
//! authentication.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{info, warn};

use crate::metrics::ServerMetrics;

/// Spawn an HTTP listener that serves `/metrics`, `/healthz`, `/readyz`
/// from `metrics`. Returns only on listener error (which under normal
/// operation never happens — the task is meant to run for the lifetime
/// of the server).
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
    let (status_line, content_type, body) = render(head, &metrics);
    let response = format!(
        "{status_line}\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\r\n\
         {body}",
        body.len()
    );
    if let Err(e) = stream.write_all(response.as_bytes()).await {
        warn!(error = %e, "metrics write failed");
    }
    let _ = stream.shutdown().await;
}

/// Match a request line against an exact path, accounting for both
/// `GET /foo ` (trailing space before HTTP version) and
/// `GET /foo?...` (query string). Rejects substring paths like
/// `/foozleak`.
fn matches_path(request_head: &str, path: &str) -> bool {
    let with_space = format!("GET {path} ");
    let with_query = format!("GET {path}?");
    request_head.starts_with(&with_space) || request_head.starts_with(&with_query)
}

/// Pure routing: given the request head and the metrics, return
/// `(status_line, content_type, body)`. Public so it can be unit-tested
/// without spinning up a TCP listener.
#[must_use]
pub fn render(request_head: &str, metrics: &ServerMetrics) -> (&'static str, &'static str, String) {
    if matches_path(request_head, "/metrics") {
        (
            "HTTP/1.1 200 OK\r\n",
            "text/plain; version=0.0.4",
            metrics.prometheus(),
        )
    } else if matches_path(request_head, "/healthz") {
        if metrics.alive.load(Ordering::Relaxed) {
            ("HTTP/1.1 200 OK\r\n", "text/plain", "alive\n".to_string())
        } else {
            (
                "HTTP/1.1 503 Service Unavailable\r\n",
                "text/plain",
                "dead\n".to_string(),
            )
        }
    } else if matches_path(request_head, "/readyz") {
        if metrics.ready.load(Ordering::Relaxed) {
            ("HTTP/1.1 200 OK\r\n", "text/plain", "ready\n".to_string())
        } else {
            (
                "HTTP/1.1 503 Service Unavailable\r\n",
                "text/plain",
                "draining\n".to_string(),
            )
        }
    } else {
        (
            "HTTP/1.1 404 Not Found\r\n",
            "text/plain",
            "not found\n".to_string(),
        )
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
        let (status, ctype, body) = render("GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n", &m);
        assert!(status.starts_with("HTTP/1.1 200"));
        assert!(ctype.starts_with("text/plain; version=0.0.4"));
        assert!(body.contains("proteus_sessions_accepted_total 7"));
    }

    #[test]
    fn render_200_on_get_metrics_with_query_string() {
        let m = ServerMetrics::default();
        let (status, _ctype, body) = render("GET /metrics?debug=1 HTTP/1.1\r\n\r\n", &m);
        assert!(status.starts_with("HTTP/1.1 200"));
        assert!(body.contains("# HELP proteus_sessions_accepted_total"));
    }

    #[test]
    fn render_404_on_root() {
        let m = ServerMetrics::default();
        let (status, _ctype, body) = render("GET / HTTP/1.1\r\n\r\n", &m);
        assert_eq!(status, "HTTP/1.1 404 Not Found\r\n");
        assert_eq!(body, "not found\n");
    }

    #[test]
    fn render_404_on_post() {
        let m = ServerMetrics::default();
        let (status, _ctype, _body) = render("POST /metrics HTTP/1.1\r\n\r\n", &m);
        assert!(status.starts_with("HTTP/1.1 404"));
    }

    #[test]
    fn render_404_on_metrics_substring_path() {
        let m = ServerMetrics::default();
        // /metricsleak should NOT match /metrics — the trailing space
        // / query-string check is what enforces this.
        let (status, _ctype, _body) = render("GET /metricsleak HTTP/1.1\r\n\r\n", &m);
        assert!(status.starts_with("HTTP/1.1 404"));
    }

    #[test]
    fn healthz_503_when_not_alive() {
        let m = ServerMetrics::default();
        // Default: alive=false.
        let (status, ctype, body) = render("GET /healthz HTTP/1.1\r\n\r\n", &m);
        assert_eq!(status, "HTTP/1.1 503 Service Unavailable\r\n");
        assert_eq!(ctype, "text/plain");
        assert_eq!(body, "dead\n");
    }

    #[test]
    fn healthz_200_when_alive() {
        let m = ServerMetrics::default();
        m.alive.store(true, Ordering::Relaxed);
        let (status, _ctype, body) = render("GET /healthz HTTP/1.1\r\n\r\n", &m);
        assert!(status.starts_with("HTTP/1.1 200"));
        assert_eq!(body, "alive\n");
    }

    #[test]
    fn readyz_503_when_not_ready() {
        let m = ServerMetrics::default();
        m.alive.store(true, Ordering::Relaxed);
        // Default: ready=false (still warming up or draining).
        let (status, _ctype, body) = render("GET /readyz HTTP/1.1\r\n\r\n", &m);
        assert_eq!(status, "HTTP/1.1 503 Service Unavailable\r\n");
        assert_eq!(body, "draining\n");
    }

    #[test]
    fn readyz_200_when_ready() {
        let m = ServerMetrics::default();
        m.ready.store(true, Ordering::Relaxed);
        let (status, _ctype, body) = render("GET /readyz HTTP/1.1\r\n\r\n", &m);
        assert!(status.starts_with("HTTP/1.1 200"));
        assert_eq!(body, "ready\n");
    }

    #[test]
    fn readyz_with_query_string_also_matches() {
        let m = ServerMetrics::default();
        m.ready.store(true, Ordering::Relaxed);
        let (status, _ctype, _body) = render("GET /readyz?source=lb HTTP/1.1\r\n\r\n", &m);
        assert!(status.starts_with("HTTP/1.1 200"));
    }

    #[test]
    fn healthz_substring_rejected() {
        let m = ServerMetrics::default();
        m.alive.store(true, Ordering::Relaxed);
        // /healthznow shouldn't match /healthz.
        let (status, _ctype, _body) = render("GET /healthznow HTTP/1.1\r\n\r\n", &m);
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

    /// End-to-end: a fresh server (alive=false, ready=false) should
    /// return 503 on both /healthz and /readyz; once flipped, 200.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn end_to_end_probes_flip_status() {
        let metrics = Arc::new(ServerMetrics::default());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_metrics = Arc::clone(&metrics);
        let server_task = tokio::spawn(serve_on_listener(listener, server_metrics));
        tokio::task::yield_now().await;

        async fn fetch(addr: std::net::SocketAddr, path: &str) -> String {
            let mut sock = timeout(Duration::from_secs(5), TcpStream::connect(addr))
                .await
                .expect("connect timeout")
                .expect("connect ok");
            sock.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
                .await
                .unwrap();
            let mut buf = Vec::new();
            sock.read_to_end(&mut buf).await.unwrap();
            String::from_utf8_lossy(&buf).to_string()
        }

        let r = fetch(addr, "/healthz").await;
        assert!(r.starts_with("HTTP/1.1 503"), "expected 503, got: {r}");

        metrics.alive.store(true, Ordering::Relaxed);
        let r = fetch(addr, "/healthz").await;
        assert!(r.starts_with("HTTP/1.1 200 OK"), "expected 200, got: {r}");

        let r = fetch(addr, "/readyz").await;
        assert!(r.starts_with("HTTP/1.1 503"), "expected 503, got: {r}");

        metrics.ready.store(true, Ordering::Relaxed);
        let r = fetch(addr, "/readyz").await;
        assert!(r.starts_with("HTTP/1.1 200 OK"), "expected 200, got: {r}");

        server_task.abort();
    }
}
