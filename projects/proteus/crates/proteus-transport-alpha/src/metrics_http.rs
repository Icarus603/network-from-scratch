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

use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::metrics::ServerMetrics;

/// Optional bearer-token gate for `/metrics`.
///
/// Stored in a [`Zeroizing<String>`] so the token is wiped from
/// memory on drop. Compared with [`subtle::ConstantTimeEq`] to avoid
/// timing oracles that could let an attacker bisect the token byte
/// by byte.
///
/// `/healthz` and `/readyz` are **never** gated — orchestrator probes
/// (kubelet, ECS health checks, GCP load balancers) don't carry
/// bearer tokens, and the bodies leak only "alive"/"dead"/"ready"/
/// "draining" anyway.
#[derive(Clone)]
pub struct MetricsAuth {
    token: Arc<Zeroizing<String>>,
}

impl MetricsAuth {
    /// Wrap a bearer token. The string content is zeroized on drop.
    /// Empty tokens are rejected — pass `None` to the serve functions
    /// instead.
    #[must_use]
    pub fn new(token: impl Into<String>) -> Option<Self> {
        let s = token.into();
        if s.is_empty() {
            return None;
        }
        Some(Self {
            token: Arc::new(Zeroizing::new(s)),
        })
    }

    /// Constant-time check that the `Authorization` header value
    /// (after stripping `Bearer ` prefix) matches the configured
    /// token. Returns `false` for any prefix mismatch, empty header,
    /// or token-length mismatch (the length mismatch is divulged
    /// either way, but knowing the length narrows search space by
    /// at most ~7 bits which is negligible for a 32-byte token).
    fn matches(&self, header_value: &str) -> bool {
        let presented = match header_value.strip_prefix("Bearer ") {
            Some(s) => s.trim_end_matches(['\r', '\n', ' ']),
            None => return false,
        };
        let expected = self.token.as_bytes();
        let got = presented.as_bytes();
        if expected.len() != got.len() {
            return false;
        }
        expected.ct_eq(got).into()
    }
}

impl std::fmt::Debug for MetricsAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetricsAuth")
            .field("token", &"<redacted>")
            .finish()
    }
}

/// Spawn an HTTP listener that serves `/metrics`, `/healthz`, `/readyz`
/// from `metrics`. Returns only on listener error (which under normal
/// operation never happens — the task is meant to run for the lifetime
/// of the server).
///
/// Equivalent to calling [`serve_with_auth`] with `auth = None`.
pub async fn serve(addr: &str, metrics: Arc<ServerMetrics>) -> std::io::Result<()> {
    serve_with_auth(addr, metrics, None).await
}

/// Like [`serve`] but optionally requires `Authorization: Bearer <token>`
/// on `/metrics` requests. `/healthz` and `/readyz` are never gated.
pub async fn serve_with_auth(
    addr: &str,
    metrics: Arc<ServerMetrics>,
    auth: Option<MetricsAuth>,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let auth_enabled = auth.is_some();
    info!(
        addr = %listener.local_addr()?,
        auth = auth_enabled,
        "metrics endpoint bound",
    );
    loop {
        let (stream, _peer) = listener.accept().await?;
        let metrics = Arc::clone(&metrics);
        let auth = auth.clone();
        tokio::spawn(handle_connection(stream, metrics, auth));
    }
}

/// Same as [`serve`] but the caller supplies an already-bound listener
/// (e.g. so a test can pick `127.0.0.1:0` and read the local addr).
pub async fn serve_on_listener(
    listener: TcpListener,
    metrics: Arc<ServerMetrics>,
) -> std::io::Result<()> {
    serve_on_listener_with_auth(listener, metrics, None).await
}

/// Like [`serve_on_listener`] with an optional bearer-token gate on
/// `/metrics`.
pub async fn serve_on_listener_with_auth(
    listener: TcpListener,
    metrics: Arc<ServerMetrics>,
    auth: Option<MetricsAuth>,
) -> std::io::Result<()> {
    loop {
        let (stream, _peer) = listener.accept().await?;
        let metrics = Arc::clone(&metrics);
        let auth = auth.clone();
        tokio::spawn(handle_connection(stream, metrics, auth));
    }
}

async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    metrics: Arc<ServerMetrics>,
    auth: Option<MetricsAuth>,
) {
    let mut req = [0u8; 2048];
    let _ = match stream.read(&mut req).await {
        Ok(n) => n,
        Err(_) => return,
    };
    let head = std::str::from_utf8(&req).unwrap_or("");
    let (status_line, content_type, body) = render(head, &metrics, auth.as_ref());
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

/// Extract the value of an `Authorization:` header from a raw HTTP
/// request head. Returns `None` if no such header exists. Case-
/// insensitive on the header name (HTTP/1.1 § 3.2 says field names
/// are case-insensitive).
fn extract_authorization(request_head: &str) -> Option<&str> {
    for line in request_head.split("\r\n") {
        let (name, value) = match line.split_once(':') {
            Some(kv) => kv,
            None => continue,
        };
        if name.eq_ignore_ascii_case("Authorization") {
            return Some(value.trim_start());
        }
    }
    None
}

/// Pure routing: given the request head and the metrics, return
/// `(status_line, content_type, body)`. Public so it can be unit-tested
/// without spinning up a TCP listener.
#[must_use]
pub fn render(
    request_head: &str,
    metrics: &ServerMetrics,
    auth: Option<&MetricsAuth>,
) -> (&'static str, &'static str, String) {
    if matches_path(request_head, "/metrics") {
        // Bearer-token gate when configured.
        if let Some(expected) = auth {
            let presented = extract_authorization(request_head);
            let ok = presented.is_some_and(|p| expected.matches(p));
            if !ok {
                return (
                    "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer realm=\"proteus-metrics\"\r\n",
                    "text/plain",
                    "unauthorized\n".to_string(),
                );
            }
        }
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
        let (status, ctype, body) = render("GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n", &m, None);
        assert!(status.starts_with("HTTP/1.1 200"));
        assert!(ctype.starts_with("text/plain; version=0.0.4"));
        assert!(body.contains("proteus_sessions_accepted_total 7"));
    }

    #[test]
    fn render_200_on_get_metrics_with_query_string() {
        let m = ServerMetrics::default();
        let (status, _ctype, body) = render("GET /metrics?debug=1 HTTP/1.1\r\n\r\n", &m, None);
        assert!(status.starts_with("HTTP/1.1 200"));
        assert!(body.contains("# HELP proteus_sessions_accepted_total"));
    }

    #[test]
    fn render_404_on_root() {
        let m = ServerMetrics::default();
        let (status, _ctype, body) = render("GET / HTTP/1.1\r\n\r\n", &m, None);
        assert_eq!(status, "HTTP/1.1 404 Not Found\r\n");
        assert_eq!(body, "not found\n");
    }

    #[test]
    fn render_404_on_post() {
        let m = ServerMetrics::default();
        let (status, _ctype, _body) = render("POST /metrics HTTP/1.1\r\n\r\n", &m, None);
        assert!(status.starts_with("HTTP/1.1 404"));
    }

    #[test]
    fn render_404_on_metrics_substring_path() {
        let m = ServerMetrics::default();
        // /metricsleak should NOT match /metrics — the trailing space
        // / query-string check is what enforces this.
        let (status, _ctype, _body) = render("GET /metricsleak HTTP/1.1\r\n\r\n", &m, None);
        assert!(status.starts_with("HTTP/1.1 404"));
    }

    #[test]
    fn healthz_503_when_not_alive() {
        let m = ServerMetrics::default();
        // Default: alive=false.
        let (status, ctype, body) = render("GET /healthz HTTP/1.1\r\n\r\n", &m, None);
        assert_eq!(status, "HTTP/1.1 503 Service Unavailable\r\n");
        assert_eq!(ctype, "text/plain");
        assert_eq!(body, "dead\n");
    }

    #[test]
    fn healthz_200_when_alive() {
        let m = ServerMetrics::default();
        m.alive.store(true, Ordering::Relaxed);
        let (status, _ctype, body) = render("GET /healthz HTTP/1.1\r\n\r\n", &m, None);
        assert!(status.starts_with("HTTP/1.1 200"));
        assert_eq!(body, "alive\n");
    }

    #[test]
    fn readyz_503_when_not_ready() {
        let m = ServerMetrics::default();
        m.alive.store(true, Ordering::Relaxed);
        // Default: ready=false (still warming up or draining).
        let (status, _ctype, body) = render("GET /readyz HTTP/1.1\r\n\r\n", &m, None);
        assert_eq!(status, "HTTP/1.1 503 Service Unavailable\r\n");
        assert_eq!(body, "draining\n");
    }

    #[test]
    fn readyz_200_when_ready() {
        let m = ServerMetrics::default();
        m.ready.store(true, Ordering::Relaxed);
        let (status, _ctype, body) = render("GET /readyz HTTP/1.1\r\n\r\n", &m, None);
        assert!(status.starts_with("HTTP/1.1 200"));
        assert_eq!(body, "ready\n");
    }

    #[test]
    fn readyz_with_query_string_also_matches() {
        let m = ServerMetrics::default();
        m.ready.store(true, Ordering::Relaxed);
        let (status, _ctype, _body) = render("GET /readyz?source=lb HTTP/1.1\r\n\r\n", &m, None);
        assert!(status.starts_with("HTTP/1.1 200"));
    }

    #[test]
    fn healthz_substring_rejected() {
        let m = ServerMetrics::default();
        m.alive.store(true, Ordering::Relaxed);
        // /healthznow shouldn't match /healthz.
        let (status, _ctype, _body) = render("GET /healthznow HTTP/1.1\r\n\r\n", &m, None);
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

    // ----- Bearer-token auth tests -----

    fn dummy_auth() -> MetricsAuth {
        MetricsAuth::new("s3cr3t-deadbeef-cafe-1234").unwrap()
    }

    #[test]
    fn metrics_auth_rejects_empty_token() {
        assert!(MetricsAuth::new("").is_none());
    }

    #[test]
    fn metrics_auth_matches_correct_token() {
        let a = dummy_auth();
        assert!(a.matches("Bearer s3cr3t-deadbeef-cafe-1234"));
    }

    #[test]
    fn metrics_auth_rejects_wrong_prefix() {
        let a = dummy_auth();
        assert!(!a.matches("Basic s3cr3t-deadbeef-cafe-1234"));
        assert!(!a.matches("Token s3cr3t-deadbeef-cafe-1234"));
        // Missing prefix.
        assert!(!a.matches("s3cr3t-deadbeef-cafe-1234"));
    }

    #[test]
    fn metrics_auth_rejects_wrong_token() {
        let a = dummy_auth();
        assert!(!a.matches("Bearer wrong-token-of-same-length-aa"));
        assert!(!a.matches("Bearer x"));
        assert!(!a.matches("Bearer "));
    }

    #[test]
    fn metrics_auth_strips_trailing_whitespace_and_crlf() {
        // HTTP header values can have trailing CR/LF when split off
        // mid-buffer. Accept them.
        let a = dummy_auth();
        assert!(a.matches("Bearer s3cr3t-deadbeef-cafe-1234\r\n"));
        assert!(a.matches("Bearer s3cr3t-deadbeef-cafe-1234 "));
    }

    #[test]
    fn extract_authorization_case_insensitive_header_name() {
        let head = "GET /metrics HTTP/1.1\r\nhost: x\r\nauthorization: Bearer foo\r\n\r\n";
        assert_eq!(extract_authorization(head), Some("Bearer foo"));
        let head = "GET /metrics HTTP/1.1\r\nAUTHORIZATION: Bearer foo\r\n\r\n";
        assert_eq!(extract_authorization(head), Some("Bearer foo"));
    }

    #[test]
    fn extract_authorization_missing_returns_none() {
        let head = "GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n";
        assert_eq!(extract_authorization(head), None);
    }

    #[test]
    fn render_401_when_auth_configured_and_no_header() {
        let m = ServerMetrics::default();
        let auth = dummy_auth();
        let (status, _ctype, body) = render("GET /metrics HTTP/1.1\r\n\r\n", &m, Some(&auth));
        assert!(status.starts_with("HTTP/1.1 401"));
        assert!(status.contains("WWW-Authenticate: Bearer"));
        assert_eq!(body, "unauthorized\n");
    }

    #[test]
    fn render_401_when_auth_configured_and_wrong_token() {
        let m = ServerMetrics::default();
        let auth = dummy_auth();
        let (status, _ctype, _body) = render(
            "GET /metrics HTTP/1.1\r\nAuthorization: Bearer nope\r\n\r\n",
            &m,
            Some(&auth),
        );
        assert!(status.starts_with("HTTP/1.1 401"));
    }

    #[test]
    fn render_200_when_auth_configured_and_correct_token() {
        let m = ServerMetrics::default();
        m.sessions_accepted.fetch_add(99, Ordering::Relaxed);
        let auth = dummy_auth();
        let (status, _ctype, body) = render(
            "GET /metrics HTTP/1.1\r\nAuthorization: Bearer s3cr3t-deadbeef-cafe-1234\r\n\r\n",
            &m,
            Some(&auth),
        );
        assert!(status.starts_with("HTTP/1.1 200"));
        assert!(body.contains("proteus_sessions_accepted_total 99"));
    }

    #[test]
    fn render_healthz_and_readyz_never_require_auth() {
        // /healthz + /readyz must respond without auth even when the
        // gate is configured — orchestrator probes don't carry tokens.
        let m = ServerMetrics::default();
        m.alive.store(true, Ordering::Relaxed);
        m.ready.store(true, Ordering::Relaxed);
        let auth = dummy_auth();
        let (s, _, _) = render("GET /healthz HTTP/1.1\r\n\r\n", &m, Some(&auth));
        assert!(s.starts_with("HTTP/1.1 200"));
        let (s, _, _) = render("GET /readyz HTTP/1.1\r\n\r\n", &m, Some(&auth));
        assert!(s.starts_with("HTTP/1.1 200"));
    }

    /// End-to-end: bind a listener, configure auth, verify that a
    /// scrape without `Authorization` gets 401, while one with the
    /// correct bearer gets 200 + exposition.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn end_to_end_auth_gate() {
        let metrics = Arc::new(ServerMetrics::default());
        metrics.handshakes_succeeded.fetch_add(7, Ordering::Relaxed);
        let auth = MetricsAuth::new("integration-test-token-fffffff");

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(serve_on_listener_with_auth(
            listener,
            Arc::clone(&metrics),
            auth,
        ));
        tokio::task::yield_now().await;

        async fn fetch(addr: std::net::SocketAddr, raw: &str) -> String {
            let mut sock = timeout(Duration::from_secs(5), TcpStream::connect(addr))
                .await
                .unwrap()
                .unwrap();
            sock.write_all(raw.as_bytes()).await.unwrap();
            let mut buf = Vec::new();
            sock.read_to_end(&mut buf).await.unwrap();
            String::from_utf8_lossy(&buf).to_string()
        }

        // No auth header → 401.
        let r = fetch(addr, "GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(r.starts_with("HTTP/1.1 401"), "expected 401, got:\n{r}");
        assert!(r.contains("WWW-Authenticate: Bearer"));

        // Wrong token → 401.
        let r = fetch(
            addr,
            "GET /metrics HTTP/1.1\r\nAuthorization: Bearer wrong\r\n\r\n",
        )
        .await;
        assert!(r.starts_with("HTTP/1.1 401"), "expected 401, got:\n{r}");

        // Correct token → 200 + body.
        let r = fetch(
            addr,
            "GET /metrics HTTP/1.1\r\nAuthorization: Bearer integration-test-token-fffffff\r\n\r\n",
        )
        .await;
        assert!(r.starts_with("HTTP/1.1 200 OK"), "expected 200, got:\n{r}");
        assert!(r.contains("proteus_handshakes_succeeded_total 7"));

        // /healthz remains unauthenticated.
        let r = fetch(addr, "GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n").await;
        // (alive defaults to false → 503, but never 401.)
        assert!(!r.starts_with("HTTP/1.1 401"));

        server_task.abort();
    }
}
