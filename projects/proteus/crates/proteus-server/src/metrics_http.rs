//! Minimal HTTP `/metrics` endpoint for Prometheus scrape.
//!
//! Deliberately hand-rolled (~40 LoC) so we don't pull in an HTTP
//! framework. This is a single-purpose endpoint that serves text/plain
//! exposition format.

use std::sync::Arc;

use proteus_transport_alpha::metrics::ServerMetrics;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{info, warn};

pub async fn serve(addr: &str, metrics: Arc<ServerMetrics>) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!(addr = %listener.local_addr()?, "metrics endpoint bound");
    loop {
        let (mut stream, _peer) = listener.accept().await?;
        let metrics = Arc::clone(&metrics);
        tokio::spawn(async move {
            // Read request line + headers (we don't actually parse them
            // beyond minimal sanity).
            let mut req = [0u8; 2048];
            let _ = match stream.read(&mut req).await {
                Ok(n) => n,
                Err(_) => return,
            };
            // Only honor GET /metrics. Anything else → 404.
            let head = std::str::from_utf8(&req).unwrap_or("");
            let body;
            let status_line;
            if head.starts_with("GET /metrics ") || head.starts_with("GET /metrics?") {
                body = metrics.prometheus();
                status_line = "HTTP/1.1 200 OK\r\n";
            } else {
                body = "not found\n".to_string();
                status_line = "HTTP/1.1 404 Not Found\r\n";
            }
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
        });
    }
}
