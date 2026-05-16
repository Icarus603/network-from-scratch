//! Server-side relay logic.
//!
//! After the Proteus handshake completes, the first record from the client
//! is interpreted as a CONNECT-style target spec:
//!
//! ```text
//! struct ConnectRequest {
//!     uint8 host_len;
//!     opaque host[host_len];          // domain name or IP literal
//!     uint16 port;                     // big-endian
//! }
//! ```
//!
//! The server opens a TCP connection to `(host, port)` and pipes the inner
//! stream bidirectionally. Subsequent client records are forwarded to the
//! upstream; upstream replies are wrapped in records back to the client.

use std::sync::Arc;
use std::time::Duration;

use proteus_transport_alpha::metrics::ServerMetrics;
use proteus_transport_alpha::session::AlphaSession;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

/// Hold the per-session knobs the relay needs from the binary.
#[derive(Debug, Clone, Default)]
pub struct RelayConfig {
    /// Per-direction idle timeout. `None` = no timeout (default).
    /// When set, a session that goes this long without any record
    /// arriving on a given direction is terminated and its FD
    /// released.
    pub idle_timeout: Option<Duration>,
    /// Optional server-wide metrics handle so the relay can increment
    /// `session_idle_reaped` when the timeout fires. The binary wires
    /// this in; standalone tests may leave it as None.
    pub metrics: Option<Arc<ServerMetrics>>,
}

pub async fn handle_session<R, W>(
    session: AlphaSession<R, W>,
    cfg: RelayConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let metrics = cfg.metrics.clone();
    let AlphaSession {
        mut sender,
        mut receiver,
        ..
    } = session;

    // First record = connect request. Push it out immediately so the
    // server can dial upstream without waiting for buffering.
    let req = match receiver.recv_record().await? {
        Some(b) => b,
        None => {
            warn!("client closed before sending connect target");
            return Ok(());
        }
    };
    let target = parse_connect(&req)?;
    info!(host = %target.0, port = target.1, "dialing upstream");

    // Bound the upstream dial — DNS hangs or unreachable targets must
    // not block the relay task indefinitely.
    let dial = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        TcpStream::connect((target.0.as_str(), target.1)),
    )
    .await;
    let upstream = match dial {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            warn!(error = %e, host = %target.0, "upstream dial failed");
            let _ = sender.send_record(&[]).await;
            let _ = sender.flush().await;
            return Ok(());
        }
        Err(_) => {
            warn!(host = %target.0, "upstream dial timed out");
            let _ = sender.send_record(&[]).await;
            let _ = sender.flush().await;
            return Ok(());
        }
    };
    upstream.set_nodelay(true).ok();
    let (mut up_r, mut up_w) = upstream.into_split();

    // Bidirectional pump. Each direction is independently bounded by
    // `cfg.idle_timeout`: a direction that goes idle longer than this
    // window shuts itself down (which causes the joined task to
    // finish, releasing the session's FDs and crypto state).
    let idle = cfg.idle_timeout;
    let metrics_c2u = metrics.clone();
    let client_to_upstream = async {
        loop {
            let recv = receiver.recv_record();
            let next = match idle {
                Some(d) => match tokio::time::timeout(d, recv).await {
                    Ok(r) => r,
                    Err(_) => {
                        warn!(idle_secs = d.as_secs(), "client→upstream idle timeout");
                        if let Some(m) = metrics_c2u.as_ref() {
                            m.session_idle_reaped
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        break;
                    }
                },
                None => recv.await,
            };
            match next {
                Ok(Some(buf)) if !buf.is_empty() => {
                    if up_w.write_all(&buf).await.is_err() {
                        break;
                    }
                }
                Ok(Some(_empty)) => {} // keepalive
                Ok(None) | Err(_) => break,
            }
        }
        let _ = up_w.shutdown().await;
    };
    let metrics_u2c = metrics.clone();
    let upstream_to_client = async {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let read_fut = up_r.read(&mut buf);
            let n = match idle {
                Some(d) => match tokio::time::timeout(d, read_fut).await {
                    Ok(Ok(0)) | Ok(Err(_)) => break,
                    Ok(Ok(n)) => n,
                    Err(_) => {
                        warn!(idle_secs = d.as_secs(), "upstream→client idle timeout");
                        if let Some(m) = metrics_u2c.as_ref() {
                            m.session_idle_reaped
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        break;
                    }
                },
                None => match read_fut.await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                },
            };
            if sender.send_record(&buf[..n]).await.is_err() {
                break;
            }
            if sender.flush().await.is_err() {
                break;
            }
        }
        // Notify the peer that we are intentionally closing the inner
        // stream so it can distinguish a clean upstream-EOF from a
        // mid-session crash.
        let _ = sender
            .send_close(proteus_spec::close_error::NO_ERROR, b"upstream eof")
            .await;
        let _ = sender.shutdown().await;
    };

    tokio::join!(client_to_upstream, upstream_to_client);
    debug!("session closed");
    Ok(())
}

/// Encode a CONNECT request the way the client transmits it. Public
/// for integration tests that need to drive `handle_session` end-to-end.
#[must_use]
#[allow(dead_code)] // used by integration tests via the lib target
pub fn encode_connect(host: &str, port: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + host.len() + 2);
    buf.push(u8::try_from(host.len()).expect("connect host > 255 bytes"));
    buf.extend_from_slice(host.as_bytes());
    buf.extend_from_slice(&port.to_be_bytes());
    buf
}

fn parse_connect(buf: &[u8]) -> Result<(String, u16), Box<dyn std::error::Error + Send + Sync>> {
    if buf.is_empty() {
        return Err("empty connect request".into());
    }
    let host_len = buf[0] as usize;
    if buf.len() < 1 + host_len + 2 {
        return Err("connect request truncated".into());
    }
    let host = std::str::from_utf8(&buf[1..1 + host_len])
        .map_err(|_| "host not valid utf-8")?
        .to_string();
    let port = u16::from_be_bytes([buf[1 + host_len], buf[1 + host_len + 1]]);
    Ok((host, port))
}
