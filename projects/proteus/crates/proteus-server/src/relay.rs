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
use std::time::{Duration, Instant};

use proteus_transport_alpha::access_log::{AccessLogHandle, AccessLogRecord};
use proteus_transport_alpha::metrics::ServerMetrics;
use proteus_transport_alpha::session::AlphaSession;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

/// Hold the per-session knobs the relay needs from the binary.
#[derive(Clone, Default)]
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
    /// Optional structured access log. One JSON Lines record emitted
    /// per completed session via [`AccessLogHandle::log`]. The handle
    /// itself is cheap to clone (Arc<dyn LogSink>); we capture it
    /// once at session entry and emit at session exit.
    pub access_log: Option<AccessLogHandle>,
}

impl std::fmt::Debug for RelayConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayConfig")
            .field("idle_timeout", &self.idle_timeout)
            .field("metrics", &self.metrics.is_some())
            .field("access_log", &self.access_log.is_some())
            .finish()
    }
}

pub async fn handle_session<R, W>(
    session: AlphaSession<R, W>,
    cfg: RelayConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    // Pull the access-log axes off the session *before* the destructure
    // so they survive the move into AlphaSender/AlphaReceiver.
    let user_id = session.user_id;
    let peer_addr = session.peer_addr;
    let session_metrics = std::sync::Arc::clone(&session.metrics);
    let access_log = cfg.access_log.clone();
    let started = Instant::now();

    let outcome = handle_session_inner(session, cfg).await;

    // Emit one access-log line for the completed session, regardless
    // of whether the inner body returned Ok / Err / through a panic
    // (the binary wraps the spawn in an InFlightGuard that catches
    // panics, but the log path is the same).
    if let Some(logger) = access_log {
        let snap = session_metrics.snapshot();
        let close_reason = match &outcome {
            Ok(reason) => Some(*reason),
            Err(_) => Some("relay_error"),
        };
        logger.log(AccessLogRecord {
            user_id,
            peer: peer_addr,
            duration_ms: Some(started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64),
            tx_bytes: Some(snap.tx_bytes),
            rx_bytes: Some(snap.rx_bytes),
            close_reason,
        });
    }
    outcome.map(|_| ())
}

async fn handle_session_inner<R, W>(
    session: AlphaSession<R, W>,
    cfg: RelayConfig,
) -> Result<&'static str, Box<dyn std::error::Error + Send + Sync>>
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
            return Ok("client_no_connect");
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
            return Ok("upstream_dial_fail");
        }
        Err(_) => {
            warn!(host = %target.0, "upstream dial timed out");
            let _ = sender.send_record(&[]).await;
            let _ = sender.flush().await;
            return Ok("upstream_dial_timeout");
        }
    };
    upstream.set_nodelay(true).ok();
    let (mut up_r, mut up_w) = upstream.into_split();

    // Bidirectional pump. Each direction is independently bounded by
    // `cfg.idle_timeout`: a direction that goes idle longer than this
    // window shuts itself down (which causes the joined task to
    // finish, releasing the session's FDs and crypto state).
    //
    // Both halves write a close-reason into `reason_cell` on exit;
    // first writer wins. The outer body returns whichever reason
    // landed there (or "session_closed" as a default).
    let idle = cfg.idle_timeout;
    let reason_cell: std::sync::Arc<std::sync::Mutex<Option<&'static str>>> =
        std::sync::Arc::new(std::sync::Mutex::new(None));
    fn set_reason(cell: &std::sync::Mutex<Option<&'static str>>, r: &'static str) {
        if let Ok(mut g) = cell.lock() {
            if g.is_none() {
                *g = Some(r);
            }
        }
    }

    let metrics_c2u = metrics.clone();
    let reason_c2u = std::sync::Arc::clone(&reason_cell);
    let client_to_upstream = async move {
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
                        set_reason(&reason_c2u, "idle_timeout");
                        break;
                    }
                },
                None => recv.await,
            };
            match next {
                Ok(Some(buf)) if !buf.is_empty() => {
                    if up_w.write_all(&buf).await.is_err() {
                        set_reason(&reason_c2u, "upstream_write_fail");
                        break;
                    }
                }
                Ok(Some(_empty)) => {} // keepalive
                Ok(None) => {
                    set_reason(&reason_c2u, "client_close");
                    break;
                }
                Err(_) => {
                    set_reason(&reason_c2u, "client_recv_err");
                    break;
                }
            }
        }
        let _ = up_w.shutdown().await;
    };
    let metrics_u2c = metrics.clone();
    let reason_u2c = std::sync::Arc::clone(&reason_cell);
    let upstream_to_client = async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let read_fut = up_r.read(&mut buf);
            let n = match idle {
                Some(d) => match tokio::time::timeout(d, read_fut).await {
                    Ok(Ok(0)) => {
                        set_reason(&reason_u2c, "upstream_eof");
                        break;
                    }
                    Ok(Err(_)) => {
                        set_reason(&reason_u2c, "upstream_read_err");
                        break;
                    }
                    Ok(Ok(n)) => n,
                    Err(_) => {
                        warn!(idle_secs = d.as_secs(), "upstream→client idle timeout");
                        if let Some(m) = metrics_u2c.as_ref() {
                            m.session_idle_reaped
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        set_reason(&reason_u2c, "idle_timeout");
                        break;
                    }
                },
                None => match read_fut.await {
                    Ok(0) => {
                        set_reason(&reason_u2c, "upstream_eof");
                        break;
                    }
                    Err(_) => {
                        set_reason(&reason_u2c, "upstream_read_err");
                        break;
                    }
                    Ok(n) => n,
                },
            };
            if sender.send_record(&buf[..n]).await.is_err() {
                set_reason(&reason_u2c, "client_send_err");
                break;
            }
            if sender.flush().await.is_err() {
                set_reason(&reason_u2c, "client_send_err");
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
    let reason = reason_cell
        .lock()
        .ok()
        .and_then(|g| *g)
        .unwrap_or("session_closed");
    Ok(reason)
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
