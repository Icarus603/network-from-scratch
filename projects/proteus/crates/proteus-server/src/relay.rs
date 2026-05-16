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

use proteus_transport_alpha::session::AlphaSession;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

pub async fn handle_session<R, W>(
    session: AlphaSession<R, W>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
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

    // Bidirectional pump.
    let client_to_upstream = async {
        loop {
            match receiver.recv_record().await {
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
    let upstream_to_client = async {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match up_r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if sender.send_record(&buf[..n]).await.is_err() {
                        break;
                    }
                    if sender.flush().await.is_err() {
                        break;
                    }
                }
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
