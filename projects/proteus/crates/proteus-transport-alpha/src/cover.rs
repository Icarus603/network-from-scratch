//! Cover-server forwarding (spec §7.5).
//!
//! When the server determines that an incoming connection is *not* a
//! legitimate Proteus client (auth fail, replay, timestamp skew, malformed
//! frame), it MUST forward the raw bytes to a configured cover URL so
//! that an external observer sees a normal HTTPS response from the cover
//! server. This is the production-grade equivalent of REALITY's
//! pass-through-on-fail behavior, with the additional requirement
//! (spec §7.2) that the forward p99 latency stays ≤ 1 ms.
//!
//! For α-profile, "cover server" is a real HTTPS endpoint (e.g.
//! `https://www.cloudflare.com:443`) that the operator configured. We
//! open a TCP connection to it and **byte-verbatim** stream the client's
//! traffic both directions until either side closes.
//!
//! This is the splice-style forward path. A future M3 milestone will
//! swap to Linux eBPF `bpf_sk_redirect_map` for sub-microsecond p99.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

const FORWARD_DIAL_TIMEOUT: Duration = Duration::from_millis(2000);
const FORWARD_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// Forward `(initial_bytes, peer_stream)` to `cover_endpoint`.
///
/// `initial_bytes` are the bytes already consumed from the peer when the
/// auth check ran (e.g. the partial ClientHello frame). They MUST be
/// emitted to the cover endpoint *before* live bidirectional pumping
/// starts, otherwise the cover sees a truncated TLS ClientHello.
pub async fn forward_to_cover(
    cover_endpoint: &str,
    initial_bytes: Vec<u8>,
    peer_stream: TcpStream,
) -> std::io::Result<()> {
    let upstream = match timeout(FORWARD_DIAL_TIMEOUT, TcpStream::connect(cover_endpoint)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "cover dial timed out",
            ))
        }
    };
    upstream.set_nodelay(true).ok();

    let (mut peer_r, mut peer_w) = peer_stream.into_split();
    let (mut up_r, mut up_w) = upstream.into_split();

    // Replay the consumed bytes to the cover upstream first.
    if !initial_bytes.is_empty() {
        up_w.write_all(&initial_bytes).await?;
    }

    let peer_to_up = async {
        let _ = tokio::io::copy(&mut peer_r, &mut up_w).await;
        let _ = up_w.shutdown().await;
    };
    let up_to_peer = async {
        let _ = tokio::io::copy(&mut up_r, &mut peer_w).await;
        let _ = peer_w.shutdown().await;
    };

    let pump = async {
        tokio::join!(peer_to_up, up_to_peer);
    };
    let _ = timeout(FORWARD_IDLE_TIMEOUT, pump).await;
    Ok(())
}

/// Parse a cover endpoint string of the form `"host:port"` into a
/// resolvable target. Returns `None` if the string is malformed.
#[must_use]
pub fn parse_cover_endpoint(s: &str) -> Option<String> {
    if s.parse::<SocketAddr>().is_ok() {
        return Some(s.to_string());
    }
    if let Some((host, port)) = s.rsplit_once(':') {
        if !host.is_empty() && port.parse::<u16>().is_ok() {
            return Some(s.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_parse_accepts_socket_addr() {
        assert_eq!(
            parse_cover_endpoint("127.0.0.1:443").as_deref(),
            Some("127.0.0.1:443")
        );
        assert_eq!(
            parse_cover_endpoint("[::1]:443").as_deref(),
            Some("[::1]:443")
        );
    }

    #[test]
    fn endpoint_parse_accepts_host_port() {
        assert_eq!(
            parse_cover_endpoint("www.cloudflare.com:443").as_deref(),
            Some("www.cloudflare.com:443")
        );
    }

    #[test]
    fn endpoint_parse_rejects_garbage() {
        assert!(parse_cover_endpoint("").is_none());
        assert!(parse_cover_endpoint("nope").is_none());
        assert!(parse_cover_endpoint("host:notaport").is_none());
        assert!(parse_cover_endpoint(":443").is_none());
    }
}
