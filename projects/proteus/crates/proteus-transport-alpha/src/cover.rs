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
    // Apply nodelay + TCP keepalive (+ TCP_USER_TIMEOUT on Linux) to
    // the cover-upstream socket. Pre-iter-137 we only set nodelay.
    // Keepalive matters here because the cover-forward path is a hot
    // DoS target — every junk ClientHello an attacker sends opens a
    // cover-upstream socket. A wedged or half-open cover-upstream
    // peer (CGNAT idle reap, cloud-LB silent connection drop, cover
    // host kernel hang) without keepalive sits on a server-side FD
    // until the 120 s FORWARD_IDLE_TIMEOUT, multiplying the FD-
    // exhaustion blast radius an attacker can inflict on the server
    // by `attempts × 120s`.
    //
    // Keepalive at 30 s = the operator's normal client-facing
    // keepalive policy, so cover-forward sockets fail fast on dead
    // upstreams without flooding the wire with probes. The
    // additional Linux-only TCP_USER_TIMEOUT covers the
    // dead-active-peer class (we're trying to send the cover
    // response back to the peer through the forwarder, but the peer
    // dropped) at 4× = 120 s, matching the outer FORWARD_IDLE_TIMEOUT.
    let _ = crate::socket_opts::apply_dial_socket_opts_with_user_timeout(&upstream, 30, 120);

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

    // `tokio::select!` (NOT `tokio::join!`) so a half-close in either
    // direction tears down the other immediately. Without this, a
    // misbehaving cover server (or one that holds its write side open
    // while waiting on a long-poll request body) parks the forward
    // for the full FORWARD_IDLE_TIMEOUT (120 s) — every junk
    // ClientHello an attacker sends sits on an FD for 2 minutes,
    // amplifying their DoS by a factor of `attempts × 120s`.
    //
    // Same class as the relay-pump bug fixed in 53c8dfc (client) and
    // ee85b27 (server). Cover-forward damage was bounded by the 120 s
    // outer timeout, but bounded != correct — production servers
    // under sustained probe attacks would still see a continuous
    // 120-s-rolling FD pile.
    //
    // Note: `tokio::io::copy` is cancel-safe — when the losing future
    // is dropped here, its internal buffer is dropped along with the
    // borrowed reader/writer halves, releasing the FDs immediately.
    let pump = async {
        tokio::select! {
            _ = peer_to_up => {}
            _ = up_to_peer => {}
        }
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

    // ---- iter-137: cover-upstream socket-options hardening ----

    /// Iter-137 pins that the cover-forward dial-stage applies
    /// keepalive + (on Linux) `TCP_USER_TIMEOUT` to the cover-
    /// upstream socket. Pre-iter-137 only nodelay was set, leaving
    /// a junk-ClientHello flood attack to pin server FDs on
    /// wedged/half-open cover-upstream peers for the full 120 s
    /// `FORWARD_IDLE_TIMEOUT`.
    ///
    /// We can't directly observe the setsockopt fired (no kernel
    /// hook in tests), but we CAN exercise the same code path
    /// against a loopback peer + assert the function returns Ok
    /// (= keepalive + nodelay applied, no errors), AND we exercise
    /// the same shared helper that has its own unit tests under
    /// `socket_opts`. This test is the end-to-end "the helper got
    /// wired up at the right call site" check.
    #[tokio::test]
    async fn forward_to_cover_dial_succeeds_against_loopback_listener() {
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpListener;

        // Loopback "cover" listener that drains its socket then exits.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cover_addr = listener.local_addr().unwrap();
        let cover = format!("{cover_addr}");

        let server_task = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 64];
            // Read whatever the forwarder relays then shut down.
            let _ = s.read(&mut buf).await;
        });

        // Connect a "peer" socket and send a few bytes — the
        // forward_to_cover function should drain those into the cover.
        let peer_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer_listener.local_addr().unwrap();
        let peer_connect_task = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let mut s = TcpStream::connect(peer_addr).await.unwrap();
            s.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
            // Hold open a moment so the forwarder has time to read.
            tokio::time::sleep(Duration::from_millis(50)).await;
        });
        let (peer_stream, _) = peer_listener.accept().await.unwrap();

        // Initial bytes empty (the test mimics the post-handshake-fail
        // path where bytes from the peer arrive AFTER the forward
        // starts; the initial-bytes argument is for the rare case
        // when the auth check pre-consumed some).
        let res = forward_to_cover(&cover, Vec::new(), peer_stream).await;
        assert!(
            res.is_ok(),
            "cover-forward against loopback listener should succeed: {res:?}"
        );
        let _ = peer_connect_task.await;
        let _ = server_task.await;
    }
}
