//! Path A dispatch primitive — the one-call surface the
//! accept loop uses to either pass a connection through to
//! the local TLS terminator or transparently splice it to
//! the cover endpoint.
//!
//! Composes:
//!   * [`crate::knock_gate::evaluate`] — sniff + verify
//!   * [`crate::cover::forward_to_cover`] — TCP splice to cover
//!
//! ## Why this lives in its own module
//!
//! The accept-loop integration (iteration 7) needs ONE
//! function call per inbound connection. Threading the gate
//! verdict, the sniffed bytes, the cover-endpoint selection,
//! AND the splice through the existing
//! `server.rs::handle_connection` would require 4-5 new
//! branches scattered across that 200-line function. By
//! collapsing the whole Path A flow into a single
//! `dispatch_or_local_terminate()` call, the accept loop
//! looks like:
//!
//! ```ignore
//!   let stream = match knock_dispatch::dispatch_or_local_terminate(
//!       stream, &dispatch_cfg, now_unix_seconds,
//!   ).await {
//!       PathARouting::TerminateLocally(s) => s,
//!       PathARouting::RoutedToCover { .. } => return, // gate handled it
//!       PathARouting::Dropped { .. } => return,
//!   };
//!   // ... existing handle_connection path with the stream ...
//! ```
//!
//! ## Re-feed semantics on the local-terminate path
//!
//! When the gate verdict is `Pass`, the sniffer already
//! consumed the first ~2 KiB of the inbound stream. The TLS
//! terminator that runs next MUST see those bytes — otherwise
//! the handshake fails at the first read. We solve this by
//! returning a `PrependedStream` that yields the peeked bytes
//! first, then transparently forwards from the underlying
//! TcpStream. The TLS terminator sees a continuous byte
//! stream identical to what was on the wire.

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use proteus_handshake::knock::KnockPsk;
use proteus_handshake::replay::{ReplayWindow, Verdict as ReplayVerdict};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::clienthello_sniffer::{SniffedClientHello, DEFAULT_PEEK_LIMIT, DEFAULT_PEEK_TIMEOUT};
use crate::knock_gate::{evaluate_with_limits, CoverReason, DropReason, GateVerdict};

/// Operator-supplied configuration the dispatcher needs.
/// Trivially clonable so the accept loop can pass `&` cheaply.
#[derive(Debug, Clone)]
pub struct DispatchConfig {
    /// Operator's knock PSK. `None` disables Path A entirely —
    /// the dispatcher returns `TerminateLocally(stream)` for
    /// every connection without sniffing or making any cover
    /// decisions.
    pub psk: Option<KnockPsk>,
    /// Cover endpoint to splice routed-to-cover connections to.
    /// `host:port` form (e.g. `"www.cloudflare.com:443"`).
    /// Required when `psk` is `Some` — without it, a probe
    /// would either trigger the silent-drop path (defeats
    /// indistinguishability) or panic. Operator validates at
    /// startup.
    pub cover_endpoint: Option<String>,
    /// Max bytes the sniffer reads before parsing. Defaults to
    /// 2048 (covers every real browser ClientHello).
    pub peek_limit: usize,
    /// Wall-clock cap on the sniff. Defaults to 3s.
    pub peek_timeout: Duration,
    /// Shared exact-replay detector for valid knocks. All cloned
    /// dispatcher configs retain the same window, so concurrent
    /// accept-loop tasks cannot admit the same captured ClientHello
    /// twice.
    pub replay_window: Arc<Mutex<ReplayWindow>>,
}

impl Default for DispatchConfig {
    fn default() -> Self {
        Self {
            psk: None,
            cover_endpoint: None,
            peek_limit: DEFAULT_PEEK_LIMIT,
            peek_timeout: DEFAULT_PEEK_TIMEOUT,
            replay_window: Arc::new(Mutex::new(ReplayWindow::new())),
        }
    }
}

/// Outcome of the dispatch. The accept loop matches on this
/// and decides whether to continue with its existing
/// per-connection logic.
#[derive(Debug)]
pub enum PathARouting {
    /// The connection passed the gate. The returned stream is
    /// either:
    ///   * the original TcpStream (when `psk = None`, no
    ///     bytes were consumed)
    ///   * a `PrependedStream` (when `psk = Some` and the
    ///     gate verified the knock — re-yields the peeked
    ///     bytes before forwarding from the underlying socket)
    ///
    /// In both cases the caller proceeds with whatever the
    /// existing accept-loop did (TLS terminate → Proteus
    /// handshake → relay).
    TerminateLocally(PrependedStream),
    /// The connection was already handled by the dispatcher —
    /// either spliced to cover OR an error in the splice
    /// path. The caller MUST NOT touch the stream again.
    RoutedToCover {
        /// Why the gate sent this to cover. Operator-throttled
        /// log site uses this for per-reason classification.
        reason: CoverReason,
        /// Result of the splice. `Ok(())` is the canonical
        /// "TCP forward completed cleanly". `Err(_)` means
        /// the splice itself failed (cover dial timeout,
        /// cover endpoint refused, mid-flight network error).
        splice_outcome: std::io::Result<()>,
    },
    /// Reserved for an unrecoverable local failure. Sniff
    /// timeout, EOF, malformed ClientHello, and non-TLS input
    /// are cover-routed; they must never reach this arm because
    /// a local drop would expose an active-probing oracle.
    Dropped {
        /// Why we dropped. Drives per-reason throttled logging.
        reason: DropReason,
    },
}

/// A `TcpStream` with a small prefix of peeked bytes that the
/// next reader sees BEFORE the live socket data. Implements
/// AsyncRead by yielding the prefix first, then forwarding
/// reads from the underlying socket. AsyncWrite is passed
/// through verbatim (peeking only consumed inbound bytes;
/// outbound was never touched).
#[derive(Debug)]
pub struct PrependedStream {
    prefix: Vec<u8>,
    prefix_pos: usize,
    inner: TcpStream,
}

impl PrependedStream {
    /// Wrap a TcpStream with an empty prefix. Used when the
    /// dispatcher returns `TerminateLocally` and no sniff
    /// happened (`psk = None` mode) — the stream is
    /// byte-identical to a bare TcpStream.
    #[must_use]
    pub fn passthrough(inner: TcpStream) -> Self {
        Self {
            prefix: Vec::new(),
            prefix_pos: 0,
            inner,
        }
    }

    /// Wrap a TcpStream with the peeked-bytes prefix from a
    /// gate verdict's `SniffedClientHello`. The next reader
    /// sees the original ClientHello as if no peek had
    /// occurred.
    #[must_use]
    pub fn with_prefix(prefix: Vec<u8>, inner: TcpStream) -> Self {
        Self {
            prefix,
            prefix_pos: 0,
            inner,
        }
    }

    /// Borrow the underlying TcpStream for callers that need
    /// socket-level operations (set_nodelay, peer_addr, etc.)
    /// without unwrapping. The prefix state is preserved.
    pub fn inner(&self) -> &TcpStream {
        &self.inner
    }

    /// Mutable borrow of the underlying TcpStream for callers
    /// that need to e.g. `set_nodelay(true)` on the way through.
    pub fn inner_mut(&mut self) -> &mut TcpStream {
        &mut self.inner
    }

    /// Consume self, returning the underlying socket. Drops
    /// any unread prefix bytes — callers should `read_to_end`
    /// first if the prefix mattered.
    #[must_use]
    pub fn into_inner(self) -> TcpStream {
        self.inner
    }
}

impl AsyncRead for PrependedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Drain the prefix first.
        if self.prefix_pos < self.prefix.len() {
            let available = &self.prefix[self.prefix_pos..];
            let to_copy = available.len().min(buf.remaining());
            buf.put_slice(&available[..to_copy]);
            self.prefix_pos += to_copy;
            return Poll::Ready(Ok(()));
        }
        // Prefix done — defer to the underlying socket.
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrependedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// The one-call dispatch entry point. Used by the accept loop:
///
/// ```ignore
///   match dispatch_or_local_terminate(stream, &dispatch_cfg, now).await {
///       PathARouting::TerminateLocally(s) => /* existing handle_connection */,
///       PathARouting::RoutedToCover { .. } => return,
///       PathARouting::Dropped { .. } => return,
///   }
/// ```
///
/// Bypasses the gate entirely when `cfg.psk = None` (Path A
/// disabled). In that case the returned `PrependedStream` is a
/// pure passthrough — zero overhead, byte-identical to the
/// original TcpStream.
pub async fn dispatch_or_local_terminate(
    mut stream: TcpStream,
    cfg: &DispatchConfig,
    now_unix_seconds: u64,
) -> PathARouting {
    // Fast path: Path A disabled.
    let Some(psk) = cfg.psk.as_ref() else {
        return PathARouting::TerminateLocally(PrependedStream::passthrough(stream));
    };

    let verdict = evaluate_with_limits(
        &mut stream,
        Some(psk),
        now_unix_seconds,
        cfg.peek_limit,
        cfg.peek_timeout,
    )
    .await;

    match verdict {
        GateVerdict::Pass { sniffed } => {
            // The HMAC gate proves possession and freshness, but an exact
            // packet capture remains valid throughout the ±90 s timestamp
            // window. Pin each accepted `(client_random, timestamp)` before
            // local TLS termination. A second copy is cover-routed, which
            // preserves the no-oracle behavior visible to an active prober.
            let timestamp = u32::from_be_bytes(
                sniffed.session_id[..4]
                    .try_into()
                    .expect("a valid knock always has a 32-byte session_id"),
            ) as u64;
            let nonce: [u8; 16] = sniffed.client_random[..16]
                .try_into()
                .expect("client_random is always 32 bytes");
            let replay_verdict = cfg
                .replay_window
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .check(now_unix_seconds, &nonce, timestamp);
            if replay_verdict != ReplayVerdict::Accept {
                let splice_outcome = splice_to_cover(stream, sniffed, cfg).await;
                return PathARouting::RoutedToCover {
                    reason: CoverReason::ReplayKnock,
                    splice_outcome,
                };
            }

            // Re-feed semantics: the TLS terminator that runs
            // next sees the peeked bytes first, then live
            // socket reads. PrependedStream handles this
            // transparently.
            PathARouting::TerminateLocally(PrependedStream::with_prefix(
                sniffed.peeked_bytes,
                stream,
            ))
        }
        GateVerdict::RouteToCover { sniffed, reason } => {
            // Splice to cover. The peeked bytes are the prefix;
            // the existing `cover::forward_to_cover` handles
            // the "write prefix first then bidir copy" flow.
            let splice_outcome = splice_to_cover(stream, sniffed, cfg).await;
            PathARouting::RoutedToCover {
                reason,
                splice_outcome,
            }
        }
        GateVerdict::Drop { reason } => {
            drop(stream);
            PathARouting::Dropped { reason }
        }
    }
}

/// Splice the (already-peeked) inbound stream to the cover
/// endpoint. The peeked bytes become the prefix; the rest of
/// the inbound stream + the cover's outbound stream are pumped
/// bidirectionally until either side closes.
///
/// Returns an error when:
///   * `cfg.cover_endpoint` is `None` (operator misconfig —
///     they enabled Path A but didn't set a cover endpoint).
///   * The cover dial / write / pump failed.
async fn splice_to_cover(
    inbound: TcpStream,
    sniffed: SniffedClientHello,
    cfg: &DispatchConfig,
) -> std::io::Result<()> {
    let cover = cfg.cover_endpoint.as_deref().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Path A enabled but cover_endpoint not configured — RouteToCover cannot proceed",
        )
    })?;
    crate::cover::forward_to_cover(cover, sniffed.peeked_bytes, inbound).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use proteus_handshake::knock::{compute_knock, KnockPsk, KNOCK_PSK_LEN};
    use proteus_handshake::knock_wire::encode_session_id;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn psk_alpha() -> KnockPsk {
        KnockPsk::from_bytes([0xA1; KNOCK_PSK_LEN])
    }

    fn craft_clienthello(client_random: &[u8; 32], session_id: &[u8]) -> Vec<u8> {
        let mut ch_body = Vec::with_capacity(256);
        ch_body.extend_from_slice(&[0x03, 0x03]);
        ch_body.extend_from_slice(client_random);
        ch_body.push(session_id.len() as u8);
        ch_body.extend_from_slice(session_id);
        ch_body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        ch_body.extend_from_slice(&[0x01, 0x00]);
        ch_body.extend_from_slice(&[0x00, 0x00]);
        let hs_len = ch_body.len();
        let mut hs = Vec::with_capacity(4 + hs_len);
        hs.push(0x01);
        hs.extend_from_slice(&[
            ((hs_len >> 16) & 0xff) as u8,
            ((hs_len >> 8) & 0xff) as u8,
            (hs_len & 0xff) as u8,
        ]);
        hs.extend_from_slice(&ch_body);
        let rec_len = hs.len();
        let mut rec = Vec::with_capacity(5 + rec_len);
        rec.extend_from_slice(&[0x16, 0x03, 0x01]);
        rec.extend_from_slice(&[((rec_len >> 8) & 0xff) as u8, (rec_len & 0xff) as u8]);
        rec.extend_from_slice(&hs);
        rec
    }

    #[tokio::test]
    async fn dispatch_disabled_returns_passthrough_without_reading() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (server_stream, _) = listener.accept().await.unwrap();

        let cfg = DispatchConfig::default(); // psk = None
        let routing = dispatch_or_local_terminate(server_stream, &cfg, 1_715_900_000u64).await;

        match routing {
            PathARouting::TerminateLocally(mut s) => {
                // Send bytes from the client; verify the
                // server reads them unchanged through the
                // PrependedStream (which has empty prefix in
                // disabled mode).
                client.write_all(b"HELLO_RAW").await.unwrap();
                client.shutdown().await.unwrap();
                let mut buf = Vec::new();
                s.read_to_end(&mut buf).await.unwrap();
                assert_eq!(&buf, b"HELLO_RAW");
            }
            other => panic!("expected TerminateLocally, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_pass_returns_prepended_stream_that_replays_clienthello() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let psk = psk_alpha();
        let client_random = [0x42; 32];
        let now = 1_715_900_000u64;
        let token = compute_knock(&psk, &client_random, now);
        let session_id = encode_session_id(&token);
        let bytes = craft_clienthello(&client_random, &session_id);
        let bytes_for_client = bytes.clone();

        // Client sends the ClientHello + an extra suffix.
        let client_handle = tokio::spawn(async move {
            let mut c = TcpStream::connect(addr).await.unwrap();
            c.write_all(&bytes_for_client).await.unwrap();
            c.write_all(b"_SUFFIX_FROM_CLIENT").await.unwrap();
            c.shutdown().await.unwrap();
        });

        let (server_stream, _) = listener.accept().await.unwrap();
        let cfg = DispatchConfig {
            psk: Some(psk),
            cover_endpoint: None,
            peek_limit: DEFAULT_PEEK_LIMIT,
            peek_timeout: DEFAULT_PEEK_TIMEOUT,
            ..Default::default()
        };
        let routing = dispatch_or_local_terminate(server_stream, &cfg, now).await;
        match routing {
            PathARouting::TerminateLocally(mut s) => {
                // The next reader (would be TLS terminator)
                // sees the original ClientHello + the suffix
                // bytes — byte-identical to what the client
                // wrote.
                let mut buf = Vec::new();
                s.read_to_end(&mut buf).await.unwrap();
                assert!(buf.starts_with(&bytes), "ClientHello must be re-prepended");
                assert!(
                    buf.ends_with(b"_SUFFIX_FROM_CLIENT"),
                    "suffix bytes must arrive through PrependedStream"
                );
            }
            other => panic!("expected TerminateLocally, got {other:?}"),
        }
        client_handle.await.unwrap();
    }

    #[tokio::test]
    async fn dispatch_routes_probe_to_cover_endpoint() {
        // The Path A win condition: prober's bytes get
        // forwarded to the cover endpoint, byte-for-byte. The
        // cover endpoint sees the original ClientHello (would
        // start a real TLS handshake with the cover backend).
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cover_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cover_addr = cover_listener.local_addr().unwrap();

        let psk = psk_alpha();
        let client_random = [0x33; 32];
        let probe_session_id = [0xCD; 32]; // random — fails knock
        let probe_bytes = craft_clienthello(&client_random, &probe_session_id);
        let probe_bytes_for_client = probe_bytes.clone();
        let now = 1_715_900_000u64;

        // Prober sends the bytes.
        let prober_handle = tokio::spawn(async move {
            let mut c = TcpStream::connect(addr).await.unwrap();
            c.write_all(&probe_bytes_for_client).await.unwrap();
            c.shutdown().await.unwrap();
        });

        // Stub cover backend: accept, echo a fixed banner so
        // the prober (if it read back) would see a "real
        // server" response.
        let cover_banner = b"COVER_BACKEND_RESPONSE\n";
        let cover_banner_for_task = cover_banner.to_vec();
        let cover_handle = tokio::spawn(async move {
            let (mut s, _) = cover_listener.accept().await.unwrap();
            let mut received = Vec::new();
            s.read_to_end(&mut received).await.unwrap();
            // Write back the banner before close. (read_to_end
            // already saw the close, so this would be ignored
            // — but in real cover it'd be the TLS server hello.)
            let _ = s.write_all(&cover_banner_for_task).await;
            received
        });

        let (server_stream, _) = listener.accept().await.unwrap();
        let cfg = DispatchConfig {
            psk: Some(psk),
            cover_endpoint: Some(format!("{cover_addr}")),
            peek_limit: DEFAULT_PEEK_LIMIT,
            peek_timeout: DEFAULT_PEEK_TIMEOUT,
            ..Default::default()
        };

        let routing = dispatch_or_local_terminate(server_stream, &cfg, now).await;
        match routing {
            PathARouting::RoutedToCover {
                reason,
                splice_outcome,
            } => {
                assert!(matches!(reason, CoverReason::BadKnock), "got {reason:?}");
                splice_outcome.expect("splice must complete cleanly");
            }
            other => panic!("expected RoutedToCover, got {other:?}"),
        }

        prober_handle.await.unwrap();
        let cover_received = cover_handle.await.unwrap();
        // The cover backend received the EXACT bytes the
        // prober sent — byte-for-byte indistinguishability.
        assert!(
            cover_received.starts_with(&probe_bytes),
            "cover backend must see the original ClientHello unmodified"
        );
        let _ = cover_banner; // explicit unused-ack
    }

    #[tokio::test]
    async fn dispatch_routes_non_tls_bytes_to_cover_verbatim() {
        let cover_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cover_addr = cover_listener.local_addr().unwrap();
        let payload = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec();
        let expected = payload.clone();
        let expected_len = expected.len();
        let cover_response = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n".to_vec();
        let expected_response = cover_response.clone();
        let cover = tokio::spawn(async move {
            let (mut stream, _) = cover_listener.accept().await.unwrap();
            let mut received = vec![0u8; expected_len];
            stream.read_exact(&mut received).await.unwrap();
            stream.write_all(&cover_response).await.unwrap();
            stream.shutdown().await.unwrap();
            received
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let psk = psk_alpha();

        let client_handle = tokio::spawn(async move {
            let mut c = TcpStream::connect(addr).await.unwrap();
            c.write_all(&payload).await.unwrap();
            let mut response = Vec::new();
            tokio::time::timeout(Duration::from_millis(500), c.read_to_end(&mut response))
                .await
                .expect("plaintext probe must not wait for the 3s sniff timeout")
                .unwrap();
            response
        });

        let (server_stream, _) = listener.accept().await.unwrap();
        let cfg = DispatchConfig {
            psk: Some(psk),
            cover_endpoint: Some(cover_addr.to_string()),
            peek_limit: DEFAULT_PEEK_LIMIT,
            peek_timeout: DEFAULT_PEEK_TIMEOUT,
            ..Default::default()
        };
        let routing = dispatch_or_local_terminate(server_stream, &cfg, 1_715_900_000u64).await;
        match routing {
            PathARouting::RoutedToCover {
                reason,
                splice_outcome,
            } => {
                assert!(
                    matches!(reason, CoverReason::MalformedClientHello { .. }),
                    "got {reason:?}"
                );
                splice_outcome.unwrap();
            }
            other => panic!("expected RoutedToCover, got {other:?}"),
        }
        assert_eq!(client_handle.await.unwrap(), expected_response);
        assert_eq!(cover.await.unwrap(), expected);
    }

    #[tokio::test]
    async fn dispatch_with_no_cover_endpoint_returns_splice_err() {
        // Operator misconfiguration: enabled Path A but didn't
        // set cover_endpoint. The probe routes to cover, but
        // the splice fails immediately. Test asserts the error
        // surfaces in `splice_outcome` instead of panicking.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let psk = psk_alpha();

        let bytes_for_client = craft_clienthello(&[0x77; 32], &[0xEE; 32]); // probe = bad knock
        let client_handle = tokio::spawn(async move {
            let mut c = TcpStream::connect(addr).await.unwrap();
            c.write_all(&bytes_for_client).await.unwrap();
            c.shutdown().await.unwrap();
        });

        let (server_stream, _) = listener.accept().await.unwrap();
        let cfg = DispatchConfig {
            psk: Some(psk),
            cover_endpoint: None, // misconfig
            peek_limit: DEFAULT_PEEK_LIMIT,
            peek_timeout: DEFAULT_PEEK_TIMEOUT,
            ..Default::default()
        };
        let routing = dispatch_or_local_terminate(server_stream, &cfg, 1_715_900_000u64).await;
        match routing {
            PathARouting::RoutedToCover { splice_outcome, .. } => {
                let e = splice_outcome.expect_err("splice must fail when cover endpoint missing");
                assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput);
            }
            other => panic!("expected RoutedToCover w/ err, got {other:?}"),
        }
        let _ = client_handle.await;
    }

    #[tokio::test]
    async fn exact_clienthello_replay_is_routed_to_cover() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cover_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cover_addr = cover_listener.local_addr().unwrap();
        let psk = psk_alpha();
        let client_random = [0x6Du8; 32];
        let now = 1_715_900_000u64;
        let token = compute_knock(&psk, &client_random, now);
        let session_id = encode_session_id(&token);
        let captured = craft_clienthello(&client_random, &session_id);
        let cfg = DispatchConfig {
            psk: Some(psk),
            cover_endpoint: Some(cover_addr.to_string()),
            ..Default::default()
        };

        let first_bytes = captured.clone();
        let first_client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream.write_all(&first_bytes).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let (first_stream, _) = listener.accept().await.unwrap();
        match dispatch_or_local_terminate(first_stream, &cfg, now).await {
            PathARouting::TerminateLocally(mut local) => {
                let mut received = Vec::new();
                local.read_to_end(&mut received).await.unwrap();
                assert_eq!(received, captured);
            }
            other => panic!("first use of a valid knock must pass: {other:?}"),
        }
        first_client.await.unwrap();

        let cover = tokio::spawn(async move {
            let (mut stream, _) = cover_listener.accept().await.unwrap();
            let mut received = Vec::new();
            stream.read_to_end(&mut received).await.unwrap();
            received
        });
        let replay_bytes = captured.clone();
        let replay_client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream.write_all(&replay_bytes).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let (replay_stream, _) = listener.accept().await.unwrap();
        match dispatch_or_local_terminate(replay_stream, &cfg, now).await {
            PathARouting::RoutedToCover {
                reason,
                splice_outcome,
            } => {
                assert!(matches!(reason, CoverReason::ReplayKnock));
                splice_outcome.unwrap();
            }
            other => panic!("exact replay must be routed to cover: {other:?}"),
        }
        replay_client.await.unwrap();
        assert_eq!(cover.await.unwrap(), captured);
    }
}
