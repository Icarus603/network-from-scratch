//! Server-side pre-TLS ClientHello sniffer for Path A.
//!
//! ## Why this exists
//!
//! Path A's pre-auth gate needs to inspect the inbound
//! ClientHello BEFORE rustls (or whatever future TLS terminator)
//! consumes the bytes — so the gate can decide:
//!
//!   * Knock present + valid → terminate locally; full Proteus
//!     handshake proceeds.
//!   * No knock OR knock invalid → transparently splice the
//!     stream to the cover endpoint. The original bytes (including
//!     the unmodified ClientHello) MUST be forwarded verbatim so
//!     the cover TLS terminator can complete its own handshake —
//!     a real Cloudflare backend has no idea Proteus existed.
//!
//! This module provides the sniffer primitive: peek the first
//! ~2 KiB of an `AsyncRead`, parse the ClientHello, return a
//! `SniffedClientHello` whose `peeked_bytes` field contains the
//! exact raw bytes the caller can either:
//!
//!   * Re-prepend to a Cursor + chain with the rest of the
//!     stream → feed to rustls as if nothing was sniffed (the
//!     Proteus-terminate path).
//!   * Write straight to the cover-endpoint socket → cover
//!     reads the same bytes the original client sent
//!     (the passthrough path).
//!
//! ## What this is NOT
//!
//! - **Not the gate itself.** That's iteration 6 — it consumes
//!   `SniffedClientHello` + the configured `KnockPsk` + calls
//!   `decode_and_verify_session_id`.
//! - **Not a TLS terminator.** This module never decrypts or
//!   validates anything beyond the ClientHello record header.
//!   Subsequent bytes (handshake, application data) flow
//!   through untouched.
//!
//! ## Bounding the read
//!
//! ClientHellos are typically 200-600 bytes (no ESNI/ECH) or
//! 1-2 KiB (with ECH). We cap the peek at 2 KiB which:
//!   * Catches every Chrome 124 / Firefox 124 / Safari 17.4
//!     real ClientHello (verified via the `tls_fingerprint_observer`
//!     module's loopback capture — same 2048-byte buffer).
//!   * Doesn't hold a relayed prober's connection indefinitely
//!     waiting for bytes — sniff is bounded by a wall-clock
//!     `peek_timeout`.
//!   * Fits comfortably in one TCP MSS (1500-byte typical),
//!     so most ClientHellos arrive in a single read.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};

/// Max bytes the sniffer will read before giving up. Operator-
/// tunable via [`sniff_client_hello_with_limits`] but defaults
/// to 2048 which covers every modern browser's ClientHello
/// (with or without ECH).
pub const DEFAULT_PEEK_LIMIT: usize = 2048;

/// Default wall-clock cap on the peek. A real ClientHello
/// arrives within one RTT after `accept()`; 3 s is generous
/// for transcontinental paths. Probers / hangers either send
/// bytes in this window or get dropped.
pub const DEFAULT_PEEK_TIMEOUT: Duration = Duration::from_secs(3);

/// Successful sniff result. Carries:
///
///   * `peeked_bytes` — the EXACT bytes read from the wire,
///     unmodified. The caller MUST re-feed these into whatever
///     downstream consumer (TLS terminator OR cover-splice
///     socket) handles the connection's first read.
///   * `record_len` — the parsed TLS record length (so callers
///     can slice `peeked_bytes[..record_len]` to get just the
///     ClientHello record vs trailing bytes if any).
///   * `client_random` + `session_id` — the extracted JA4
///     fields the Path A gate consumes via
///     `proteus_handshake::knock_wire::decode_and_verify_session_id`.
#[derive(Debug, Clone)]
pub struct SniffedClientHello {
    /// Raw bytes read from the inbound stream. MUST be re-fed
    /// into the downstream consumer (TLS terminator OR cover
    /// socket) verbatim.
    pub peeked_bytes: Vec<u8>,
    /// Total length of the TLS record (header + body). The
    /// ClientHello bytes are `peeked_bytes[..5 + record_len]`;
    /// anything past that is residual that arrived in the
    /// same read (rare for real ClientHellos).
    pub record_len: usize,
    /// 32-byte client_random extracted from the ClientHello.
    /// Feed into the knock verifier.
    pub client_random: [u8; 32],
    /// Raw session_id bytes (0-32 per RFC 8446 §4.1.2).
    /// Feed into the knock verifier.
    pub session_id: Vec<u8>,
}

/// Errors from the sniffer. The gate distinguishes these to
/// drive different operational responses:
///   * `Timeout` → operator-throttled INFO log (probers hang
///     constantly; not page-worthy).
///   * `ConnectionClosed` → same — common for half-open scans.
///   * `BadRecord` → operator-throttled WARN log (someone is
///     sending malformed bytes — probably a buggy client or
///     a misconfiguration).
///   * `Io` → unexpected (kernel-level failure); operator
///     INFO log + drop connection.
#[derive(thiserror::Error, Debug)]
pub enum SniffError {
    /// Peek didn't complete within the configured deadline.
    #[error("peek timed out after {0:?}")]
    Timeout(Duration),
    /// Peer closed the connection before sending enough bytes
    /// to even include the TLS record header.
    #[error("connection closed before ClientHello arrived (got {bytes} bytes, need at least 5)")]
    ConnectionClosed {
        /// How many bytes were read before EOF.
        bytes: usize,
    },
    /// TLS record / handshake / ClientHello parsing failed.
    /// Likely a non-TLS protocol on this port (e.g. HTTP CONNECT
    /// without TLS, plaintext SSH probe, etc.).
    #[error("malformed ClientHello: {0}")]
    BadRecord(String),
    /// Underlying I/O failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Sniff with default limits ([`DEFAULT_PEEK_LIMIT`] +
/// [`DEFAULT_PEEK_TIMEOUT`]).
pub async fn sniff_client_hello<R>(reader: &mut R) -> Result<SniffedClientHello, SniffError>
where
    R: AsyncRead + Unpin,
{
    sniff_client_hello_with_limits(reader, DEFAULT_PEEK_LIMIT, DEFAULT_PEEK_TIMEOUT).await
}

/// Sniff with operator-supplied limits. Used by integration
/// tests that want to exercise short deadlines.
pub async fn sniff_client_hello_with_limits<R>(
    reader: &mut R,
    peek_limit: usize,
    peek_timeout: Duration,
) -> Result<SniffedClientHello, SniffError>
where
    R: AsyncRead + Unpin,
{
    let read_fut = read_full_clienthello(reader, peek_limit);
    let peeked_bytes = match tokio::time::timeout(peek_timeout, read_fut).await {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err(SniffError::Timeout(peek_timeout)),
    };

    // Parse via the existing JA4 components extractor — it
    // gives us client_random + session_id directly without
    // duplicating TLS-record parsing here.
    let (_, components) =
        proteus_fingerprint::ja4::parse_client_hello_with_components(&peeked_bytes, 't')
            .map_err(|e| SniffError::BadRecord(format!("{e}")))?;

    // Record length the parser implicitly walked.
    // TLS record: bytes 0..5 are header, bytes 3..5 are the
    // big-endian u16 body length.
    let record_body_len = u16::from_be_bytes([peeked_bytes[3], peeked_bytes[4]]) as usize;
    let record_len = 5 + record_body_len;

    Ok(SniffedClientHello {
        peeked_bytes,
        record_len,
        client_random: components.client_random,
        session_id: components.session_id,
    })
}

/// Read until we have at least one full TLS record (the
/// ClientHello), OR `limit` bytes total, OR EOF. Returns the
/// raw bytes collected.
async fn read_full_clienthello<R>(reader: &mut R, limit: usize) -> Result<Vec<u8>, SniffError>
where
    R: AsyncRead + Unpin,
{
    let mut buf = vec![0u8; limit];
    let mut total = 0usize;
    loop {
        if total >= buf.len() {
            // Bumping into the cap. Returning what we have lets
            // the parser surface BadRecord if the record header
            // claimed more bytes than we read.
            break;
        }
        let n = reader.read(&mut buf[total..]).await?;
        if n == 0 {
            // EOF before any data or before the record completes.
            if total < 5 {
                return Err(SniffError::ConnectionClosed { bytes: total });
            }
            break;
        }
        total += n;
        // Header arrived — check if record body fits in what
        // we've already read.
        if total >= 5 {
            let record_body_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
            let full_record = 5 + record_body_len;
            if total >= full_record {
                break;
            }
            // If the header claims more than our cap, we still
            // try to fill what we can — the parser will surface
            // BadRecord on the truncation. We DELIBERATELY do not
            // resize beyond `limit` here: iter-156 closes a defect
            // where a previous `buf.resize(full_record.min(limit * 2), 0)`
            // silently doubled the documented `peek_limit` on a
            // malformed record-length header — an attacker who set
            // `record_body_len = 0xFFFF` could force the sniffer to
            // hold 2 × peek_limit bytes per connection. The buffer
            // is already pre-sized to `limit` on entry, so a record
            // that demands more bytes than the cap simply truncates
            // and the parser rejects it as BadRecord.
        }
    }
    buf.truncate(total);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Build a minimal-but-valid TLS 1.3 ClientHello record.
    /// Mirrors the helper in `proteus-handshake::tests::knock_wire_e2e`
    /// but inlined here to keep this crate's tests self-contained.
    fn craft_clienthello(client_random: &[u8; 32], session_id: &[u8]) -> Vec<u8> {
        let mut ch_body = Vec::with_capacity(256);
        ch_body.extend_from_slice(&[0x03, 0x03]); // legacy_version
        ch_body.extend_from_slice(client_random);
        ch_body.push(session_id.len() as u8);
        ch_body.extend_from_slice(session_id);
        ch_body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher_suites
        ch_body.extend_from_slice(&[0x01, 0x00]); // compression
        ch_body.extend_from_slice(&[0x00, 0x00]); // no extensions

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
    async fn sniff_full_clienthello_in_one_read() {
        let client_random = [0xAA; 32];
        let session_id = vec![0xBB; 32];
        let bytes = craft_clienthello(&client_random, &session_id);
        let mut cursor = Cursor::new(bytes.clone());
        let result = sniff_client_hello(&mut cursor).await.unwrap();
        assert_eq!(result.peeked_bytes, bytes);
        assert_eq!(result.client_random, client_random);
        assert_eq!(result.session_id, session_id);
        assert_eq!(result.record_len, bytes.len());
    }

    #[tokio::test]
    async fn sniff_full_clienthello_across_multiple_short_reads() {
        // Simulate a kernel TCP stack that delivers the record
        // in 16-byte chunks. The sniffer's loop must drain
        // until the full record arrives.
        let client_random = [0x11; 32];
        let session_id = vec![0x22; 32];
        let bytes = craft_clienthello(&client_random, &session_id);

        // Use a SlowReader that yields one chunk per `.read()`.
        struct SlowReader {
            inner: Vec<u8>,
            pos: usize,
            chunk: usize,
        }
        impl AsyncRead for SlowReader {
            fn poll_read(
                mut self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                let remaining = self.inner.len() - self.pos;
                let want = remaining.min(self.chunk).min(buf.remaining());
                if want == 0 {
                    return std::task::Poll::Ready(Ok(()));
                }
                let start = self.pos;
                let end = start + want;
                buf.put_slice(&self.inner[start..end]);
                self.pos = end;
                std::task::Poll::Ready(Ok(()))
            }
        }

        let mut reader = SlowReader {
            inner: bytes.clone(),
            pos: 0,
            chunk: 16,
        };
        let result = sniff_client_hello(&mut reader).await.unwrap();
        assert_eq!(result.peeked_bytes, bytes);
        assert_eq!(result.client_random, client_random);
        assert_eq!(result.session_id, session_id);
    }

    #[tokio::test]
    async fn sniff_returns_connection_closed_on_truncated_record() {
        // Peer sent only 2 bytes then closed — not enough for
        // even the TLS record header (5 bytes).
        let mut cursor = Cursor::new(vec![0x16, 0x03]);
        let err = sniff_client_hello(&mut cursor).await.unwrap_err();
        assert!(
            matches!(err, SniffError::ConnectionClosed { bytes: 2 }),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn sniff_returns_bad_record_on_non_tls_payload() {
        // HTTP GET probe — looks like text, parses as TLS
        // record-type 0x47 ('G') which the JA4 parser rejects
        // as BadRecord.
        let mut cursor = Cursor::new(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec());
        let err = sniff_client_hello(&mut cursor).await.unwrap_err();
        assert!(matches!(err, SniffError::BadRecord(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn sniff_returns_timeout_when_peer_stalls() {
        // PendingReader never delivers any bytes. Sniff must
        // fire its timeout deadline.
        struct PendingReader;
        impl AsyncRead for PendingReader {
            fn poll_read(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                _buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Pending
            }
        }
        let mut reader = PendingReader;
        let err = sniff_client_hello_with_limits(
            &mut reader,
            DEFAULT_PEEK_LIMIT,
            Duration::from_millis(50),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, SniffError::Timeout(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn sniff_preserves_peeked_bytes_byte_for_byte() {
        // The CRITICAL invariant for the cover-passthrough path:
        // peeked_bytes MUST equal what the peer sent, so we
        // can re-write it to the cover socket and the cover
        // sees an unmodified TLS handshake start.
        let client_random = [0x77; 32];
        let session_id = vec![0x88; 16];
        let bytes = craft_clienthello(&client_random, &session_id);
        let mut cursor = Cursor::new(bytes.clone());
        let result = sniff_client_hello(&mut cursor).await.unwrap();
        assert_eq!(result.peeked_bytes, bytes);
        // Verify we can write the peeked bytes back somewhere
        // and they're the same length / contents.
        let mut sink = Vec::new();
        tokio::io::AsyncWriteExt::write_all(&mut sink, &result.peeked_bytes)
            .await
            .unwrap();
        assert_eq!(sink, bytes);
    }

    #[tokio::test]
    async fn sniff_handles_clienthello_followed_by_trailing_bytes_in_same_read() {
        // Some clients pipeline the ClientHello + early data
        // in one TCP segment. Sniffer must capture the
        // ClientHello + leave the trailing bytes addressable
        // via record_len.
        let client_random = [0x42; 32];
        let session_id = vec![0x55; 32];
        let mut bytes = craft_clienthello(&client_random, &session_id);
        let original_len = bytes.len();
        bytes.extend_from_slice(b"TRAILING_BYTES_FROM_CLIENT");
        let mut cursor = Cursor::new(bytes.clone());
        let result = sniff_client_hello(&mut cursor).await.unwrap();
        // peeked_bytes may include the trailing bytes (because
        // we read in one go), but record_len marks the
        // ClientHello boundary.
        assert_eq!(result.record_len, original_len);
        assert!(result.peeked_bytes.len() >= original_len);
        // The ClientHello prefix MUST be byte-for-byte original.
        assert_eq!(&result.peeked_bytes[..original_len], &bytes[..original_len]);
    }

    #[tokio::test]
    async fn sniff_respects_peek_limit_on_oversized_claim() {
        // Maliciously crafted record header claims a 100 KB
        // body. Sniffer's read cap MUST not grow unbounded.
        // The parser will then surface BadRecord (the body
        // we read is shorter than the claimed length).
        let mut bytes = vec![0x16, 0x03, 0x01];
        // Length = 65000 (won't fit our cap)
        bytes.extend_from_slice(&[0xFD, 0xE8]);
        // Padding (much less than 65000)
        bytes.extend_from_slice(&[0x00; 50]);
        let mut cursor = Cursor::new(bytes);
        let err = sniff_client_hello_with_limits(
            &mut cursor,
            128, // tight cap
            DEFAULT_PEEK_TIMEOUT,
        )
        .await
        .unwrap_err();
        // Either BadRecord (truncation detected by parser) or
        // ConnectionClosed (we hit EOF before reaching cap).
        // Either is acceptable — the critical property is
        // we did NOT allocate gigabytes.
        assert!(matches!(
            err,
            SniffError::BadRecord(_) | SniffError::ConnectionClosed { .. }
        ));
    }

    /// Iter-156: an attacker who controls the TLS-record-length
    /// header (bytes 3-4) could previously force the sniffer to
    /// `buf.resize(full_record.min(limit * 2), 0)` — silently
    /// doubling the documented `peek_limit`. This test feeds the
    /// maximum possible 16-bit length (`record_body_len = 0xFFFF`)
    /// against a tight 256-byte cap and asserts the error surfaces
    /// without the buffer ever growing beyond the cap.
    ///
    /// Verification strategy: we use a `CountingReader` that
    /// records the largest `buf.remaining()` it observes across
    /// poll_read calls. The cap is N bytes; observed `remaining`
    /// must never exceed `N - 5` (= N minus the bytes already
    /// consumed by the time the cap is first felt).
    #[tokio::test]
    async fn sniff_does_not_grow_buffer_past_peek_limit_on_attacker_length() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        struct CountingReader {
            inner: Vec<u8>,
            pos: usize,
            max_buf_remaining: Arc<AtomicUsize>,
        }
        impl AsyncRead for CountingReader {
            fn poll_read(
                mut self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                let prev = self.max_buf_remaining.load(Ordering::Relaxed);
                let now = buf.remaining();
                if now > prev {
                    self.max_buf_remaining.store(now, Ordering::Relaxed);
                }
                let remaining = self.inner.len() - self.pos;
                let want = remaining.min(8).min(buf.remaining());
                if want == 0 {
                    return std::task::Poll::Ready(Ok(()));
                }
                let start = self.pos;
                let end = start + want;
                buf.put_slice(&self.inner[start..end]);
                self.pos = end;
                std::task::Poll::Ready(Ok(()))
            }
        }

        // Crafted record: type=0x16, version=0x0301, length=0xFFFF
        // — the maximum a 16-bit big-endian length can claim. Body
        // is much smaller; we never deliver more than the cap.
        let mut bytes = vec![0x16, 0x03, 0x01, 0xFF, 0xFF];
        bytes.extend_from_slice(&[0x00; 1024]);

        let cap: usize = 256;
        let max_observed = Arc::new(AtomicUsize::new(0));
        let mut reader = CountingReader {
            inner: bytes,
            pos: 0,
            max_buf_remaining: max_observed.clone(),
        };

        let res = sniff_client_hello_with_limits(&mut reader, cap, DEFAULT_PEEK_TIMEOUT).await;
        // Must error (truncated record body); never panic and
        // never allocate beyond the cap.
        assert!(res.is_err(), "expected error on oversized claim");
        let observed = max_observed.load(Ordering::Relaxed);
        assert!(
            observed <= cap,
            "iter-156: sniffer offered {observed} bytes to the reader \
             (cap = {cap}). The pre-iter-156 code would double the \
             buffer via `buf.resize(full_record.min(limit * 2), 0)` \
             when the attacker-controlled record-length header \
             exceeded the cap."
        );
    }
}
