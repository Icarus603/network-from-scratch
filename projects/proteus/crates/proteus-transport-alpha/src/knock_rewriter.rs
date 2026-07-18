//! Path-A client-side knock injector — byte-level rewriter
//! primitive.
//!
//! Iteration 9 of Path A. The previous iterations built:
//!   * `proteus_handshake::knock` — cryptographic primitive
//!   * `proteus_handshake::knock_wire` — session_id encoder
//!   * server-side sniffer + gate + dispatch + accept loop
//!
//! ## STATUS: superseded by transcript-native injection
//!
//! This module remains as a tested, self-contained record-layout
//! primitive and as a regression record of an approach that cannot
//! work. Production Path A now uses
//! `tls::KnockSecureRandom`: rustls receives the knock-bearing
//! session_id during its own ClientHello construction, before hashing
//! the transcript. The passing
//! `transcript_native_knock_passes_gate_and_tls_handshake` and
//! `shared_knock_connector_survives_concurrent_clienthello_construction`
//! tests cover the replacement path.
//!
//! ### What goes wrong
//!
//! TLS 1.3 (RFC 8446 §4.4) hashes the EXACT bytes of every
//! handshake message into a running transcript that both sides
//! must compute identically. The handshake-traffic keys
//! (ServerHello onwards is encrypted) are derived from that
//! transcript. If client and server have different transcripts,
//! the server encrypts with keys derived from H_server and the
//! client decrypts with keys derived from H_client → garbage
//! plaintext → `DecryptError`.
//!
//! Our byte-level rewriter modifies the ClientHello's
//! `legacy_session_id` field on the wire AFTER client's rustls
//! has already added the original bytes to its transcript hash.
//! Server's rustls receives the modified bytes and adds those
//! to ITS transcript hash. Transcripts diverge by exactly the
//! 32 bytes of session_id. Result: every encrypted record
//! fails to decrypt.
//!
//! We also tried restoring the ServerHello's echoed session_id
//! back to rustls's expected value on the inbound side. That
//! fixes the trivial `legacy_session_id_echo` equality check
//! (RFC 8446 §4.1.3) but does NOT fix the transcript-hash
//! divergence — the server's hash committed to the modified
//! session_id, and there's no way to retroactively reconcile.
//!
//! ### Why not an alternative wire location
//!
//! Every field inside the ClientHello (random, extensions,
//! anything) participates in the transcript hash. So rewriting
//! ANY ClientHello byte without modifying rustls's internal
//! state produces the same DecryptError.
//!
//! ### The replacement that shipped
//!
//! rustls's public `CryptoProvider::secure_random` surface supplies
//! the TLS 1.3 compatibility session_id and client_random. The
//! knock-aware provider predicts the outer random, derives the
//! session_id from it, and returns the same prediction on rustls's
//! next outer-random request. ECH GREASE adds a third 32-byte inner
//! random request; an explicit state-machine passes that one through
//! unchanged. This avoids both a rustls fork and a fingerprintable
//! pre-TLS prefix.
//!
//! ## What this module is good for TODAY
//!
//! Although production no longer calls this rewriter, it remains
//! useful for two reasons:
//!
//!   1. It documents (with proofs via unit tests) the wire
//!      layout of TLS 1.3 ClientHello/ServerHello session_id
//!      fields — required reading for whoever does iteration 10.
//!   2. The byte-level patching mechanism is correct in
//!      isolation (verified by `knock_token_is_recoverable_by_
//!      server_decode`): the rewriter's output decodes
//!      successfully via `decode_and_verify_session_id`. The
//!      wire-format debugging can reuse this module's offset
//!      constants and `patch_outbound_in_place` helper.
//!
//! ## Wire layout we patch (RFC 8446 §4.1.2 ClientHello,
//! §4.1.3 ServerHello)
//!
//! Both records start identically up through the session_id:
//!
//! ```text
//!   bytes 0..5    TLS record header
//!                   [0]   = 0x16 (handshake)
//!                   [1..3] = legacy_record_version (0x0301 or 0x0303)
//!                   [3..5] = record body length, big-endian u16
//!   bytes 5..9    handshake header
//!                   [5]   = 0x01 ClientHello | 0x02 ServerHello
//!                   [6..9] = handshake body length, big-endian u24
//!   bytes 9..11   legacy_version (TLS 1.2 marker = 0x0303 — TLS 1.3
//!                                 negotiates via supported_versions
//!                                 extension)
//!   bytes 11..43  random (client_random or server_random, 32 bytes)
//!   bytes 43..44  legacy_session_id length (rustls in TLS 1.3 mode
//!                                            always writes 32 per the
//!                                            "middlebox compatibility"
//!                                            convention in §4.1.2)
//!   bytes 44..76  legacy_session_id payload (32 bytes when len=32)
//!   bytes 76..    cipher_suites, compression, extensions ...
//! ```
//!
//! The rewriter therefore needs at least 76 bytes of the
//! first record to do its work. Real ClientHellos are
//! 200-600 bytes, so this always lands inside the first
//! TCP segment.
//!
//! ## What happens end-to-end
//!
//! 1. Client's rustls builds a normal ClientHello with a
//!    rustls-generated random 32-byte session_id (call it
//!    `R_orig`). rustls writes it to the wrapped stream.
//! 2. We buffer the bytes until we have ≥ 76. We extract
//!    `client_random` from bytes 11..43, compute
//!    `knock_token = compute_knock(psk, client_random, now)`,
//!    encode `[knock_token || random_padding]` into 32 bytes,
//!    and overwrite bytes 44..76 with the encoding. We save
//!    `R_orig` for the inbound side.
//! 3. The patched bytes go on the wire. The server's Path-A
//!    gate sniffs, verifies the knock, and lets rustls (the
//!    server's rustls) terminate TLS over a PrependedStream.
//! 4. Server's rustls echoes the received session_id back in
//!    the ServerHello (`legacy_session_id_echo`, RFC 8446
//!    §4.1.3 — "MUST be set to legacy_session_id from the
//!    ClientHello"). So the wire-inbound carries our knock
//!    bytes back.
//! 5. Client's rustls would compare echoed session_id against
//!    `R_orig` and abort if they mismatch (RFC 8446 §4.1.3:
//!    "if the field is not empty, the client MUST verify
//!    that the legacy_session_id_echo field is equal to the
//!    legacy_session_id field provided"). So we intercept the
//!    inbound ServerHello, swap bytes 44..76 back to `R_orig`,
//!    and forward to rustls. rustls's check passes.
//! 6. Everything after the first record in each direction
//!    passes through unmodified. The TLS handshake completes
//!    normally and yields a working TLS stream — Proteus's
//!    inner handshake then runs over it as usual.
//!
//! ## Known limit: HelloRetryRequest (HRR)
//!
//! If the server's first response is HRR (TLS 1.3 §4.1.4 —
//! rare with Chrome-shaped X25519+ML-KEM client keyshares),
//! client's rustls will send a second ClientHello with the
//! SAME legacy_session_id as the first. Since our rewriter
//! is one-shot per direction, the second ClientHello would
//! go out unmodified (no knock) and the server's gate would
//! cover-splice it. Path A would fail under HRR.
//!
//! Mitigation: the Chrome-shaped client config we ship offers
//! the exact key shares the server's Chrome-shaped TLS 1.3
//! config accepts, so HRR is essentially unreachable in our
//! deployment. A future iteration could extend the rewriter
//! to handle HRR (detect the magic random `0xCF21AD74...` in
//! the inbound and reset the outbound state to re-patch the
//! retry). Documented as a follow-up; not blocking
//! single-VPS production deploy.
//!
//! ## Wire-shape preservation
//!
//! Per RFC 8446 §4.1.2, rustls in TLS 1.3 mode emits a 32-byte
//! random session_id by default (middlebox-compatibility mode).
//! Our rewrite replaces 32 random bytes with 32 different
//! random-looking bytes — the JA4 fingerprint, record length,
//! and every other observable byte are unchanged. A passive
//! observer sees a byte-for-byte Chrome-shaped ClientHello
//! whose session_id happens to differ from what rustls
//! generated — exactly the same property real Chrome has,
//! since Chrome regenerates a random session_id every
//! ClientHello.

use std::pin::Pin;
use std::task::{Context, Poll};

use proteus_handshake::knock::{compute_knock, KnockPsk, CLIENT_RANDOM_LEN};
use proteus_handshake::knock_wire::{encode_session_id, ENCODED_SESSION_ID_LEN};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Byte offsets we depend on inside the TLS first record.
/// All u16/u24 length fields are validated at runtime; these
/// constants pin the FIXED-offset fields.
mod offsets {
    /// Where the 32-byte `client_random` (or `server_random`)
    /// starts within the first record.
    pub const RANDOM_START: usize = 11;
    /// `client_random` / `server_random` length, per RFC 8446
    /// §4.1.2 / §4.1.3.
    pub const RANDOM_LEN: usize = 32;
    /// Single byte holding the legacy_session_id length.
    pub const SID_LEN_BYTE_OFFSET: usize = 43;
    /// First byte of the legacy_session_id (when present).
    pub const SID_PAYLOAD_OFFSET: usize = 44;
    /// Minimum bytes we need before we can patch (i.e. read
    /// the sid length byte AND have its full 32-byte payload).
    pub const MIN_BYTES_TO_PATCH: usize = SID_PAYLOAD_OFFSET + 32;
}

/// Errors during rewrite. All map to `io::Error` for the
/// `AsyncRead`/`AsyncWrite` surface.
#[derive(thiserror::Error, Debug)]
pub enum RewriteError {
    /// First outbound record wasn't a TLS handshake (byte 0
    /// ≠ 0x16). Likely a misuse — wrapping a non-TLS stream.
    #[error("first outbound record is not a TLS handshake (type=0x{0:02x})")]
    NotHandshake(u8),
    /// rustls wrote a session_id length other than 32. In TLS
    /// 1.3 compatibility mode rustls always uses 32; if we see
    /// anything else either rustls changed its default (we'd
    /// need to relax this guard) or the stream isn't actually
    /// a TLS 1.3 client config.
    #[error("expected 32-byte legacy_session_id, got {0}")]
    UnexpectedSidLength(usize),
    /// EOF on the inbound stream before we collected enough
    /// bytes to patch the ServerHello.
    #[error(
        "inbound EOF before ServerHello session_id (got {got} bytes, need {})",
        offsets::MIN_BYTES_TO_PATCH
    )]
    InboundEofBeforePatch {
        /// How many bytes had arrived before EOF.
        got: usize,
    },
    /// EOF on the outbound writer trying to drain the patched
    /// ClientHello (a downstream socket closed mid-write).
    #[error("outbound downstream closed during patched ClientHello drain")]
    OutboundCloseDuringDrain,
}

impl From<RewriteError> for std::io::Error {
    fn from(e: RewriteError) -> Self {
        std::io::Error::other(e.to_string())
    }
}

/// State machine for the OUTBOUND direction (client→server).
/// The first record (ClientHello) is buffered, patched, and
/// flushed. Subsequent writes pass straight through.
#[derive(Debug)]
enum OutState {
    /// Accumulating the first record's bytes until we have
    /// enough to patch (≥ 76 bytes).
    Buffer(Vec<u8>),
    /// Patched record is being drained to the inner writer.
    /// `pos` is how many bytes have been accepted so far.
    Flush { bytes: Vec<u8>, pos: usize },
    /// Done patching — every subsequent write passes through.
    Done,
}

/// State machine for the INBOUND direction (server→client).
/// The first record (ServerHello) is buffered, restored, and
/// delivered. Subsequent reads pass straight through.
#[derive(Debug)]
enum InState {
    /// Waiting for outbound to finish so we know `R_orig` (the
    /// session_id rustls expected to see echoed back).
    AwaitingOutbound,
    /// Accumulating the first inbound record's bytes until we
    /// have enough to patch (≥ 76 bytes).
    Buffer {
        /// Bytes read from the inner stream so far.
        bytes: Vec<u8>,
        /// The 32-byte session_id rustls put on the wire
        /// before we rewrote it. We restore this into the
        /// ServerHello echo so rustls's equality check passes.
        orig_sid: [u8; ENCODED_SESSION_ID_LEN],
    },
    /// Patched record is being delivered to the inner reader's
    /// caller. `pos` is how many bytes the caller has consumed.
    Deliver { bytes: Vec<u8>, pos: usize },
    /// Done — pass-through.
    Done,
}

/// The wrapping AsyncRead+AsyncWrite stream. Holds the inner
/// IO + per-direction state + the operator-supplied PSK + a
/// frozen `unix_seconds` (we read it at construction so the
/// knock timestamp matches what the server's gate will see
/// in the same RTT — within the ±90s window regardless).
#[derive(Debug)]
pub struct KnockRewriteStream<S> {
    inner: S,
    psk: KnockPsk,
    now_unix_seconds: u64,
    out_state: OutState,
    in_state: InState,
}

impl<S> KnockRewriteStream<S> {
    /// Wrap `inner` with a knock-rewriter. `now_unix_seconds`
    /// should be `SystemTime::now()`'s unix-epoch seconds at
    /// the moment of connection setup; the knock is bound to
    /// it via HMAC and the server's gate accepts ±90 s of
    /// skew.
    pub fn new(inner: S, psk: KnockPsk, now_unix_seconds: u64) -> Self {
        Self {
            inner,
            psk,
            now_unix_seconds,
            out_state: OutState::Buffer(Vec::with_capacity(1024)),
            in_state: InState::AwaitingOutbound,
        }
    }

    /// Borrow the inner stream (e.g. for `peer_addr()`).
    pub fn inner(&self) -> &S {
        &self.inner
    }

    /// Consume and return the wrapped inner stream.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.inner
    }
}

/// Validate the buffered prefix is a TLS handshake whose
/// session_id is 32 bytes. Returns the patched record (in
/// place) plus the original 32 session_id bytes saved off.
fn patch_outbound_in_place(
    buf: &mut [u8],
    psk: &KnockPsk,
    now_unix_seconds: u64,
) -> Result<[u8; ENCODED_SESSION_ID_LEN], RewriteError> {
    if buf[0] != 0x16 {
        return Err(RewriteError::NotHandshake(buf[0]));
    }
    let sid_len = buf[offsets::SID_LEN_BYTE_OFFSET] as usize;
    if sid_len != ENCODED_SESSION_ID_LEN {
        return Err(RewriteError::UnexpectedSidLength(sid_len));
    }
    let mut client_random = [0u8; CLIENT_RANDOM_LEN];
    client_random
        .copy_from_slice(&buf[offsets::RANDOM_START..offsets::RANDOM_START + offsets::RANDOM_LEN]);
    // Save what rustls put there before we overwrite — needed
    // for the inbound ServerHello echo swap.
    let mut orig_sid = [0u8; ENCODED_SESSION_ID_LEN];
    orig_sid.copy_from_slice(
        &buf[offsets::SID_PAYLOAD_OFFSET..offsets::SID_PAYLOAD_OFFSET + ENCODED_SESSION_ID_LEN],
    );
    // Compute the knock token bound to (psk, client_random, now)
    // and encode it into 32 bytes (token||random_padding).
    let token = compute_knock(psk, &client_random, now_unix_seconds);
    let encoded = encode_session_id(&token);
    buf[offsets::SID_PAYLOAD_OFFSET..offsets::SID_PAYLOAD_OFFSET + ENCODED_SESSION_ID_LEN]
        .copy_from_slice(&encoded);
    Ok(orig_sid)
}

/// Restore the original session_id rustls expected into the
/// ServerHello's echo field.
fn patch_inbound_in_place(
    buf: &mut [u8],
    orig_sid: &[u8; ENCODED_SESSION_ID_LEN],
) -> Result<(), RewriteError> {
    if buf[0] != 0x16 {
        return Err(RewriteError::NotHandshake(buf[0]));
    }
    let sid_len = buf[offsets::SID_LEN_BYTE_OFFSET] as usize;
    if sid_len != ENCODED_SESSION_ID_LEN {
        return Err(RewriteError::UnexpectedSidLength(sid_len));
    }
    buf[offsets::SID_PAYLOAD_OFFSET..offsets::SID_PAYLOAD_OFFSET + ENCODED_SESSION_ID_LEN]
        .copy_from_slice(orig_sid);
    Ok(())
}

impl<S> AsyncWrite for KnockRewriteStream<S>
where
    S: AsyncWrite + AsyncRead + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        loop {
            match &mut this.out_state {
                OutState::Buffer(b) => {
                    // Append everything rustls handed us. We
                    // return Ready(Ok(buf.len())) to keep rustls
                    // moving forward; the actual wire write
                    // happens on the next poll (under Flush).
                    b.extend_from_slice(buf);
                    if b.len() >= offsets::MIN_BYTES_TO_PATCH {
                        // We have enough bytes to identify and
                        // patch the session_id. Do it now.
                        let orig_sid =
                            patch_outbound_in_place(&mut b[..], &this.psk, this.now_unix_seconds)?;
                        // Transition outbound to draining, and
                        // mark inbound ready for ServerHello
                        // patching (we need orig_sid to swap
                        // the echo back).
                        let mut taken = Vec::new();
                        std::mem::swap(&mut taken, b);
                        this.out_state = OutState::Flush {
                            bytes: taken,
                            pos: 0,
                        };
                        this.in_state = InState::Buffer {
                            bytes: Vec::with_capacity(1024),
                            orig_sid,
                        };
                    }
                    return Poll::Ready(Ok(buf.len()));
                }
                OutState::Flush { bytes, pos } => {
                    // Drain our patched buffer before accepting
                    // any new writes. We keep flushing until
                    // pos == bytes.len() OR inner returns Pending.
                    while *pos < bytes.len() {
                        match Pin::new(&mut this.inner).poll_write(cx, &bytes[*pos..]) {
                            Poll::Ready(Ok(0)) => {
                                return Poll::Ready(Err(
                                    RewriteError::OutboundCloseDuringDrain.into()
                                ));
                            }
                            Poll::Ready(Ok(n)) => *pos += n,
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                    this.out_state = OutState::Done;
                    // Loop continues — falls into Done branch
                    // which forwards `buf` to the inner writer.
                }
                OutState::Done => return Pin::new(&mut this.inner).poll_write(cx, buf),
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            match &mut this.out_state {
                OutState::Buffer(b) => {
                    if b.is_empty() {
                        // Nothing to flush, forward.
                        return Pin::new(&mut this.inner).poll_flush(cx);
                    }
                    if b.len() < offsets::MIN_BYTES_TO_PATCH {
                        // Partial bytes in the buffer but not
                        // enough to patch. rustls never flushes
                        // mid-ClientHello in practice, but if
                        // it does we have to wait for more
                        // writes (Pending is the safe answer).
                        return Poll::Pending;
                    }
                    let orig_sid =
                        patch_outbound_in_place(&mut b[..], &this.psk, this.now_unix_seconds)?;
                    let mut taken = Vec::new();
                    std::mem::swap(&mut taken, b);
                    this.out_state = OutState::Flush {
                        bytes: taken,
                        pos: 0,
                    };
                    this.in_state = InState::Buffer {
                        bytes: Vec::with_capacity(1024),
                        orig_sid,
                    };
                }
                OutState::Flush { bytes, pos } => {
                    while *pos < bytes.len() {
                        match Pin::new(&mut this.inner).poll_write(cx, &bytes[*pos..]) {
                            Poll::Ready(Ok(0)) => {
                                return Poll::Ready(Err(
                                    RewriteError::OutboundCloseDuringDrain.into()
                                ));
                            }
                            Poll::Ready(Ok(n)) => *pos += n,
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                    this.out_state = OutState::Done;
                }
                OutState::Done => return Pin::new(&mut this.inner).poll_flush(cx),
            }
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // Best-effort drain of any pending patched bytes before
        // shutdown. We loop on poll_flush until it completes
        // (the OutState::Done branch then forwards to inner).
        // Note: we hold `self` as Pin<&mut Self> the entire time
        // and use Pin::as_mut to reborrow — no unsafe needed.
        loop {
            let out_state_done = matches!(self.out_state, OutState::Done);
            if out_state_done {
                return Pin::new(&mut self.inner).poll_shutdown(cx);
            }
            match self.as_mut().poll_flush(cx) {
                Poll::Ready(Ok(())) => continue,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S> AsyncRead for KnockRewriteStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            match &mut this.in_state {
                InState::AwaitingOutbound => {
                    // rustls drives reads after writing the
                    // ClientHello. If the caller called read
                    // before any write completed, we must wait
                    // — but poll_read returning Pending
                    // without registering a waker is wrong.
                    // Forward to inner so the inner socket
                    // registers wakeup on incoming data; once
                    // poll_write completes the ClientHello,
                    // a subsequent poll_read will land in
                    // Buffer mode.
                    //
                    // In practice rustls always writes its
                    // ClientHello (which moves us to InState::
                    // Buffer) before issuing the first read.
                    return Pin::new(&mut this.inner).poll_read(cx, out);
                }
                InState::Buffer { bytes, orig_sid } => {
                    // Read into a scratch buffer; if we get
                    // enough to patch the ServerHello, swap
                    // the echo and transition to Deliver.
                    let mut scratch = [0u8; 2048];
                    let mut sb = ReadBuf::new(&mut scratch);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut sb) {
                        Poll::Ready(Ok(())) => {
                            let n = sb.filled().len();
                            if n == 0 {
                                return Poll::Ready(Err(RewriteError::InboundEofBeforePatch {
                                    got: bytes.len(),
                                }
                                .into()));
                            }
                            bytes.extend_from_slice(sb.filled());
                            if bytes.len() >= offsets::MIN_BYTES_TO_PATCH {
                                patch_inbound_in_place(&mut bytes[..], orig_sid)?;
                                let mut taken = Vec::new();
                                std::mem::swap(&mut taken, bytes);
                                this.in_state = InState::Deliver {
                                    bytes: taken,
                                    pos: 0,
                                };
                                // Loop falls into Deliver branch.
                            }
                            // else: loop again, read more.
                        }
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    }
                }
                InState::Deliver { bytes, pos } => {
                    let avail = &bytes[*pos..];
                    let want = avail.len().min(out.remaining());
                    out.put_slice(&avail[..want]);
                    *pos += want;
                    if *pos >= bytes.len() {
                        this.in_state = InState::Done;
                    }
                    return Poll::Ready(Ok(()));
                }
                InState::Done => return Pin::new(&mut this.inner).poll_read(cx, out),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proteus_handshake::knock::{KnockPsk, KNOCK_PSK_LEN};
    use std::io::Cursor;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn psk() -> KnockPsk {
        KnockPsk::from_bytes([0xA5; KNOCK_PSK_LEN])
    }

    /// Build a minimal-but-valid TLS 1.3 ClientHello/ServerHello
    /// record with a 32-byte session_id.
    fn craft_record(handshake_type: u8, random: &[u8; 32], session_id_32: &[u8; 32]) -> Vec<u8> {
        let mut hs_body = Vec::with_capacity(128);
        hs_body.extend_from_slice(&[0x03, 0x03]); // legacy_version
        hs_body.extend_from_slice(random);
        hs_body.push(32); // sid length
        hs_body.extend_from_slice(session_id_32);
        hs_body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher_suites
        hs_body.extend_from_slice(&[0x01, 0x00]); // compression
        hs_body.extend_from_slice(&[0x00, 0x00]); // empty extensions

        let hs_len = hs_body.len();
        let mut hs = Vec::with_capacity(4 + hs_len);
        hs.push(handshake_type);
        hs.extend_from_slice(&[
            ((hs_len >> 16) & 0xff) as u8,
            ((hs_len >> 8) & 0xff) as u8,
            (hs_len & 0xff) as u8,
        ]);
        hs.extend_from_slice(&hs_body);

        let rec_len = hs.len();
        let mut rec = Vec::with_capacity(5 + rec_len);
        rec.extend_from_slice(&[0x16, 0x03, 0x01]);
        rec.extend_from_slice(&[((rec_len >> 8) & 0xff) as u8, (rec_len & 0xff) as u8]);
        rec.extend_from_slice(&hs);
        rec
    }

    /// Mock IO holding outbound bytes captured into a Vec, and
    /// inbound bytes scripted by the test.
    #[derive(Debug)]
    struct MockIo {
        captured_out: Arc<Mutex<Vec<u8>>>,
        scripted_in: Vec<u8>,
        in_pos: usize,
    }

    impl MockIo {
        fn new(scripted_in: Vec<u8>) -> (Self, Arc<Mutex<Vec<u8>>>) {
            let captured = Arc::new(Mutex::new(Vec::new()));
            let me = MockIo {
                captured_out: Arc::clone(&captured),
                scripted_in,
                in_pos: 0,
            };
            (me, captured)
        }
    }

    impl AsyncWrite for MockIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.captured_out.lock().unwrap().extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncRead for MockIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let remaining = self.scripted_in.len() - self.in_pos;
            if remaining == 0 {
                return Poll::Ready(Ok(())); // EOF
            }
            let want = remaining.min(buf.remaining());
            let start = self.in_pos;
            let end = start + want;
            buf.put_slice(&self.scripted_in[start..end]);
            self.in_pos = end;
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn outbound_patches_session_id_with_knock() {
        let psk = psk();
        let now = 1_715_900_000u64;
        let client_random = [0x11u8; 32];
        let rustls_sid = [0x22u8; 32]; // what "rustls" generated
        let ch = craft_record(0x01, &client_random, &rustls_sid);

        let (io, captured) = MockIo::new(Vec::new());
        let mut wrapper = KnockRewriteStream::new(io, psk.clone(), now);
        wrapper.write_all(&ch).await.unwrap();
        wrapper.flush().await.unwrap();

        let out = captured.lock().unwrap().clone();
        // Length unchanged.
        assert_eq!(out.len(), ch.len(), "patched record changed length");
        // First 44 bytes unchanged (record hdr + hs hdr + version + random + sid_len).
        assert_eq!(&out[..44], &ch[..44]);
        // After 76 unchanged.
        assert_eq!(&out[76..], &ch[76..]);
        // session_id rewritten.
        assert_ne!(&out[44..76], &rustls_sid[..]);
        // First 16 bytes of patched sid is the knock token —
        // verify by re-running compute_knock.
        let expected_token = compute_knock(&psk, &client_random, now);
        assert_eq!(&out[44..60], &expected_token[..]);
    }

    #[tokio::test]
    async fn outbound_rejects_non_handshake_first_byte() {
        let mut bad = vec![0x17u8]; // 0x17 = appdata, not handshake
        bad.extend_from_slice(&[0x03, 0x03, 0x00, 0x10]);
        bad.extend_from_slice(&[0u8; 100]); // pad to >= 76 bytes total
        let (io, _captured) = MockIo::new(Vec::new());
        let mut wrapper = KnockRewriteStream::new(io, psk(), 1_715_900_000);
        let err = wrapper.write_all(&bad).await.err();
        assert!(err.is_some(), "expected error on non-handshake first byte");
    }

    #[tokio::test]
    async fn outbound_rejects_sid_length_not_32() {
        // Craft a record with sid_len = 16 (not 32). Pad with
        // a bogus extensions blob so the total record is > 76
        // bytes — MIN_BYTES_TO_PATCH — and the rewriter actually
        // reaches the patch step (and rejects).
        let mut rec = vec![0x16u8, 0x03, 0x01];
        let mut hs_body = Vec::new();
        hs_body.extend_from_slice(&[0x03, 0x03]);
        hs_body.extend_from_slice(&[0x33u8; 32]); // random
        hs_body.push(16); // sid_len = 16
        hs_body.extend_from_slice(&[0x44u8; 16]); // sid
        hs_body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // ciphers
        hs_body.extend_from_slice(&[0x01, 0x00]); // comp
        hs_body.extend_from_slice(&[0x00, 0x40]); // ext_count = 64 bytes
        hs_body.extend_from_slice(&[0x55u8; 64]); // bogus extension bytes
        let hs_len = hs_body.len();
        let mut hs = vec![0x01u8];
        hs.extend_from_slice(&[
            ((hs_len >> 16) & 0xff) as u8,
            ((hs_len >> 8) & 0xff) as u8,
            (hs_len & 0xff) as u8,
        ]);
        hs.extend_from_slice(&hs_body);
        let rec_len = hs.len();
        rec.extend_from_slice(&[((rec_len >> 8) & 0xff) as u8, (rec_len & 0xff) as u8]);
        rec.extend_from_slice(&hs);
        assert!(
            rec.len() >= 76,
            "test setup: record must be >= 76 bytes to hit patch step"
        );

        let (io, _captured) = MockIo::new(Vec::new());
        let mut wrapper = KnockRewriteStream::new(io, psk(), 1_715_900_000);
        let err = wrapper.write_all(&rec).await.err();
        assert!(err.is_some(), "expected error on sid_len != 32 (got Ok)");
    }

    #[tokio::test]
    async fn inbound_restores_echoed_session_id_to_rustls_original() {
        let psk = psk();
        let now = 1_715_900_000u64;
        let client_random = [0xAAu8; 32];
        let rustls_sid = [0xBBu8; 32];
        let server_random = [0xCCu8; 32];
        let ch = craft_record(0x01, &client_random, &rustls_sid);

        // The "server" echoes whatever it received (our patched sid).
        let token = compute_knock(&psk, &client_random, now);
        let encoded = encode_session_id(&token);
        let sh = craft_record(0x02, &server_random, &encoded);

        let (io, _captured) = MockIo::new(sh.clone());
        let mut wrapper = KnockRewriteStream::new(io, psk, now);
        // Write ClientHello — needed to populate `orig_sid`.
        wrapper.write_all(&ch).await.unwrap();
        wrapper.flush().await.unwrap();

        // Read ServerHello back.
        let mut got = vec![0u8; sh.len()];
        let mut read = 0;
        while read < sh.len() {
            let n = wrapper.read(&mut got[read..]).await.unwrap();
            if n == 0 {
                break;
            }
            read += n;
        }
        got.truncate(read);
        // Restored bytes [44..76] should equal rustls's ORIGINAL
        // session_id (not the wire bytes the "server" echoed).
        assert_eq!(&got[44..76], &rustls_sid[..]);
        // Other bytes unchanged from what the "server" sent.
        assert_eq!(&got[..44], &sh[..44]);
        assert_eq!(&got[76..], &sh[76..]);
    }

    #[tokio::test]
    async fn outbound_passthrough_after_first_record() {
        // After the first record, subsequent writes flow
        // unmodified.
        let psk = psk();
        let now = 1_715_900_000u64;
        let cr = [0xDDu8; 32];
        let sid = [0xEEu8; 32];
        let ch = craft_record(0x01, &cr, &sid);

        let (io, captured) = MockIo::new(Vec::new());
        let mut wrapper = KnockRewriteStream::new(io, psk, now);
        wrapper.write_all(&ch).await.unwrap();
        wrapper.flush().await.unwrap();

        let follow_on = vec![0xF0u8; 200];
        wrapper.write_all(&follow_on).await.unwrap();
        wrapper.flush().await.unwrap();

        let out = captured.lock().unwrap().clone();
        assert_eq!(out.len(), ch.len() + follow_on.len());
        assert_eq!(&out[ch.len()..], &follow_on[..]);
    }

    #[tokio::test]
    async fn outbound_handles_writes_split_across_polls() {
        // rustls in theory could split the ClientHello across
        // multiple write calls. Each chunk should be buffered
        // until we have enough to patch.
        let psk = psk();
        let now = 1_715_900_000u64;
        let cr = [0x77u8; 32];
        let sid = [0x88u8; 32];
        let ch = craft_record(0x01, &cr, &sid);

        let (io, captured) = MockIo::new(Vec::new());
        let mut wrapper = KnockRewriteStream::new(io, psk.clone(), now);
        // Write byte-by-byte for the first 80 bytes (well past
        // session_id), then the rest in one go.
        for byte in &ch[..80] {
            wrapper.write_all(std::slice::from_ref(byte)).await.unwrap();
        }
        wrapper.write_all(&ch[80..]).await.unwrap();
        wrapper.flush().await.unwrap();

        let out = captured.lock().unwrap().clone();
        assert_eq!(out.len(), ch.len());
        let expected_token = compute_knock(&psk, &cr, now);
        assert_eq!(&out[44..60], &expected_token[..]);
        assert_eq!(&out[60..76].len(), &16); // padding present
        assert_eq!(&out[..44], &ch[..44]);
        assert_eq!(&out[76..], &ch[76..]);
    }

    #[tokio::test]
    async fn inbound_passthrough_after_first_record() {
        let psk = psk();
        let now = 1_715_900_000u64;
        let cr = [0x11u8; 32];
        let sid = [0x22u8; 32];
        let ch = craft_record(0x01, &cr, &sid);
        let token = compute_knock(&psk, &cr, now);
        let encoded = encode_session_id(&token);
        let sr = [0x44u8; 32];
        let sh = craft_record(0x02, &sr, &encoded);
        let trailing = vec![0x99u8; 500];

        let mut scripted = sh.clone();
        scripted.extend_from_slice(&trailing);

        let (io, _c) = MockIo::new(scripted.clone());
        let mut wrapper = KnockRewriteStream::new(io, psk, now);
        wrapper.write_all(&ch).await.unwrap();
        wrapper.flush().await.unwrap();

        let mut got = vec![0u8; scripted.len()];
        let mut read = 0;
        while read < scripted.len() {
            let n = wrapper.read(&mut got[read..]).await.unwrap();
            if n == 0 {
                break;
            }
            read += n;
        }
        got.truncate(read);
        assert_eq!(read, scripted.len());
        assert_eq!(&got[44..76], &sid[..]);
        assert_eq!(&got[sh.len()..], &trailing[..]);
    }

    #[tokio::test]
    async fn knock_token_is_recoverable_by_server_decode() {
        // The smoke test that ties iter 1-4 and 9 together:
        // outbound patch -> wire bytes -> server-side decode.
        use proteus_handshake::knock_wire::decode_and_verify_session_id;
        let psk = psk();
        let now = 1_715_900_000u64;
        let cr = [0x5Au8; 32];
        let sid = [0xA5u8; 32];
        let ch = craft_record(0x01, &cr, &sid);

        let (io, captured) = MockIo::new(Vec::new());
        let mut wrapper = KnockRewriteStream::new(io, psk.clone(), now);
        wrapper.write_all(&ch).await.unwrap();
        wrapper.flush().await.unwrap();

        let out = captured.lock().unwrap().clone();
        let on_wire_sid = &out[44..76];
        // Server's verifier should accept this.
        decode_and_verify_session_id(&psk, &cr, on_wire_sid, now).expect("knock must verify");
    }

    #[test]
    fn into_inner_recovers_the_underlying_stream() {
        let psk = psk();
        let now = 1_715_900_000u64;
        let inner: Cursor<Vec<u8>> = Cursor::new(Vec::new());
        let wrapper = KnockRewriteStream::new(inner, psk, now);
        let _recovered: Cursor<Vec<u8>> = wrapper.into_inner();
    }
}
