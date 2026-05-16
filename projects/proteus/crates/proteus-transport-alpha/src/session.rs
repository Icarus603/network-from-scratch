//! Post-handshake AEAD record session with **per-direction ratchet**.
//!
//! After both sides reach the `Connected` state (spec §5.1), all traffic
//! is exchanged as length-prefixed records (spec §4.2) whose payload is
//! AEAD-protected. The `aad` is the 8-byte big-endian `(epoch:24 || seqnum:40)`
//! header; the nonce is `iv XOR (epoch||seqnum)` (spec §4.5.2).
//!
//! ## Symmetric ratchet (this build)
//!
//! Every [`RATCHET_BYTES`] of application data sent on a direction, both
//! sides advance the direction's traffic secret:
//!
//! ```text
//! new_secret = HKDF-Expand-Label(current_secret, "proteus ratchet v1", "", 32)
//! key, iv    = derive_keys(new_secret)
//! epoch     ← epoch + 1
//! seqnum    ← 0
//! ```
//!
//! Properties:
//! - **Forward secrecy**: HKDF is forward-only, so a compromised
//!   `current_secret` at epoch N cannot recover any `secret_(N-k)`.
//! - **PCS-weak**: a compromised `current_secret` allows recovery of all
//!   future secrets *if the adversary keeps observing the ratchet
//!   schedule*; full PCS-strong needs the asymmetric DH ratchet which is
//!   wired in M2.
//!
//! Compared to VLESS+REALITY (which never rotates the AEAD key for the
//! entire session): a single key-leak in VLESS+REALITY exposes the entire
//! conversation; in Proteus, only the bytes between two ratchet boundaries
//! are exposed.
//!
//! ## Ratchet trigger
//!
//! Trigger conditions, in priority order:
//! 1. Sender has sent ≥ [`RATCHET_BYTES`] bytes since the last ratchet.
//! 2. Sender has sent ≥ [`RATCHET_RECORDS`] records since the last ratchet.
//!
//! Either trigger emits a [`alpha::RECORD_RATCHET`] frame containing the
//! new epoch number; the receiver, on seeing the matching epoch, advances
//! its own receiving direction.

use proteus_crypto::key_schedule::DirectionKeys;
use proteus_crypto::{aead, kdf};
use proteus_spec::SEQNUM_MAX;
use proteus_wire::alpha;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufWriter};
use zeroize::Zeroizing;

use crate::error::{AlphaError, AlphaResult};
use crate::metrics::SessionMetrics;

/// Number of application bytes per direction between ratchets.
///
/// 4 MiB chosen as a balance: per the Russian TSPU 15-20 KB freeze
/// observation (spec §11.13), 5 MB is the spec's normative trigger; we
/// pick a slightly smaller value to stay comfortably under for clients
/// that consume close to the limit.
pub const RATCHET_BYTES: u64 = 4 * 1024 * 1024;

/// Number of records per direction between ratchets (fallback when
/// records are very small / chatty).
pub const RATCHET_RECORDS: u64 = 16_384;

/// Upper bound on the per-session receive buffer. Any peer that wedges
/// more bytes than this without us being able to parse a frame is
/// treated as malicious and the session is closed. 16 MiB lets us
/// tolerate the largest legitimate single-record (e.g. a multi-MB
/// upstream chunk) plus generous slack for TCP coalescing, while
/// putting a firm ceiling on memory exhaustion attacks.
pub const RX_BUF_HARD_CAP: usize = 16 * 1024 * 1024;

/// Send-side TX buffer capacity. 64 KiB matches typical TCP_NOTSENT_LOWAT
/// + lets us coalesce a handful of records per syscall.
pub const TX_BUF_CAPACITY: usize = 64 * 1024;

/// Sending half of an established session.
///
/// Generic over the underlying writer so the same session machinery
/// works on plain TCP (`OwnedWriteHalf`) and TLS-wrapped TCP
/// (`tokio::io::WriteHalf<TlsStream<TcpStream>>`).
pub struct AlphaSender<W: AsyncWrite + Unpin = tokio::net::tcp::OwnedWriteHalf> {
    write: BufWriter<W>,
    /// Current epoch's AEAD key + iv.
    keys: DirectionKeys,
    /// Current traffic secret (used to derive the next epoch's keys).
    secret: Zeroizing<[u8; 32]>,
    /// 24-bit epoch counter (within u32 for arithmetic ergonomics).
    epoch: u32,
    /// 40-bit per-epoch monotonic seqnum.
    seqnum: u64,
    /// Bytes sent in this epoch (drives ratchet trigger).
    bytes_in_epoch: u64,
    /// Records sent in this epoch.
    records_in_epoch: u64,
    /// Shared metrics counter.
    metrics: std::sync::Arc<SessionMetrics>,
}

impl<W: AsyncWrite + Unpin> AlphaSender<W> {
    pub(crate) fn new(
        write: W,
        keys: DirectionKeys,
        secret: Zeroizing<[u8; 32]>,
        metrics: std::sync::Arc<SessionMetrics>,
    ) -> Self {
        Self {
            write: BufWriter::with_capacity(TX_BUF_CAPACITY, write),
            keys,
            secret,
            epoch: 0,
            seqnum: 0,
            bytes_in_epoch: 0,
            records_in_epoch: 0,
            metrics,
        }
    }

    /// Flush any buffered frames to the kernel TCP buffer.
    ///
    /// Call this at every logical "batch boundary" (e.g. after copying
    /// one chunk of upstream bytes through). The bidirectional relay
    /// loops in `proteus-server` and `proteus-client` flush after each
    /// read-from-upstream → send-record pair, which yields a clean
    /// vectored-write per upstream chunk.
    pub async fn flush(&mut self) -> AlphaResult<()> {
        self.write.flush().await.map_err(AlphaError::Io)
    }

    /// Encrypt + frame + send `payload`. Returns the seqnum used.
    ///
    /// May trigger a ratchet before sending if the byte / record budget
    /// has been exhausted.
    pub async fn send_record(&mut self, payload: &[u8]) -> AlphaResult<u64> {
        if self.should_ratchet() {
            self.send_ratchet_frame().await?;
        }
        if self.seqnum > SEQNUM_MAX {
            // The 40-bit seqnum space inside one epoch was exhausted. Force a
            // ratchet so the next packet starts at seqnum=0 of a new epoch.
            self.send_ratchet_frame().await?;
        }
        let combined = self.combined();
        let aad = combined.to_be_bytes();
        let ct = aead::seal(&self.keys.key, &self.keys.iv, combined, &aad, payload)?;
        let frame = alpha::encode_record(alpha::RECORD_DATA, &ct);
        self.write.write_all(&frame).await?;
        let used = self.seqnum;
        self.seqnum = self.seqnum.saturating_add(1);
        self.bytes_in_epoch = self.bytes_in_epoch.saturating_add(payload.len() as u64);
        self.records_in_epoch = self.records_in_epoch.saturating_add(1);
        self.metrics.record_tx(payload.len() as u64);
        Ok(used)
    }

    fn should_ratchet(&self) -> bool {
        self.bytes_in_epoch >= RATCHET_BYTES || self.records_in_epoch >= RATCHET_RECORDS
    }

    fn combined(&self) -> u64 {
        (u64::from(self.epoch) << 40) | self.seqnum
    }

    /// Compute the next epoch's secret + AEAD direction keys, advance
    /// counters, and emit a RATCHET record on the wire announcing the
    /// new epoch. The frame itself is AEAD-protected under the *current*
    /// key with `seqnum = SEQNUM_MAX` (a reserved slot we never use for
    /// DATA), so the receiver must decrypt with the old key, then
    /// install the new key for everything after.
    async fn send_ratchet_frame(&mut self) -> AlphaResult<()> {
        // 1. Derive the new secret and keys.
        let new_secret = derive_ratchet_secret(&self.secret)?;
        let new_keys = direction_keys_from_secret(&new_secret)?;
        let new_epoch = self.epoch.saturating_add(1);

        // 2. Send a RATCHET frame under the OLD key, using a reserved
        //    sentinel seqnum so that the receiver can distinguish this
        //    from regular DATA without an explicit type field.
        //    Sentinel = SEQNUM_MAX (the very last per-epoch seqnum); we
        //    never emit DATA on this seqnum because `send_record` would
        //    force a ratchet first.
        let sentinel = (u64::from(self.epoch) << 40) | SEQNUM_MAX;
        let aad = sentinel.to_be_bytes();
        let payload = new_epoch.to_be_bytes(); // 4 bytes, just the new epoch.
        let ct = aead::seal(&self.keys.key, &self.keys.iv, sentinel, &aad, &payload)?;
        let frame = alpha::encode_record(alpha::RECORD_RATCHET, &ct);
        self.write.write_all(&frame).await?;

        // 3. Install the new state.
        self.keys = new_keys;
        self.secret = new_secret;
        self.epoch = new_epoch;
        self.seqnum = 0;
        self.bytes_in_epoch = 0;
        self.records_in_epoch = 0;
        self.metrics.record_ratchet();
        Ok(())
    }

    /// Send a CLOSE record, flush, then shut down the write half.
    ///
    /// `error_code` follows spec §26.1. `reason` is opaque-bytes (truncated
    /// to 255 bytes for the on-wire `u8` length prefix).
    pub async fn send_close(&mut self, error_code: u8, reason: &[u8]) -> AlphaResult<()> {
        let reason_len = reason.len().min(255) as u8;
        let mut pt = Vec::with_capacity(2 + reason_len as usize);
        pt.push(error_code);
        pt.push(reason_len);
        pt.extend_from_slice(&reason[..reason_len as usize]);

        let combined = self.combined();
        let aad = combined.to_be_bytes();
        let ct = aead::seal(&self.keys.key, &self.keys.iv, combined, &aad, &pt)?;
        let frame = alpha::encode_record(alpha::RECORD_CLOSE, &ct);
        self.write.write_all(&frame).await?;
        self.write.flush().await?;
        // After CLOSE we MUST NOT send more records on this direction
        // (spec). Burn the seqnum so any accidental send_record fails
        // with `SeqnumExhausted` instead of nonce reuse.
        self.seqnum = SEQNUM_MAX + 1;
        self.metrics.record_close_sent();
        Ok(())
    }

    /// Gracefully close the write side, flushing any buffered records first.
    pub async fn shutdown(mut self) -> std::io::Result<()> {
        self.write.flush().await?;
        self.write.shutdown().await
    }
}

/// Receiving half of an established session.
pub struct AlphaReceiver<R: AsyncRead + Unpin = tokio::net::tcp::OwnedReadHalf> {
    read: R,
    keys: DirectionKeys,
    secret: Zeroizing<[u8; 32]>,
    epoch: u32,
    next_seqnum: u64,
    rx_buf: Vec<u8>,
    metrics: std::sync::Arc<SessionMetrics>,
    last_close_code: Option<u8>,
    last_close_reason: Option<Vec<u8>>,
}

impl<R: AsyncRead + Unpin> AlphaReceiver<R> {
    #[allow(dead_code)]
    pub(crate) fn new(
        read: R,
        keys: DirectionKeys,
        secret: Zeroizing<[u8; 32]>,
        metrics: std::sync::Arc<SessionMetrics>,
    ) -> Self {
        Self::with_prefix(read, keys, secret, metrics, Vec::with_capacity(8192))
    }

    /// Like `new`, but seeds the receive buffer with bytes already read
    /// off the wire (e.g. tail bytes from a previous handshake read).
    pub(crate) fn with_prefix(
        read: R,
        keys: DirectionKeys,
        secret: Zeroizing<[u8; 32]>,
        metrics: std::sync::Arc<SessionMetrics>,
        prefix: Vec<u8>,
    ) -> Self {
        Self {
            read,
            keys,
            secret,
            epoch: 0,
            next_seqnum: 0,
            rx_buf: prefix,
            metrics,
            last_close_code: None,
            last_close_reason: None,
        }
    }

    /// Block until one full DATA record is available, then decrypt and
    /// return the plaintext. RATCHET records are consumed internally
    /// and the call resumes reading the next frame. CLOSE records
    /// surface as `Ok(None)` after recording the peer's stated reason.
    pub async fn recv_record(&mut self) -> AlphaResult<Option<Vec<u8>>> {
        loop {
            match alpha::decode_frame(&self.rx_buf) {
                Ok((frame, consumed)) => {
                    let kind = frame.kind;
                    let body = frame.body.to_vec();
                    self.rx_buf.drain(..consumed);
                    match kind {
                        alpha::RECORD_DATA => {
                            let combined = (u64::from(self.epoch) << 40) | self.next_seqnum;
                            let aad = combined.to_be_bytes();
                            match aead::open(&self.keys.key, &self.keys.iv, combined, &aad, &body) {
                                Ok(pt) => {
                                    self.next_seqnum = self.next_seqnum.saturating_add(1);
                                    let bytes = pt.as_slice().to_vec();
                                    self.metrics.record_rx(bytes.len() as u64);
                                    return Ok(Some(bytes));
                                }
                                Err(_) => {
                                    self.metrics.record_aead_drop();
                                    // Spec §11.16 silent drop on data plane.
                                    continue;
                                }
                            }
                        }
                        alpha::RECORD_RATCHET => {
                            self.apply_ratchet(&body)?;
                            continue;
                        }
                        alpha::RECORD_CLOSE => {
                            let combined = (u64::from(self.epoch) << 40) | self.next_seqnum;
                            let aad = combined.to_be_bytes();
                            if let Ok(pt) =
                                aead::open(&self.keys.key, &self.keys.iv, combined, &aad, &body)
                            {
                                let pt = pt.as_slice();
                                if pt.len() >= 2 {
                                    self.last_close_code = Some(pt[0]);
                                    let reason_len = pt[1] as usize;
                                    if pt.len() >= 2 + reason_len {
                                        self.last_close_reason =
                                            Some(pt[2..2 + reason_len].to_vec());
                                    }
                                }
                                self.metrics.record_close_recv();
                                return Ok(None);
                            }
                            // CLOSE failed authentication — drop silently
                            // (spec §11.16).
                            self.metrics.record_aead_drop();
                            continue;
                        }
                        _ => {
                            // Unknown record type → silently ignore per
                            // spec §12.2.
                            continue;
                        }
                    }
                }
                Err(proteus_wire::WireError::Short { .. }) => {}
                Err(e) => return Err(e.into()),
            }
            // Refuse to grow the receive buffer past the hard cap.
            // This catches both garbage-flood attacks and a peer that
            // sends a single record larger than we will ever accept.
            if self.rx_buf.len() >= RX_BUF_HARD_CAP {
                self.metrics.record_aead_drop();
                return Err(AlphaError::Closed);
            }
            let mut tmp = [0u8; 4096];
            let n = self.read.read(&mut tmp).await?;
            if n == 0 {
                return Ok(None);
            }
            self.rx_buf.extend_from_slice(&tmp[..n]);
        }
    }

    /// If the peer sent a CLOSE, return the error code they declared.
    #[must_use]
    pub fn last_close_code(&self) -> Option<u8> {
        self.last_close_code
    }

    /// If the peer sent a CLOSE, return any reason phrase they included.
    #[must_use]
    pub fn last_close_reason(&self) -> Option<&[u8]> {
        self.last_close_reason.as_deref()
    }

    fn apply_ratchet(&mut self, body: &[u8]) -> AlphaResult<()> {
        // body = AEAD(old_key, nonce=combined(old_epoch, SEQNUM_MAX), aad=that, pt=new_epoch BE-u32)
        let combined = (u64::from(self.epoch) << 40) | SEQNUM_MAX;
        let aad = combined.to_be_bytes();
        let pt = aead::open(&self.keys.key, &self.keys.iv, combined, &aad, body)
            .map_err(|_| AlphaError::BadServerFinished)?; // misuse of an existing variant; treat as fatal
        if pt.as_slice().len() != 4 {
            return Err(AlphaError::BadServerFinished);
        }
        let new_epoch = u32::from_be_bytes([
            pt.as_slice()[0],
            pt.as_slice()[1],
            pt.as_slice()[2],
            pt.as_slice()[3],
        ]);
        if new_epoch != self.epoch.saturating_add(1) {
            return Err(AlphaError::BadServerFinished);
        }
        let new_secret = derive_ratchet_secret(&self.secret)?;
        let new_keys = direction_keys_from_secret(&new_secret)?;
        self.keys = new_keys;
        self.secret = new_secret;
        self.epoch = new_epoch;
        self.next_seqnum = 0;
        self.metrics.record_ratchet();
        Ok(())
    }
}

/// Symmetric ratchet step: `new = HKDF-Expand-Label(current, "proteus ratchet v1", "", 32)`.
fn derive_ratchet_secret(current: &[u8; 32]) -> AlphaResult<Zeroizing<[u8; 32]>> {
    let mut next = Zeroizing::new([0u8; 32]);
    kdf::expand_label(current, proteus_spec::hkdf_label::RATCHET, b"", &mut *next)?;
    Ok(next)
}

/// Re-derive `(key, iv)` from a freshly-installed traffic secret. Mirrors
/// `proteus_crypto::key_schedule::direction_keys_from_secret` but kept
/// local because that function is private.
fn direction_keys_from_secret(secret: &[u8; 32]) -> AlphaResult<DirectionKeys> {
    let mut key = Zeroizing::new([0u8; 32]);
    let mut iv = Zeroizing::new([0u8; 12]);
    kdf::expand_label(secret, b"key", b"", &mut *key)?;
    kdf::expand_label(secret, b"iv", b"", &mut *iv)?;
    Ok(DirectionKeys { key, iv })
}

/// A full bidirectional α-profile session, split for separate task ownership.
pub struct AlphaSession<
    R: AsyncRead + Unpin = tokio::net::tcp::OwnedReadHalf,
    W: AsyncWrite + Unpin = tokio::net::tcp::OwnedWriteHalf,
> {
    /// Send half.
    pub sender: AlphaSender<W>,
    /// Receive half.
    pub receiver: AlphaReceiver<R>,
    /// Per-session metrics snapshot accessor.
    pub metrics: std::sync::Arc<SessionMetrics>,
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> AlphaSession<R, W> {
    #[allow(dead_code)]
    pub(crate) fn new(
        write: W,
        read: R,
        send_keys: DirectionKeys,
        recv_keys: DirectionKeys,
        send_secret: Zeroizing<[u8; 32]>,
        recv_secret: Zeroizing<[u8; 32]>,
    ) -> Self {
        Self::with_prefix(
            write,
            read,
            send_keys,
            recv_keys,
            send_secret,
            recv_secret,
            Vec::new(),
        )
    }

    /// Same as `new`, but seeds the receiver's buffer with bytes already
    /// drained from the wire during the handshake — guarantees we do
    /// not lose any post-handshake DATA records that arrived coalesced
    /// with the final handshake frame.
    pub(crate) fn with_prefix(
        write: W,
        read: R,
        send_keys: DirectionKeys,
        recv_keys: DirectionKeys,
        send_secret: Zeroizing<[u8; 32]>,
        recv_secret: Zeroizing<[u8; 32]>,
        rx_prefix: Vec<u8>,
    ) -> Self {
        let metrics = std::sync::Arc::new(SessionMetrics::default());
        Self {
            sender: AlphaSender::new(
                write,
                send_keys,
                send_secret,
                std::sync::Arc::clone(&metrics),
            ),
            receiver: AlphaReceiver::with_prefix(
                read,
                recv_keys,
                recv_secret,
                std::sync::Arc::clone(&metrics),
                rx_prefix,
            ),
            metrics,
        }
    }
}
