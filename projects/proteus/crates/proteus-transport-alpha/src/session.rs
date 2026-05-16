//! Post-handshake AEAD record session with **per-direction ratchet**.
//!
//! After both sides reach the `Connected` state (spec §5.1), all traffic
//! is exchanged as length-prefixed records (spec §4.2) whose payload is
//! AEAD-protected. The `aad` is the 8-byte big-endian `(epoch:24 || seqnum:40)`
//! header; the nonce is `iv XOR (epoch||seqnum)` (spec §4.5.2).
//!
//! ## Hybrid ratchet (one-shot asymmetric DH heal + continuous symmetric)
//!
//! On the FIRST [`RATCHET_BYTES`] boundary of a direction, the sender
//! performs a fresh asymmetric Diffie-Hellman ratchet step — a Signal-
//! style heal that recovers from any pre-first-ratchet compromise.
//! Every subsequent ratchet event on the same direction is a pure
//! symmetric HKDF step. The split happens because a continuous
//! Double Ratchet requires strict request/response synchronization
//! that pipelined ratchets (256 chunks in flight before the peer
//! responds) cannot maintain without an extra round of state-sync —
//! one heal is a clean tradeoff that delivers strict-improvement
//! security over the prior build with zero risk of pipelining races.
//!
//! ### Sender state machine (per direction)
//!
//! ```text
//! ratchet_event:
//!   if has bootstrap (dh_sk, peer_dh_pub):
//!       my_dh_sk_new ← fresh ephemeral X25519
//!       dh_ikm ← X25519(my_dh_sk_new, peer_dh_pub)
//!       new_secret ← HKDF-Expand-Label(current_secret,
//!                                       "proteus dh-ratchet v1",
//!                                       dh_ikm, 32)
//!       body ← (new_epoch:u32_be || my_dh_pub_new:[u8;32])   # 36 B
//!       burn bootstrap
//!   else:
//!       new_secret ← HKDF-Expand-Label(current_secret,
//!                                       "proteus ratchet v1",
//!                                       "", 32)
//!       body ← (new_epoch:u32_be)                             # 4 B
//!   emit RATCHET_RECORD(body)
//!   key, iv ← direction_keys_from(new_secret)
//!   epoch ← new_epoch; seqnum ← 0
//! ```
//!
//! ### Receiver
//!
//! Decodes 4-byte or 36-byte body. 4-byte → pure symmetric step.
//! 36-byte → consumes bootstrap dh_sk, computes
//! `DH(my_dh_sk, peer_dh_pub_new)`, derives new secret. Burns
//! bootstrap.
//!
//! ### Initial DH state at handshake completion
//!
//! - Client: `my_dh_sk = client_x25519_sk`,
//!   `peer_dh_pub = server_x25519_eph_pub` (the per-session ephemeral
//!   from SH).
//! - Server: `my_dh_sk = server_x25519_eph_sk`,
//!   `peer_dh_pub = client_x25519_pub` (from AuthExtension).
//!
//! No extra handshake round-trip is needed.
//!
//! ### Properties
//!
//! - **Forward secrecy (FS)**: HKDF is forward-only, so a compromised
//!   `current_secret` at epoch N cannot recover `secret_(N-k)`. The
//!   asymmetric heal step doesn't weaken this — `dh_ikm` is one-way
//!   blended in.
//! - **Post-compromise security (PCS)**:
//!     - Compromise before first ratchet: heals at first ratchet (fresh
//!       DH the attacker can't replicate). PCS-strong heal step.
//!     - Compromise after first ratchet: traffic up to next symmetric
//!       step leaks; later epochs are forward-secret only. Same as
//!       prior build.
//! - **Replay across ratchet boundaries**: distinct epochs use distinct
//!   keys and reset seqnum to 0, so replay across boundaries fails AEAD.
//!
//! Compared to VLESS+REALITY (no rotation, no DH ratchet): a single key
//! leak exposes the entire conversation. Proteus achieves FS always and
//! PCS heal at the first ratchet — REALITY achieves neither.
//!
//! ### Backward compatibility
//!
//! The M0/M1/M2 builds emitted 4-byte ratchet bodies (new epoch only).
//! Receivers handle both 4-byte and 36-byte; a legacy 4-byte arriving
//! when we still hold a bootstrap dh_sk falls through to symmetric (the
//! DH state is retained but never used — slight memory waste, zero
//! security loss). A 36-byte arriving after the bootstrap was burned
//! is a fatal protocol error.
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
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};
use zeroize::Zeroizing;

/// HKDF label distinguishing the asymmetric DH-ratchet step from the
/// legacy pure-symmetric ratchet step. New label so transcripts +
/// recorded captures encrypted under one cannot be cross-replayed
/// against the other.
const DH_RATCHET_LABEL: &[u8] = b"proteus dh-ratchet v1";

/// Sentinel value placed in a cell's 4-byte length prefix to indicate
/// "this cell is a continuation; more cells follow as part of the
/// same logical record". The terminal cell carries the actual
/// remaining length (`0..=pad_quantum-4`); intermediate cells carry
/// this sentinel. `0xffff_ffff` is chosen because no legitimate
/// payload can be that large (`pad_quantum` is a `u16`, so the max
/// per-cell chunk size is 65 531 bytes — far below 4 GiB).
const CONTINUATION_SENTINEL: u32 = 0xffff_ffff;

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
    /// Length-quantum for data plane padding. 0 = no padding (legacy
    /// `RECORD_DATA` wire form, identical to pre-padding wire bytes).
    /// Non-zero = round every plaintext up to the next multiple of this
    /// value, then emit `RECORD_DATA_PADDED`. Spec §4.6 / §22.
    ///
    /// Typical operator values:
    /// - 0: no padding (CPU & throughput max; wire-length leak)
    /// - 64: 64-byte buckets (most leakage gone, ~1% overhead at 16 KiB)
    /// - 1280: 1280-byte buckets (matches β-profile β-CELL_SIZE, destroys all sub-cell length signal)
    pad_quantum: u16,
    /// Our local X25519 secret seeded from the handshake (client's
    /// `client_x25519_sk`, server's `server_x25519_eph_sk`). Consumed
    /// EXACTLY ONCE by the first outgoing ratchet event to provide
    /// one PCS-strong heal step. Subsequent ratchets are pure
    /// symmetric — which preserves forward secrecy and is robust to
    /// pipelined ratchets that would otherwise race a full Signal-
    /// style Double Ratchet.
    ///
    /// Wire effect: the first ratchet on a sender direction emits a
    /// 36-byte body containing the new DH pub; later ratchets emit
    /// the legacy 4-byte body.
    ///
    /// `None` disables the DH bootstrap — falls back to pure
    /// symmetric ratchet for the whole session (M0/M1/M2 behavior).
    dh_sk: Option<StaticSecret>,
    /// The peer's last-known DH pub used as the DH partner on the
    /// FIRST outgoing ratchet. Bootstrapped from the handshake; never
    /// updated thereafter (we use the symmetric chain for subsequent
    /// ratchets, so this only needs to be valid for the first one).
    peer_dh_pub: Option<[u8; 32]>,
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
            pad_quantum: 0,
            dh_sk: None,
            peer_dh_pub: None,
        }
    }

    /// Install one-shot DH-bootstrap state. The first outgoing ratchet
    /// will emit a fresh DH pub and derive the new secret from
    /// `DH(my_dh_sk_new, peer_dh_pub)`; subsequent ratchets fall back
    /// to pure symmetric. Provides one PCS-strong heal step at the
    /// first ratchet boundary.
    pub(crate) fn install_dh_ratchet(&mut self, my_dh_sk: StaticSecret, peer_dh_pub: [u8; 32]) {
        self.dh_sk = Some(my_dh_sk);
        self.peer_dh_pub = Some(peer_dh_pub);
    }

    /// Enable per-record padding to `quantum` bytes. `0` disables.
    /// Returns the previous setting so callers can stack-restore in
    /// composite handlers.
    ///
    /// This MUST be called before `send_record` if non-zero, ideally
    /// right after handshake completion. Switching the quantum
    /// mid-session is safe (each record carries its own type byte)
    /// but loses the threat-model property — observers learn that
    /// "this user toggled padding at sequence N", which is itself a
    /// distinctive signature. Production deployments should pick one
    /// quantum at handshake time and hold it.
    pub fn set_pad_quantum(&mut self, quantum: u16) -> u16 {
        std::mem::replace(&mut self.pad_quantum, quantum)
    }

    /// Read the current padding quantum.
    #[must_use]
    pub fn pad_quantum(&self) -> u16 {
        self.pad_quantum
    }

    /// Derive an `out_len`-byte subkey from the sender's current
    /// traffic secret using HKDF-Expand-Label with the operator-
    /// supplied `label`. The secret itself stays inside the
    /// AlphaSender and is **not** exposed.
    ///
    /// Used by side-channels that need independent keying material
    /// but want to bind it to the same handshake — e.g. the β-
    /// profile QUIC DATAGRAM AEAD path keys its out-of-band datagram
    /// channel via `derive_subkey(b"proteus-beta-datagram-key-v1", 32)`
    /// + `derive_subkey(b"proteus-beta-datagram-iv-v1", 12)`.
    ///
    /// Caller is responsible for zeroizing the returned Vec when
    /// done (return type is `Zeroizing<Vec<u8>>` for safety).
    pub fn derive_subkey(&self, label: &[u8], out_len: usize) -> AlphaResult<Zeroizing<Vec<u8>>> {
        let mut out = Zeroizing::new(vec![0u8; out_len]);
        proteus_crypto::kdf::expand_label(&self.secret, label, b"", &mut out)
            .map_err(|_| AlphaError::Closed)?;
        Ok(out)
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
    ///
    /// When `pad_quantum > 0`, the plaintext is wrapped as one or more
    /// CELLs each padded to exactly `pad_quantum` bytes. A logical
    /// record of length `L` produces `ceil((L + 4) / (pad_quantum - 4))`
    /// cells on the wire, each AEAD-sealed individually. All
    /// non-terminal cells carry the sentinel length prefix
    /// `0xffff_ffff`; the terminal cell carries the actual remaining
    /// length (`0..=pad_quantum-4`).
    ///
    /// Wire effect: every record on the wire is exactly
    /// `pad_quantum + 16` bytes of AEAD ciphertext, regardless of the
    /// logical payload size. A passive observer cannot distinguish a
    /// 1-byte logical record from a 64-KiB one by record-length
    /// shaping — they see a uniform stream of equally-sized cells.
    /// This is exactly the §4.6 cell-padding model REALITY cannot
    /// match.
    ///
    /// Returns the seqnum of the FIRST cell emitted. Each cell
    /// consumes one seqnum and one record-counter slot, so a long
    /// payload eats more of the per-epoch budget than a short one
    /// (which is correct — the wire actually carries more bytes).
    pub async fn send_record(&mut self, payload: &[u8]) -> AlphaResult<u64> {
        if self.pad_quantum == 0 {
            // ---- Legacy unpadded path (RECORD_DATA) ----
            self.ensure_ratchet().await?;
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
            return Ok(used);
        }

        // ---- Cell-padded path (RECORD_DATA_PADDED), split into cells ----
        let quantum = self.pad_quantum as usize;
        debug_assert!(
            quantum >= 8,
            "pad_quantum must allow a 4-byte length prefix"
        );
        let chunk_max = quantum - 4; // space for plaintext after the length prefix
        let first_seqnum = self.seqnum;
        // The total number of cells is `ceil(payload.len() / chunk_max).max(1)`.
        // A 0-byte payload still produces ONE terminal cell (real_len=0).
        let total_cells = payload.len().div_ceil(chunk_max).max(1);

        for cell_idx in 0..total_cells {
            self.ensure_ratchet().await?;
            let offset = cell_idx * chunk_max;
            let is_last = cell_idx + 1 == total_cells;
            let chunk = if is_last {
                &payload[offset..]
            } else {
                &payload[offset..offset + chunk_max]
            };
            // Build the cell plaintext: [len_prefix | chunk | zero-pad].
            let mut pt_buf = vec![0u8; quantum];
            if is_last {
                pt_buf[..4].copy_from_slice(&(chunk.len() as u32).to_be_bytes());
            } else {
                pt_buf[..4].copy_from_slice(&CONTINUATION_SENTINEL.to_be_bytes());
            }
            pt_buf[4..4 + chunk.len()].copy_from_slice(chunk);

            let combined = self.combined();
            let aad = combined.to_be_bytes();
            let ct = aead::seal(&self.keys.key, &self.keys.iv, combined, &aad, &pt_buf)?;
            let frame = alpha::encode_record(alpha::RECORD_DATA_PADDED, &ct);
            self.write.write_all(&frame).await?;

            self.seqnum = self.seqnum.saturating_add(1);
            self.records_in_epoch = self.records_in_epoch.saturating_add(1);
        }
        // Bytes accounting once per logical record (not once per cell)
        // so the ratchet trigger reflects application-visible bandwidth.
        self.bytes_in_epoch = self.bytes_in_epoch.saturating_add(payload.len() as u64);
        self.metrics.record_tx(payload.len() as u64);
        Ok(first_seqnum)
    }

    /// Ratchet-prep shared between the legacy + cell-mode paths.
    async fn ensure_ratchet(&mut self) -> AlphaResult<()> {
        if self.should_ratchet() {
            self.send_ratchet_frame().await?;
        }
        if self.seqnum > SEQNUM_MAX {
            self.send_ratchet_frame().await?;
        }
        Ok(())
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
    ///
    /// **DH mode (PCS-strong)**: when `self.dh_sk` is set AND a peer
    /// DH pub is known, the body carries `(new_epoch:u32 || my_dh_pub_new:[u8;32])`
    /// = 36 bytes, and the new secret is derived from a fresh X25519
    /// step. Otherwise we fall back to the legacy 4-byte body — same
    /// pure-symmetric behavior as the M0/M1/M2 builds. The decision is
    /// per-ratchet, so a peer can up- or down-grade mid-session.
    async fn send_ratchet_frame(&mut self) -> AlphaResult<()> {
        let new_epoch = self.epoch.saturating_add(1);

        // One-shot DH heal step: the FIRST ratchet event on this
        // direction takes the bootstrap dh_sk + peer_dh_pub and
        // performs a fresh DH; subsequent ratchets fall back to pure
        // symmetric. This avoids the pipelined-ratchet race that a
        // continuous Double Ratchet would face (where the sender
        // emits multiple ratchets faster than the peer responds, and
        // the receiver cannot tell which sk was paired with which
        // pub). One heal step is sufficient to recover PCS from any
        // pre-first-ratchet compromise; subsequent compromises are
        // bounded to one ratchet window by symmetric forward secrecy.
        let dh_takes_priority = self.dh_sk.is_some() && self.peer_dh_pub.is_some();

        let (new_secret, body_payload): (Zeroizing<[u8; 32]>, Vec<u8>) = if dh_takes_priority {
            let peer_pub = self.peer_dh_pub.expect("checked Some");
            let my_dh_sk_new = StaticSecret::random_from_rng(rand_core::OsRng);
            let my_dh_pub_new = XPublicKey::from(&my_dh_sk_new).to_bytes();

            // dh_ikm = X25519(my_dh_sk_new, peer_dh_pub). Reject the
            // all-zero output (RFC 7748 §6.1).
            let dh = my_dh_sk_new.diffie_hellman(&XPublicKey::from(peer_pub));
            let dh_bytes = dh.as_bytes();
            if dh_bytes.iter().all(|&b| b == 0) {
                return Err(AlphaError::Closed);
            }

            // new_secret = HKDF-Expand-Label(current_secret, "proteus dh-ratchet v1", dh_ikm, 32)
            let mut next = Zeroizing::new([0u8; 32]);
            kdf::expand_label(&self.secret, DH_RATCHET_LABEL, dh_bytes, &mut *next)?;

            // Burn the bootstrap dh_sk + peer_dh_pub — they were
            // consumed in this single heal step. The next ratchet
            // will fall through to the symmetric path. (We could
            // chain more DH steps but each costs a round-trip's worth
            // of state-sync complexity to handle pipelined ratchets;
            // one heal is a clean tradeoff that REALITY cannot match
            // at all.)
            self.dh_sk = None;
            self.peer_dh_pub = None;
            let _ = my_dh_sk_new; // burned on drop

            // Body = new_epoch (4 BE) || my_dh_pub_new (32) = 36 bytes
            let mut body = Vec::with_capacity(4 + 32);
            body.extend_from_slice(&new_epoch.to_be_bytes());
            body.extend_from_slice(&my_dh_pub_new);
            (next, body)
        } else {
            // ---- Pure symmetric ratchet (legacy + every-subsequent) ----
            let next = derive_ratchet_secret(&self.secret)?;
            (next, new_epoch.to_be_bytes().to_vec())
        };
        let new_keys = direction_keys_from_secret(&new_secret)?;

        // Emit RATCHET frame under the OLD key + sentinel seqnum.
        let sentinel = (u64::from(self.epoch) << 40) | SEQNUM_MAX;
        let aad = sentinel.to_be_bytes();
        let ct = aead::seal(&self.keys.key, &self.keys.iv, sentinel, &aad, &body_payload)?;
        let frame = alpha::encode_record(alpha::RECORD_RATCHET, &ct);
        self.write.write_all(&frame).await?;

        // Install the new state.
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
    /// One-shot DH bootstrap secret. Consumed on the FIRST 36-byte
    /// RATCHET we see from the peer; burned thereafter. Symmetric
    /// receiver-side counterpart of `AlphaSender::dh_sk`.
    dh_sk: Option<StaticSecret>,
    /// Accumulator for cell-mode `RECORD_DATA_PADDED` continuations.
    /// When the sender split a logical record into multiple cells
    /// (each prefixed with the sentinel `0xffff_ffff` real_len meaning
    /// "more follows"), we buffer their chunks here until the final
    /// cell (with a real length prefix) arrives and we can return the
    /// reassembled logical record.
    pending: Vec<u8>,
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

    /// Mirror of [`AlphaSender::derive_subkey`] for the receive
    /// direction. The two endpoints' sender→receiver pairs share
    /// the same secret so deriving with the same label on
    /// `client.session.sender` and `server.session.receiver` yields
    /// identical key material.
    pub fn derive_subkey(&self, label: &[u8], out_len: usize) -> AlphaResult<Zeroizing<Vec<u8>>> {
        let mut out = Zeroizing::new(vec![0u8; out_len]);
        proteus_crypto::kdf::expand_label(&self.secret, label, b"", &mut out)
            .map_err(|_| AlphaError::Closed)?;
        Ok(out)
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
            dh_sk: None,
            pending: Vec::new(),
        }
    }

    /// Install the receiver's bootstrap DH secret — consumed on the
    /// first 36-byte RATCHET from the peer.
    pub(crate) fn install_dh_ratchet(&mut self, my_dh_sk: StaticSecret) {
        self.dh_sk = Some(my_dh_sk);
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
                        alpha::RECORD_DATA_PADDED => {
                            let combined = (u64::from(self.epoch) << 40) | self.next_seqnum;
                            let aad = combined.to_be_bytes();
                            match aead::open(&self.keys.key, &self.keys.iv, combined, &aad, &body) {
                                Ok(pt) => {
                                    let raw = pt.as_slice();
                                    if raw.len() < 4 {
                                        self.metrics.record_aead_drop();
                                        continue;
                                    }
                                    let len_prefix =
                                        u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
                                    self.next_seqnum = self.next_seqnum.saturating_add(1);

                                    if len_prefix == CONTINUATION_SENTINEL {
                                        // Continuation cell: append the full
                                        // post-prefix region to `pending` and
                                        // keep reading. RX_BUF_HARD_CAP bounds
                                        // the total accumulator so a malicious
                                        // peer cannot OOM us with an unbounded
                                        // continuation chain.
                                        if self.pending.len() + (raw.len() - 4) > RX_BUF_HARD_CAP {
                                            self.metrics.record_aead_drop();
                                            return Err(AlphaError::Closed);
                                        }
                                        self.pending.extend_from_slice(&raw[4..]);
                                        continue;
                                    }

                                    // Terminal cell: parse the real length,
                                    // reassemble with any pending bytes.
                                    let real_len = len_prefix as usize;
                                    if 4 + real_len > raw.len() {
                                        self.metrics.record_aead_drop();
                                        continue;
                                    }
                                    let last_chunk = &raw[4..4 + real_len];
                                    let bytes = if self.pending.is_empty() {
                                        last_chunk.to_vec()
                                    } else {
                                        let mut out = std::mem::take(&mut self.pending);
                                        out.extend_from_slice(last_chunk);
                                        out
                                    };
                                    self.metrics.record_rx(bytes.len() as u64);
                                    return Ok(Some(bytes));
                                }
                                Err(_) => {
                                    self.metrics.record_aead_drop();
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
        // body = AEAD(old_key, nonce=combined(old_epoch, SEQNUM_MAX), aad=that, pt=...)
        // Plaintext is either:
        //   4 bytes  : new_epoch (legacy symmetric ratchet)
        //   36 bytes : new_epoch || peer_dh_pub_new (asymmetric DH ratchet)
        let combined = (u64::from(self.epoch) << 40) | SEQNUM_MAX;
        let aad = combined.to_be_bytes();
        let pt = aead::open(&self.keys.key, &self.keys.iv, combined, &aad, body)
            .map_err(|_| AlphaError::BadServerFinished)?;
        let pt_bytes = pt.as_slice();
        if pt_bytes.len() != 4 && pt_bytes.len() != 36 {
            return Err(AlphaError::BadServerFinished);
        }
        let new_epoch = u32::from_be_bytes([pt_bytes[0], pt_bytes[1], pt_bytes[2], pt_bytes[3]]);
        if new_epoch != self.epoch.saturating_add(1) {
            return Err(AlphaError::BadServerFinished);
        }

        let new_secret: Zeroizing<[u8; 32]> = if pt_bytes.len() == 36 {
            // ---- One-shot DH heal ratchet ----
            //
            // Only valid if WE still hold the bootstrap DH sk. After
            // it's been consumed once, a second 36-byte ratchet is a
            // protocol error (peer is expected to fall back to the
            // 4-byte symmetric form after their first heal).
            let Some(my_sk) = self.dh_sk.take() else {
                return Err(AlphaError::BadServerFinished);
            };
            let mut peer_pub_new = [0u8; 32];
            peer_pub_new.copy_from_slice(&pt_bytes[4..36]);

            let dh = my_sk.diffie_hellman(&XPublicKey::from(peer_pub_new));
            let dh_bytes = dh.as_bytes();
            if dh_bytes.iter().all(|&b| b == 0) {
                // Low-order point — reject (RFC 7748 §6.1).
                return Err(AlphaError::BadServerFinished);
            }

            let mut next = Zeroizing::new([0u8; 32]);
            kdf::expand_label(&self.secret, DH_RATCHET_LABEL, dh_bytes, &mut *next)?;
            // `my_sk` dropped here — bootstrap consumed.
            next
        } else {
            // ---- Pure symmetric ratchet ----
            derive_ratchet_secret(&self.secret)?
        };

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

/// On drop, scrub any plaintext bytes that transited the receive
/// buffer (decrypted DATA, post-handshake tail, peer-supplied CLOSE
/// reason). `keys` / `secret` are wrapped in `Zeroizing` so they
/// already zero themselves on drop; we wipe the variable-length
/// buffers manually.
impl<R: AsyncRead + Unpin> Drop for AlphaReceiver<R> {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.rx_buf.zeroize();
        self.pending.zeroize();
        if let Some(reason) = self.last_close_reason.as_mut() {
            reason.zeroize();
        }
    }
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
    /// Authenticated user identifier, set by the server-side handshake
    /// when an allowlist entry matches the client's Ed25519 sig. `None`
    /// on the client side, or when no allowlist is configured (test
    /// builds). Used by access logs and per-user rate limiters.
    pub user_id: Option<[u8; 8]>,
    /// Peer socket address as observed at TCP accept. `None` when the
    /// session was built over an in-memory stream (tests). Used by
    /// access logs.
    pub peer_addr: Option<std::net::SocketAddr>,
    /// 32-bit shape-shift PRG seed the client picked for this session
    /// (spec §22). The server captures it during handshake decode so
    /// access logs can record what cell-size schedule was negotiated;
    /// `None` on the client side or for legacy in-memory tests.
    pub shape_seed: Option<u32>,
    /// Cover-profile selector the client picked (spec §22.4); same
    /// lifecycle as `shape_seed`.
    pub cover_profile_id: Option<u16>,
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> AlphaSession<R, W> {
    /// Builder-style setter for the authenticated user-id. Called by
    /// the server-side handshake after the allowlist check.
    #[must_use]
    pub fn with_user_id(mut self, user_id: [u8; 8]) -> Self {
        self.user_id = Some(user_id);
        self
    }

    /// Builder-style setter for the peer socket address. Called by
    /// the server-side accept loop just after `accept()`.
    #[must_use]
    pub fn with_peer_addr(mut self, peer: std::net::SocketAddr) -> Self {
        self.peer_addr = Some(peer);
        self
    }

    /// Builder-style setter for the shape-shift parameters the client
    /// advertised. Called by the server handshake after the AuthExtension
    /// auth_tag has verified — only the bound, attested values land here.
    #[must_use]
    pub fn with_shape(mut self, shape_seed: u32, cover_profile_id: u16) -> Self {
        self.shape_seed = Some(shape_seed);
        self.cover_profile_id = Some(cover_profile_id);
        self
    }

    /// Install one-shot asymmetric DH ratchet state derived from the
    /// handshake. The sender will perform a fresh DH on its first
    /// outgoing RATCHET event (PCS heal step); subsequent ratchets
    /// are pure symmetric.
    ///
    /// `my_dh_sk` is THIS endpoint's X25519 secret half of the
    /// handshake key (`client_x25519_sk` for client, `server_x25519_eph_sk`
    /// for server). `peer_dh_pub` is the matching public.
    ///
    /// The sender and receiver each get their OWN copy of `my_dh_sk`
    /// — the sender consumes it to produce a new DH pub on outgoing
    /// ratchets; the receiver consumes it to combine with the peer's
    /// announced pub on incoming ratchets. The two copies are
    /// independent: each is burned exactly once.
    #[must_use]
    pub fn with_dh_ratchet(mut self, my_dh_sk: StaticSecret, peer_dh_pub: [u8; 32]) -> Self {
        self.sender
            .install_dh_ratchet(my_dh_sk.clone(), peer_dh_pub);
        self.receiver.install_dh_ratchet(my_dh_sk);
        self
    }
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
            user_id: None,
            peer_addr: None,
            shape_seed: None,
            cover_profile_id: None,
        }
    }
}
