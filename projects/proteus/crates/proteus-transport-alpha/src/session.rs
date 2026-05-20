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

/// Sentinel placed in a cell's 4-byte length prefix to mark a
/// heartbeat / cover-traffic cell. The receiver silently consumes
/// these and does NOT surface them to the application.
///
/// Wire indistinguishability: same record-type byte (`0x13`), same
/// total wire length (`pad_quantum + 16`), same AEAD key + nonce
/// scheme as a real data cell. A passive observer counting cells
/// per-second sees a uniform stream and cannot tell active bulk
/// transfer apart from interactive RPC apart from pure cover.
///
/// `0xffff_fffe` chosen for symmetry with `CONTINUATION_SENTINEL`
/// (one below the max u32 value), and because no legitimate payload
/// length can match it (max chunk_max is well under 65 KiB).
const HEARTBEAT_SENTINEL: u32 = 0xffff_fffe;

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

/// Threshold for compacting `rx_buf` after the cursor advances past it.
/// Below this, we leave the consumed prefix in place and just advance
/// `rx_offset` — this avoids the per-record O(N) memmove that
/// `rx_buf.drain(..consumed)` would do on every successfully-decoded
/// frame.
///
/// At `pad_quantum=1280` a single 16 KiB TCP read holds ~12 cells.
/// Pre-iter every cell decode cost one drain (memmove of the
/// remaining tail). Post-iter we accumulate the consumed bytes
/// until the offset crosses 64 KiB, then compact ONCE per ~50
/// records on bulk download.
///
/// The threshold also bounds the worst-case "wasted" buffer-head
/// memory at 64 KiB — the live (uncompacted) buffer can be at most
/// `rx_offset + live_tail_size`, and we compact whenever rx_offset
/// crosses this threshold so wasted-head ≤ 64 KiB.
const RX_COMPACT_THRESHOLD: usize = 64 * 1024;

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
    /// Cached ChaCha20-Poly1305 cipher built from `keys.key` once per
    /// epoch (rebuilt on every ratchet). Avoids paying the per-record
    /// `ChaCha20Poly1305::new(&key)` cost in the hot data path. See
    /// `proteus_crypto::aead::AeadKey` for the rationale.
    cipher: proteus_crypto::aead::AeadKey,
    /// Reusable scratch buffer for in-place AEAD seal in the cell-
    /// padded path. Holds the cell plaintext on entry and
    /// `ciphertext || tag` on exit. Capacity sticks across calls
    /// so the hot loop allocates exactly zero times.
    tx_aead_scratch: Vec<u8>,
    /// Reusable scratch buffer for the per-record wire header
    /// (type byte + varint length). 16 bytes is generous (worst-case
    /// varint is 8 bytes; α records cap well below 2^14 so it's
    /// typically 1-2). Capacity sticks across calls.
    tx_hdr_scratch: Vec<u8>,
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
        let cipher = keys.aead_key();
        Self {
            write: BufWriter::with_capacity(TX_BUF_CAPACITY, write),
            keys,
            cipher,
            // 2 KiB covers any quantum we ship today (max 1280 + tag).
            // Capacity sticks across calls so the loop is alloc-free.
            tx_aead_scratch: Vec::with_capacity(2 * 1024),
            // 16 bytes covers the worst-case header.
            tx_hdr_scratch: Vec::with_capacity(16),
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
            // Hot path: cached cipher + reused scratch buffers, zero
            // allocations per record.
            self.ensure_ratchet().await?;
            let combined = self.combined();
            let aad = combined.to_be_bytes();

            // Seal plaintext into the reused scratch buffer.
            self.tx_aead_scratch.clear();
            self.tx_aead_scratch.extend_from_slice(payload);
            self.cipher
                .seal_into(combined, &aad, &mut self.tx_aead_scratch)?;

            // Emit header (type + varint len) into the reused
            // header scratch, then write header + ciphertext to
            // the BufWriter (two write_all calls; the BufWriter
            // coalesces them under the 64 KiB TX_BUF_CAPACITY).
            self.tx_hdr_scratch.clear();
            alpha::write_record_header_to(
                &mut self.tx_hdr_scratch,
                alpha::RECORD_DATA,
                self.tx_aead_scratch.len(),
            );
            self.write.write_all(&self.tx_hdr_scratch).await?;
            self.write.write_all(&self.tx_aead_scratch).await?;

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
            // Build the cell plaintext into the reused scratch buffer:
            // [len_prefix | chunk | zero-pad-to-quantum].
            //
            // Iter-150: skip the zero-fill on non-terminal cells.
            // A non-terminal cell ALWAYS has chunk.len() == chunk_max,
            // so the layout is `[4-byte sentinel | chunk_max bytes] =
            // quantum bytes` — every byte gets written by the
            // copy_from_slice calls below, so a pre-fill is pure
            // waste. Terminal cells still need zero-padding from
            // `4 + chunk.len()` to `quantum`.
            //
            // Win scales with `quantum`: at pad_quantum=1280, every
            // non-terminal cell saves one 1280-byte memset. On bulk
            // download where the payload is 16 KiB and chunk_max =
            // 1276, that's ~12 saved memsets per logical record →
            // ~15 KiB of saved memset work per record. AEAD encrypt
            // remains the dominant cost, but every saved memset is
            // a free L1-cache cycle.
            self.tx_aead_scratch.clear();
            if is_last {
                // Terminal cell: build [real_len | chunk | zero-pad].
                //
                // Iter-202: extend prefix + chunk first, THEN resize
                // up to `quantum` with zeros. Vec::resize only memsets
                // the bytes between current len and new len, so this
                // zeros ONLY the actual padding region — not the
                // prefix + chunk bytes that the previous order
                // (resize-to-quantum-with-0, then overwrite prefix
                // and chunk) was memset-then-overwritten on every
                // call. Wins scale linearly with chunk.len(): at
                // pad_quantum=1280 and chunk.len()=900 (typical
                // mid-payload terminal cell), this saves a 904-byte
                // memset per record. On bulk download where the
                // terminal cell tends to be full or near-full
                // (chunk.len() ≈ chunk_max), the saving approaches
                // an entire quantum's worth of memset per logical
                // record. AEAD encrypt still dominates CPU, but a
                // saved memset is L1 cycles back in the budget — and
                // unlike the iter-150 win for non-terminal cells
                // (which only kicks in on multi-cell records), this
                // fires on EVERY logical record, including the common
                // single-cell case where the entire payload fits in
                // one cell.
                self.tx_aead_scratch
                    .extend_from_slice(&(chunk.len() as u32).to_be_bytes());
                self.tx_aead_scratch.extend_from_slice(chunk);
                self.tx_aead_scratch.resize(quantum, 0);
                debug_assert_eq!(
                    self.tx_aead_scratch.len(),
                    quantum,
                    "terminal cell must be exactly quantum bytes pre-AEAD"
                );
            } else {
                // Non-terminal cell: build [sentinel | chunk_max bytes]
                // = quantum bytes, no padding region. extend_from_slice
                // appends without a pre-zero, saving the memset.
                self.tx_aead_scratch
                    .extend_from_slice(&CONTINUATION_SENTINEL.to_be_bytes());
                self.tx_aead_scratch.extend_from_slice(chunk);
                debug_assert_eq!(
                    self.tx_aead_scratch.len(),
                    quantum,
                    "non-terminal cell must be exactly quantum bytes pre-AEAD"
                );
            }

            let combined = self.combined();
            let aad = combined.to_be_bytes();
            self.cipher
                .seal_into(combined, &aad, &mut self.tx_aead_scratch)?;

            self.tx_hdr_scratch.clear();
            alpha::write_record_header_to(
                &mut self.tx_hdr_scratch,
                alpha::RECORD_DATA_PADDED,
                self.tx_aead_scratch.len(),
            );
            self.write.write_all(&self.tx_hdr_scratch).await?;
            self.write.write_all(&self.tx_aead_scratch).await?;

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
        // Iter-177: same EPOCH_MAX gate as the recv-side
        // `apply_ratchet` path. If we ever reach 1 << 24 epochs
        // (impossible in any realistic deployment, but a future
        // bug or pathological peer could trigger it), the
        // 24-bit epoch field overflows when packed into the
        // 64-bit AEAD nonce counter via `u64::from(epoch) << 40`,
        // breaking the nonce-uniqueness invariant. Refuse to
        // emit the ratchet and surface a closed session — the
        // operator must restart with a fresh handshake.
        if u64::from(new_epoch) >= (1u64 << proteus_spec::EPOCH_BITS) {
            return Err(AlphaError::Closed);
        }

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
        // Low-frequency path (one per ratchet), so we keep the
        // free-function `aead::seal` + `encode_record` form for
        // readability — no measurable perf cost at sub-Hz rates.
        let sentinel = (u64::from(self.epoch) << 40) | SEQNUM_MAX;
        let aad = sentinel.to_be_bytes();
        let ct = aead::seal(&self.keys.key, &self.keys.iv, sentinel, &aad, &body_payload)?;
        let frame = alpha::encode_record(alpha::RECORD_RATCHET, &ct);
        self.write.write_all(&frame).await?;

        // Install the new state — and refresh the cached cipher so
        // subsequent records on this epoch encrypt under the new
        // key, not the old one.
        self.keys = new_keys;
        self.cipher = self.keys.aead_key();
        self.secret = new_secret;
        self.epoch = new_epoch;
        self.seqnum = 0;
        self.bytes_in_epoch = 0;
        self.records_in_epoch = 0;
        self.metrics.record_ratchet();
        Ok(())
    }

    /// Send a heartbeat / cover-traffic cell. Requires `pad_quantum > 0`
    /// (cell mode). On the wire this is byte-indistinguishable from a
    /// normal data cell: same record-type byte (`0x13` =
    /// `RECORD_DATA_PADDED`), same total length (`pad_quantum + 16`
    /// bytes ciphertext), same AEAD key + nonce progression. Only the
    /// plaintext-after-decrypt length prefix distinguishes it — and
    /// only the legitimate session endpoints can decrypt.
    ///
    /// Threat model: a passive observer (DPI / ML classifier) measuring
    /// the per-second cell arrival rate sees a uniform stream. They
    /// cannot distinguish:
    ///   - active bulk transfer (every cell carries data)
    ///   - idle session being kept alive by heartbeats
    ///   - interactive RPC at low cells/sec
    ///   - pure cover traffic with no real payload
    ///
    /// Returns `Err(AlphaError::Closed)` if `pad_quantum == 0` — cover
    /// traffic in non-cell mode would be a distinguishable record type
    /// and so is disallowed.
    pub async fn send_heartbeat(&mut self) -> AlphaResult<()> {
        if self.pad_quantum == 0 {
            return Err(AlphaError::Closed);
        }
        self.ensure_ratchet().await?;

        let quantum = self.pad_quantum as usize;
        // Use the reused scratch buffer (cached cipher path) so
        // periodic heartbeats don't trickle into the heap.
        self.tx_aead_scratch.clear();
        self.tx_aead_scratch.resize(quantum, 0);
        self.tx_aead_scratch[..4].copy_from_slice(&HEARTBEAT_SENTINEL.to_be_bytes());
        // The rest is zero-pad (same shape as a terminal cell with
        // real_len=0, but the sentinel tells the receiver to drop it
        // silently instead of returning Ok(Some(empty))).

        let combined = self.combined();
        let aad = combined.to_be_bytes();
        self.cipher
            .seal_into(combined, &aad, &mut self.tx_aead_scratch)?;
        self.tx_hdr_scratch.clear();
        alpha::write_record_header_to(
            &mut self.tx_hdr_scratch,
            alpha::RECORD_DATA_PADDED,
            self.tx_aead_scratch.len(),
        );
        self.write.write_all(&self.tx_hdr_scratch).await?;
        self.write.write_all(&self.tx_aead_scratch).await?;
        // Don't flush here — the caller drives flush cadence
        // independently. A heartbeat task that flushes every cell would
        // emit smaller TCP segments than a real bulk sender, which
        // itself is a fingerprint.

        self.seqnum = self.seqnum.saturating_add(1);
        self.records_in_epoch = self.records_in_epoch.saturating_add(1);
        // bytes_in_epoch is NOT incremented (no application bytes) —
        // heartbeats should not consume the ratchet byte budget. But
        // records_in_epoch IS incremented so the record-count budget
        // still triggers correctly.
        self.metrics.record_heartbeat_sent();
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

/// Scrub the sender's reused scratch buffers on drop.
///
/// `tx_aead_scratch` carries the most-recent record's plaintext-then-
/// ciphertext (the in-place seal writes the AEAD tag without scrubbing
/// the underlying plaintext bytes — they're overwritten in place, but
/// trailing capacity may retain stale plaintext bytes across calls).
/// `tx_hdr_scratch` only carries record-type bytes + varint length —
/// not secret — but zeroizing it is cheap and keeps the rule
/// uniform ("every scratch buffer that touched session state gets
/// scrubbed on drop").
impl<W: AsyncWrite + Unpin> Drop for AlphaSender<W> {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.tx_aead_scratch.zeroize();
        self.tx_hdr_scratch.zeroize();
    }
}

/// Receiving half of an established session.
pub struct AlphaReceiver<R: AsyncRead + Unpin = tokio::net::tcp::OwnedReadHalf> {
    read: R,
    keys: DirectionKeys,
    /// Cached ChaCha20-Poly1305 cipher built from `keys.key` once per
    /// epoch (rebuilt on every ratchet). Mirror of `AlphaSender::cipher`
    /// — eliminates the per-record key-schedule cost on the recv side.
    cipher: proteus_crypto::aead::AeadKey,
    /// Reusable scratch buffer for in-place AEAD open. Populated from
    /// the inbound record body, then decrypted in-place. Capacity
    /// sticks across calls.
    rx_aead_scratch: Vec<u8>,
    secret: Zeroizing<[u8; 32]>,
    epoch: u32,
    next_seqnum: u64,
    rx_buf: Vec<u8>,
    /// Cursor into `rx_buf` marking the byte offset of the next
    /// unconsumed frame. Pre-iter every decoded frame did
    /// `rx_buf.drain(..consumed)` which memmoves the unconsumed tail
    /// to position 0 — O(N) per record. Post-iter we just bump this
    /// cursor and defer compaction until it crosses
    /// [`RX_COMPACT_THRESHOLD`], saving ~12 memmoves per 16 KiB read
    /// at `pad_quantum=1280`. The live (unconsumed) bytes are at
    /// `rx_buf[rx_offset..]`.
    rx_offset: usize,
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
        let cipher = keys.aead_key();
        Self {
            read,
            keys,
            cipher,
            rx_aead_scratch: Vec::with_capacity(2 * 1024),
            secret,
            epoch: 0,
            next_seqnum: 0,
            rx_buf: prefix,
            rx_offset: 0,
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
    ///
    /// **Allocation note**: this method clones the decrypted plaintext
    /// into a fresh `Vec<u8>` per call. Hot relay loops should prefer
    /// [`AlphaReceiver::recv_record_into`] which writes into a
    /// caller-owned buffer whose capacity sticks across calls.
    pub async fn recv_record(&mut self) -> AlphaResult<Option<Vec<u8>>> {
        let mut buf = Vec::new();
        match self.recv_record_into(&mut buf).await? {
            Some(()) => Ok(Some(buf)),
            None => Ok(None),
        }
    }

    /// Zero-alloc variant of [`AlphaReceiver::recv_record`].
    ///
    /// On `Ok(Some(()))` the caller's `out` buffer is cleared and then
    /// extended with the decrypted plaintext (an empty buffer signals a
    /// keepalive, same as `recv_record` returning `Ok(Some(vec![]))`).
    /// On `Ok(None)` the peer issued a clean CLOSE and `out` is left
    /// empty.
    ///
    /// ## Why this exists
    ///
    /// The α data plane on a bulk relay leg can process thousands of
    /// records per second (pad_quantum=1280 → ~12 cells per logical
    /// 16 KiB record × hundreds of MiB/s). The legacy `recv_record`
    /// returned an owned `Vec<u8>` per record; each return path
    /// allocated a fresh backing buffer (`rx_aead_scratch.clone()` /
    /// `last_chunk.to_vec()`) purely to hand the plaintext to the
    /// caller. That's one heap allocation per record on the hottest
    /// loop in the codebase — burning ~120 K allocs/sec on a saturated
    /// gigabit relay.
    ///
    /// `recv_record_into` re-uses the caller's buffer. The relay code
    /// keeps a single `Vec<u8>` per session direction; its capacity
    /// stabilises at the first large record and stays there for the
    /// session lifetime. AEAD decrypt remains the dominant CPU cost,
    /// but the per-record `malloc/free` round-trip is now gone.
    ///
    /// ## Buffer hygiene
    ///
    /// `out.clear()` is called at the top of every successful return
    /// path. Capacity is preserved (Vec::clear only sets `len = 0`).
    /// Callers who care about plaintext residue should call
    /// `out.zeroize()` after they finish processing each record — the
    /// session itself scrubs its internal scratch (iter-197) but not
    /// the caller's buffer, by design.
    pub async fn recv_record_into(&mut self, out: &mut Vec<u8>) -> AlphaResult<Option<()>> {
        out.clear();
        loop {
            match alpha::decode_frame(&self.rx_buf[self.rx_offset..]) {
                Ok((frame, consumed)) => {
                    let kind = frame.kind;
                    // Copy the frame body into our reusable scratch
                    // so the AEAD can decrypt in place. Using
                    // rx_aead_scratch instead of `frame.body.to_vec()`
                    // means the inner Vec<u8> capacity sticks across
                    // records, eliminating the per-record allocation
                    // on the recv hot path.
                    self.rx_aead_scratch.clear();
                    self.rx_aead_scratch.extend_from_slice(frame.body);
                    // Cursor-based consume: defer the O(N) memmove until
                    // the cursor crosses RX_COMPACT_THRESHOLD. On bulk
                    // download at pad_quantum=1280 (~12 cells / 16 KiB
                    // read) this drops ~11 of every 12 drains.
                    self.rx_offset += consumed;
                    if self.rx_offset >= RX_COMPACT_THRESHOLD {
                        self.rx_buf.drain(..self.rx_offset);
                        self.rx_offset = 0;
                    }
                    match kind {
                        alpha::RECORD_DATA => {
                            let combined = (u64::from(self.epoch) << 40) | self.next_seqnum;
                            let aad = combined.to_be_bytes();
                            match self.cipher.open_in_place(
                                combined,
                                &aad,
                                &mut self.rx_aead_scratch,
                            ) {
                                Ok(()) => {
                                    self.next_seqnum = self.next_seqnum.saturating_add(1);
                                    // Iter-200: extend the caller-supplied
                                    // `out` buffer in place instead of
                                    // cloning the scratch into a fresh
                                    // Vec. On a bulk relay leg this is
                                    // the difference between one heap
                                    // allocation per record (legacy) and
                                    // zero (this path). The scratch is
                                    // scrubbed below so plaintext residue
                                    // does not survive the call.
                                    out.extend_from_slice(&self.rx_aead_scratch);
                                    self.metrics.record_rx(out.len() as u64);
                                    // Iter-197: scrub the scratch
                                    // buffer NOW (post-extend) so the
                                    // plaintext doesn't linger
                                    // between recv_record calls. On a
                                    // low-traffic session the gap can
                                    // be minutes — long enough for a
                                    // coredump or stack-image grab to
                                    // recover the last record's
                                    // plaintext (HTTP response
                                    // headers, tunneled bytes). The
                                    // iter-135 Drop scrub catches the
                                    // teardown case; this catches the
                                    // BETWEEN-RECORDS case. Vec::zeroize
                                    // preserves capacity (clears len +
                                    // zeros spare), so the hot-loop
                                    // alloc-free property is preserved.
                                    use zeroize::Zeroize as _;
                                    self.rx_aead_scratch.zeroize();
                                    return Ok(Some(()));
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
                            match self.cipher.open_in_place(
                                combined,
                                &aad,
                                &mut self.rx_aead_scratch,
                            ) {
                                Ok(()) => {
                                    let raw = self.rx_aead_scratch.as_slice();
                                    if raw.len() < 4 {
                                        self.metrics.record_aead_drop();
                                        continue;
                                    }
                                    let len_prefix =
                                        u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
                                    self.next_seqnum = self.next_seqnum.saturating_add(1);

                                    if len_prefix == HEARTBEAT_SENTINEL {
                                        // Cover-traffic cell. The peer
                                        // emitted this purely to keep the
                                        // wire-level cell-arrival rate
                                        // indistinguishable across active /
                                        // idle / RPC sessions. Drop it
                                        // silently — do NOT surface to the
                                        // caller, do NOT touch `pending`
                                        // (heartbeats sit between data
                                        // cells but never interrupt a
                                        // continuation chain).
                                        self.metrics.record_heartbeat_recv();
                                        continue;
                                    }
                                    if len_prefix == CONTINUATION_SENTINEL {
                                        // Continuation cell: append the full
                                        // post-prefix region to `pending` and
                                        // keep reading. RX_BUF_HARD_CAP bounds
                                        // the total accumulator so a malicious
                                        // peer cannot OOM us with an unbounded
                                        // continuation chain.
                                        //
                                        // Iter-176: checked_add on the
                                        // `pending.len() + (raw.len() - 4)`
                                        // sum. raw.len() ≥ 4 here (we just
                                        // dispatched off raw[0..4]'s u32),
                                        // so `raw.len() - 4` is well-defined.
                                        // The sum can in principle overflow
                                        // `usize` on 32-bit hosts; closing
                                        // it is the same defense-in-depth
                                        // class as the iter-175 / iter-176
                                        // terminal-cell-length fix. Failure
                                        // path (overflow OR cap exceeded)
                                        // closes the session cleanly.
                                        let proj = self
                                            .pending
                                            .len()
                                            .checked_add(raw.len() - 4)
                                            .filter(|p| *p <= RX_BUF_HARD_CAP);
                                        if proj.is_none() {
                                            self.metrics.record_aead_drop();
                                            return Err(AlphaError::Closed);
                                        }
                                        self.pending.extend_from_slice(&raw[4..]);
                                        continue;
                                    }

                                    // Terminal cell: parse the real length,
                                    // reassemble with any pending bytes.
                                    let real_len = len_prefix as usize;
                                    // Iter-176: checked_add on `4 + real_len`
                                    // — closes the matching overflow class
                                    // iter-175 fixed in alpha::decode_frame.
                                    // On 32-bit hosts `4 + real_len` with
                                    // real_len near 2^32-1 wraps to a small
                                    // value, sneaks past the `> raw.len()`
                                    // check, then `&raw[4..4 + real_len]`
                                    // panics on the OOB slice. The peer-
                                    // controlled `len_prefix` is the u32
                                    // read from the cell's first 4 bytes
                                    // AFTER AEAD-decrypt — already
                                    // authenticated, but a malicious
                                    // sealing-key holder (= the peer)
                                    // controls every byte of plaintext.
                                    // Fail-closed via silent-drop matches
                                    // every other terminal-cell rejection
                                    // path above (truncated, sentinel-
                                    // mismatch, etc.).
                                    let end = match 4usize.checked_add(real_len) {
                                        Some(e) if e <= raw.len() => e,
                                        _ => {
                                            self.metrics.record_aead_drop();
                                            continue;
                                        }
                                    };
                                    let last_chunk = &raw[4..end];
                                    // Iter-200: write the reassembled
                                    // logical record into `out`. If
                                    // `pending` carried earlier
                                    // continuation cells, drain them
                                    // into `out` first, then append
                                    // this terminal chunk. The
                                    // continuation buffer is scrubbed
                                    // on take (Vec::clear() preserves
                                    // capacity; we explicitly zeroize
                                    // before clearing so residue from
                                    // earlier continuation cells
                                    // doesn't linger).
                                    if !self.pending.is_empty() {
                                        out.extend_from_slice(&self.pending);
                                        use zeroize::Zeroize as _;
                                        self.pending.zeroize();
                                        self.pending.clear();
                                    }
                                    out.extend_from_slice(last_chunk);
                                    self.metrics.record_rx(out.len() as u64);
                                    // Iter-197: scrub the AEAD scratch
                                    // post-extend so the plaintext
                                    // doesn't linger between
                                    // recv_record calls. Same fix as
                                    // the unpadded RECORD_DATA path
                                    // above; same threat model
                                    // (between-records residue).
                                    use zeroize::Zeroize as _;
                                    self.rx_aead_scratch.zeroize();
                                    return Ok(Some(()));
                                }
                                Err(_) => {
                                    self.metrics.record_aead_drop();
                                    continue;
                                }
                            }
                        }
                        alpha::RECORD_RATCHET => {
                            // Low-frequency path — keep using the
                            // free-function aead::open. rx_aead_scratch
                            // still holds the (untouched) body bytes
                            // since the hot data branches above only
                            // mutate it under their own match arms.
                            let body = self.rx_aead_scratch.clone();
                            self.apply_ratchet(&body)?;
                            continue;
                        }
                        alpha::RECORD_CLOSE => {
                            let combined = (u64::from(self.epoch) << 40) | self.next_seqnum;
                            let aad = combined.to_be_bytes();
                            // Same low-frequency note as RATCHET above.
                            let body = &self.rx_aead_scratch;
                            if let Ok(pt) =
                                aead::open(&self.keys.key, &self.keys.iv, combined, &aad, body)
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
            // Measure LIVE bytes (post-cursor) — the consumed prefix
            // is reclaimable on the next compaction.
            let live_len = self.rx_buf.len() - self.rx_offset;
            if live_len >= RX_BUF_HARD_CAP {
                self.metrics.record_aead_drop();
                return Err(AlphaError::Closed);
            }
            // If the consumed prefix has grown to dominate the buffer,
            // compact pre-emptively before the next read so we don't
            // hold an unbounded `rx_offset` worth of dead bytes while
            // appending fresh data. Threshold matches the post-decode
            // compaction so the worst-case head-waste stays
            // ≤ RX_COMPACT_THRESHOLD.
            if self.rx_offset >= RX_COMPACT_THRESHOLD {
                self.rx_buf.drain(..self.rx_offset);
                self.rx_offset = 0;
            }
            // Iter-201: read directly into the rx_buf's spare
            // capacity via `AsyncReadExt::read_buf`, eliminating
            // the 16 KiB stack scratch + extend_from_slice memcpy
            // that the legacy path paid on every syscall. The
            // tokio implementation calls the underlying
            // `poll_read` against a `ReadBuf` wrapping the Vec's
            // unfilled tail, then bumps Vec::len by `n`. End
            // result: the kernel writes the bytes once into the
            // final destination, not into a stack page first.
            //
            // Target batch size remains ~16 KiB so the receive
            // syscall caps at the same throughput as pre-iter-201
            // on bulk download. We reserve the spare capacity
            // *only if* the current spare is below the target —
            // a session that's already at high water mark
            // (post-compaction with ~64 KiB held) re-uses the
            // existing capacity. The reserve is bounded above by
            // RX_BUF_HARD_CAP so a pathological reserve request
            // can never push us past the hard cap (we measured
            // live_len < RX_BUF_HARD_CAP above this block).
            const RECV_BATCH: usize = 16 * 1024;
            let spare = self.rx_buf.capacity() - self.rx_buf.len();
            if spare < RECV_BATCH {
                // `try_reserve` rather than `reserve` so an
                // allocator failure surfaces as a clean session
                // close rather than aborting the process.
                let need = RECV_BATCH - spare;
                if self.rx_buf.try_reserve(need).is_err() {
                    self.metrics.record_aead_drop();
                    return Err(AlphaError::Closed);
                }
            }
            // `read_buf` writes into the Vec's spare capacity and
                // returns the byte count. EOF is signalled by `n == 0`.
            let pre_len = self.rx_buf.len();
            let n = self.read.read_buf(&mut self.rx_buf).await?;
            debug_assert_eq!(self.rx_buf.len(), pre_len + n);
            if n == 0 {
                return Ok(None);
            }
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
        // Iter-177: enforce the 24-bit epoch field (spec §4.5 +
        // proteus_spec::EPOCH_BITS = 24). The wire format packs
        // `epoch:24 || seqnum:40` into a 64-bit AEAD nonce
        // counter; if `epoch` reaches `1 << 24` the
        // `u64::from(epoch) << 40` shift in `recv_record` /
        // `send_record` would overflow u64 (debug panic / release
        // wrap-to-0). Either outcome breaks the
        // nonce-uniqueness invariant that AEAD security
        // depends on. Once we cross EPOCH_MAX, refuse to apply
        // the ratchet and close the session — operator must
        // start a fresh handshake.
        //
        // Sessions hit this limit only after 2^24 = ~16M
        // ratchet events. At RATCHET_BYTES = 4 MiB that's 64 TiB
        // per direction per session — never reached in any
        // realistic deployment, but the gate must be present so
        // a deliberately-pathological peer (or a hypothetical
        // future bug that triggers excessive ratcheting) cannot
        // smash the nonce invariant.
        if u64::from(new_epoch) >= (1u64 << proteus_spec::EPOCH_BITS) {
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
        // Refresh cached cipher so subsequent records on this epoch
        // decrypt under the new key (mirror of AlphaSender::send_ratchet_frame).
        self.cipher = self.keys.aead_key();
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
        // `rx_aead_scratch` carries the most-recently-decrypted
        // plaintext (between the AEAD open and the caller's
        // `recv_record` consumer); explicitly scrub on drop.
        // The current `Plaintext` wrapper for the legacy
        // `aead::open` path zeroizes on drop already; this
        // covers the in-place hot path that uses the cached
        // cipher's `open_in_place` (which scrubs ON tag failure
        // but leaves a successful decrypt in-place until the
        // next clear).
        self.rx_aead_scratch.zeroize();
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
    /// Wall-clock duration of the handshake (from accept to
    /// completion, as measured by the server-side accept loop).
    /// `None` on the client side or for legacy in-memory tests
    /// where no accept loop exists. Operators observe via the
    /// `proteus_handshake_duration_seconds` histogram fed by the
    /// session-handler hook in main.rs.
    pub handshake_duration: Option<std::time::Duration>,
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> AlphaSession<R, W> {
    /// Builder-style setter for the authenticated user-id. Called by
    /// the server-side handshake after the allowlist check.
    #[must_use]
    pub fn with_user_id(mut self, user_id: [u8; 8]) -> Self {
        self.user_id = Some(user_id);
        self
    }

    /// Builder-style setter for the handshake duration. Called
    /// by the server-side accept loop right after the handshake
    /// completes and before invoking the user's session handler.
    #[must_use]
    pub fn with_handshake_duration(mut self, d: std::time::Duration) -> Self {
        self.handshake_duration = Some(d);
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
            handshake_duration: None,
        }
    }
}

#[cfg(test)]
mod bufwriter_coalescing_tests {
    //! Pins the iter-12 contract: when callers send multiple records
    //! WITHOUT calling `flush` between them, the inner BufWriter must
    //! coalesce them into ONE underlying write call (up to the 64 KiB
    //! `TX_BUF_CAPACITY` ceiling). Pre-iter-12, the SOCKS relay
    //! pump and the server relay forced a flush after every record,
    //! defeating this BufWriter entirely on bulk uploads/downloads.
    //!
    //! The fix is in the *callers* (socks.rs::pump,
    //! relay.rs::upstream_to_client) — they now flush only on
    //! batch boundaries (partial read = source paused). This test
    //! exists to catch any future regression that re-introduces
    //! the per-record flush at the session layer.
    use super::*;
    use std::pin::Pin;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use std::task::{Context, Poll};
    use tokio::io::AsyncWrite;

    /// Mock writer that counts how many distinct `poll_write` calls
    /// it receives. A single `BufWriter` flush manifests as ONE
    /// `poll_write` (passing the whole buffered payload).
    struct CountingWriter {
        bytes: Vec<u8>,
        writes: Arc<AtomicUsize>,
    }
    impl AsyncWrite for CountingWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.writes.fetch_add(1, Ordering::Relaxed);
            self.bytes.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn keys() -> DirectionKeys {
        DirectionKeys {
            key: zeroize::Zeroizing::new([0x9Au8; 32]),
            iv: zeroize::Zeroizing::new([0x4Cu8; 12]),
        }
    }

    /// Many small records without intermediate flush → ONE
    /// underlying writer call (BufWriter coalesces).
    #[tokio::test]
    async fn many_small_records_without_flush_coalesce_to_one_underlying_write() {
        let writes = Arc::new(AtomicUsize::new(0));
        let mw = CountingWriter {
            bytes: Vec::new(),
            writes: Arc::clone(&writes),
        };
        let metrics = std::sync::Arc::new(SessionMetrics::default());
        let mut sender = AlphaSender::new(mw, keys(), zeroize::Zeroizing::new([0u8; 32]), metrics);

        // Send 50 short records. Total bytes (50 * ~80 incl AEAD + header)
        // ≈ 4 KiB, well under TX_BUF_CAPACITY (64 KiB) — BufWriter
        // must coalesce all of them into ONE underlying write at the
        // explicit flush below.
        for i in 0..50u32 {
            let payload = i.to_be_bytes();
            sender.send_record(&payload).await.unwrap();
        }
        sender.flush().await.unwrap();
        let total_writes = writes.load(Ordering::Relaxed);
        assert_eq!(
            total_writes, 1,
            "50 small records without intermediate flush MUST coalesce to 1 underlying write, got {total_writes}",
        );
    }

    /// Per-record flush → one underlying write PER record. This is
    /// the pre-iter-12 anti-pattern; the test pins the *cost* so
    /// future readers see why the callers must NOT do this.
    #[tokio::test]
    async fn per_record_flush_emits_one_underlying_write_per_record() {
        let writes = Arc::new(AtomicUsize::new(0));
        let mw = CountingWriter {
            bytes: Vec::new(),
            writes: Arc::clone(&writes),
        };
        let metrics = std::sync::Arc::new(SessionMetrics::default());
        let mut sender = AlphaSender::new(mw, keys(), zeroize::Zeroizing::new([0u8; 32]), metrics);
        for i in 0..50u32 {
            let payload = i.to_be_bytes();
            sender.send_record(&payload).await.unwrap();
            sender.flush().await.unwrap(); // anti-pattern
        }
        let total_writes = writes.load(Ordering::Relaxed);
        assert!(
            total_writes >= 50,
            "per-record-flush MUST emit at least one underlying write per record (got {total_writes})",
        );
    }

    /// Records totalling more than TX_BUF_CAPACITY without explicit
    /// flush will auto-flush at the buffer boundary, but the
    /// boundary should be at ~64 KiB — NOT every 16 KiB the way the
    /// pre-iter-12 buffer size would have implied.
    #[tokio::test]
    async fn bulk_records_auto_flush_only_at_tx_buf_capacity_boundary() {
        let writes = Arc::new(AtomicUsize::new(0));
        let mw = CountingWriter {
            bytes: Vec::new(),
            writes: Arc::clone(&writes),
        };
        let metrics = std::sync::Arc::new(SessionMetrics::default());
        let mut sender = AlphaSender::new(mw, keys(), zeroize::Zeroizing::new([0u8; 32]), metrics);
        // Three 32 KiB records = 96 KiB raw, ~96 KiB ciphertext +
        // headers. Should trigger ~2 BufWriter flushes (96 / 64 = 1.5
        // → 2) at the TX_BUF_CAPACITY boundary, NOT 3 (one per record)
        // and NOT 6 (one per record on a 16 KiB buf).
        let payload = vec![0xA5u8; 32 * 1024];
        for _ in 0..3 {
            sender.send_record(&payload).await.unwrap();
        }
        sender.flush().await.unwrap();
        let total_writes = writes.load(Ordering::Relaxed);
        assert!(
            total_writes <= 4,
            "3 × 32 KiB records should yield ≤4 underlying writes (got {total_writes})",
        );
        assert!(
            total_writes >= 1,
            "should still produce at least one write (got {total_writes})",
        );
    }
}

#[cfg(test)]
mod rx_cursor_compaction_tests {
    //! Pins the per-record cursor optimization: `recv_record` MUST
    //! NOT memmove the `rx_buf` tail on every successfully-decoded
    //! frame. Pre-optimization the `rx_buf.drain(..consumed)` cost
    //! O(N) per record on bulk download — at pad_quantum=1280 and a
    //! 16 KiB TCP read containing ~12 cells, that was ~12 memmoves
    //! per syscall. Post-optimization compaction happens once per
    //! RX_COMPACT_THRESHOLD bytes consumed (64 KiB), so at ~1.3 KiB
    //! per cell that's ~50 records per compaction = ~1 memmove per
    //! ~4 TCP reads.
    //!
    //! We can't directly observe memmoves, but we CAN observe the
    //! state of `rx_buf` and `rx_offset` — the cursor advances on
    //! every decode, and the underlying Vec only changes length
    //! when we cross the compaction threshold.
    use super::*;
    use proteus_crypto::key_schedule::DirectionKeys;
    use proteus_wire::alpha;
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, ReadBuf};

    fn keys() -> DirectionKeys {
        DirectionKeys {
            key: zeroize::Zeroizing::new([0u8; 32]),
            iv: zeroize::Zeroizing::new([0u8; 12]),
        }
    }

    /// A reader that yields a single pre-filled blob then EOFs.
    struct OnceReader {
        data: Vec<u8>,
        pos: usize,
    }
    impl AsyncRead for OnceReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let rem = &self.data[self.pos..];
            if rem.is_empty() {
                return Poll::Ready(Ok(()));
            }
            let n = std::cmp::min(rem.len(), buf.remaining());
            buf.put_slice(&rem[..n]);
            self.pos += n;
            Poll::Ready(Ok(()))
        }
    }

    /// After consuming N small frames from a single read, the cursor
    /// must reflect the consumed prefix and the underlying Vec must
    /// NOT have been shrunk — until the cursor crosses
    /// `RX_COMPACT_THRESHOLD`.
    #[tokio::test]
    async fn rx_cursor_defers_compaction_below_threshold() {
        // Build 5 small RECORD_DATA frames sealed under the zero key.
        let session_keys = keys();
        let cipher = session_keys.aead_key();
        let mut wire = Vec::new();
        for seq in 0..5u64 {
            let combined = seq; // epoch=0
            let aad = combined.to_be_bytes();
            let mut body = b"hello".to_vec();
            cipher.seal_into(combined, &aad, &mut body).unwrap();
            wire.extend_from_slice(&alpha::encode_record(alpha::RECORD_DATA, &body));
        }
        let wire_len = wire.len();
        // Each frame is well below RX_COMPACT_THRESHOLD (64 KiB).
        assert!(
            wire_len < RX_COMPACT_THRESHOLD,
            "test pre-condition: small wire fits below the threshold"
        );

        let reader = OnceReader { data: wire, pos: 0 };
        let metrics = std::sync::Arc::new(SessionMetrics::default());
        let mut rx = AlphaReceiver::new(
            reader,
            session_keys,
            zeroize::Zeroizing::new([0u8; 32]),
            metrics,
        );

        // Decode all 5 frames.
        for _ in 0..5 {
            let rec = rx.recv_record().await.unwrap();
            assert_eq!(rec.as_deref(), Some(b"hello".as_slice()));
        }

        // Post-condition: cursor advanced over all 5 frames (= wire_len),
        // but the Vec's *length* is also wire_len (no shrink yet).
        // That means the next decode would have a zero-byte live tail —
        // exactly correct, and confirms no per-record drain happened.
        assert_eq!(
            rx.rx_offset, wire_len,
            "cursor should advance over the wire bytes"
        );
        assert_eq!(
            rx.rx_buf.len(),
            wire_len,
            "Vec length should be unchanged (no per-record drain)"
        );
    }

    /// Crossing the threshold MUST compact the buffer back to the
    /// live tail. After compaction, the cursor is 0 and the Vec
    /// length is just the unconsumed bytes.
    #[tokio::test]
    async fn rx_cursor_compacts_when_threshold_crossed() {
        let session_keys = keys();
        let cipher = session_keys.aead_key();

        // Build enough cells to push past RX_COMPACT_THRESHOLD.
        // ~6 KiB payload per record (cipher: 6 KiB + 16 tag + 3 byte hdr
        // = ~6.15 KiB) — 11 records gets us to ~67 KiB, just past 64 KiB.
        let mut wire = Vec::new();
        let n_frames = 11usize;
        for seq in 0..n_frames as u64 {
            let combined = seq; // epoch=0
            let aad = combined.to_be_bytes();
            let mut body = vec![0x42u8; 6 * 1024];
            cipher.seal_into(combined, &aad, &mut body).unwrap();
            wire.extend_from_slice(&alpha::encode_record(alpha::RECORD_DATA, &body));
        }
        assert!(
            wire.len() > RX_COMPACT_THRESHOLD,
            "test pre-condition: wire size must exceed the compaction threshold"
        );

        let reader = OnceReader { data: wire, pos: 0 };
        let metrics = std::sync::Arc::new(SessionMetrics::default());
        let mut rx = AlphaReceiver::new(
            reader,
            session_keys,
            zeroize::Zeroizing::new([0u8; 32]),
            metrics,
        );

        for _ in 0..n_frames {
            let _ = rx.recv_record().await.unwrap();
        }

        // After processing all frames, at least one compaction MUST
        // have fired (because the cumulative cursor crossed the
        // threshold). Cursor < THRESHOLD afterward, and the Vec
        // length must be <= RX_COMPACT_THRESHOLD too (the residual
        // live tail).
        assert!(
            rx.rx_offset < RX_COMPACT_THRESHOLD,
            "after threshold-crossing reads, cursor must be reset to a small value, got {}",
            rx.rx_offset
        );
        // No more bytes are in flight (everything was consumed), so
        // the buf length equals the cursor (i.e., zero live bytes).
        assert_eq!(rx.rx_buf.len(), rx.rx_offset);
    }

    /// Iter-200: `recv_record_into` MUST produce the same plaintext
    /// as `recv_record` and MUST reuse the caller's buffer (capacity
    /// stable across the second call). If this regresses, the relay
    /// hot path silently falls back to per-record allocation.
    #[tokio::test]
    async fn recv_record_into_reuses_buffer_capacity() {
        let session_keys = keys();
        let cipher = session_keys.aead_key();
        let mut wire = Vec::new();
        // Two records, ~6 KiB each.
        for seq in 0..2u64 {
            let combined = seq;
            let aad = combined.to_be_bytes();
            let mut body = vec![0xA5u8; 6 * 1024];
            cipher.seal_into(combined, &aad, &mut body).unwrap();
            wire.extend_from_slice(&alpha::encode_record(alpha::RECORD_DATA, &body));
        }
        let reader = OnceReader { data: wire, pos: 0 };
        let metrics = std::sync::Arc::new(SessionMetrics::default());
        let mut rx = AlphaReceiver::new(
            reader,
            session_keys,
            zeroize::Zeroizing::new([0u8; 32]),
            metrics,
        );

        let mut out = Vec::new();
        let r1 = rx.recv_record_into(&mut out).await.unwrap();
        assert_eq!(r1, Some(()));
        assert_eq!(out.len(), 6 * 1024);
        assert!(out.iter().all(|&b| b == 0xA5));
        let cap_after_first = out.capacity();
        assert!(cap_after_first >= 6 * 1024);

        // Second call: same buffer, same plaintext. Capacity must NOT
        // grow — recv_record_into() does clear() then extend, so a
        // sufficiently-sized backing stays put.
        let r2 = rx.recv_record_into(&mut out).await.unwrap();
        assert_eq!(r2, Some(()));
        assert_eq!(out.len(), 6 * 1024);
        assert_eq!(
            out.capacity(),
            cap_after_first,
            "recv_record_into grew capacity on second call — alloc-free invariant broken"
        );
    }

    /// `recv_record_into` and the legacy `recv_record` MUST agree on
    /// the plaintext bytes for every record type the data plane uses.
    /// This catches the case where one path refactors but the other
    /// drifts.
    #[tokio::test]
    async fn recv_record_into_matches_legacy_recv_record() {
        let session_keys = keys();
        let cipher = session_keys.aead_key();
        let mut wire_a = Vec::new();
        let mut wire_b = Vec::new();
        let payload = b"proteus iter-200 zero-alloc recv";
        for seq in 0..3u64 {
            let combined = seq;
            let aad = combined.to_be_bytes();
            let mut body = payload.to_vec();
            cipher.seal_into(combined, &aad, &mut body).unwrap();
            let bytes = alpha::encode_record(alpha::RECORD_DATA, &body);
            wire_a.extend_from_slice(&bytes);
            wire_b.extend_from_slice(&bytes);
        }
        let metrics = std::sync::Arc::new(SessionMetrics::default());
        // DirectionKeys is not Clone (intentional — secret material).
        // Build two parallel receivers from `keys()` which deterministically
        // yields the same direction key from the zero secret.
        drop(session_keys);
        let mut rx_a = AlphaReceiver::new(
            OnceReader {
                data: wire_a,
                pos: 0,
            },
            keys(),
            zeroize::Zeroizing::new([0u8; 32]),
            metrics.clone(),
        );
        let mut rx_b = AlphaReceiver::new(
            OnceReader {
                data: wire_b,
                pos: 0,
            },
            keys(),
            zeroize::Zeroizing::new([0u8; 32]),
            metrics,
        );
        for _ in 0..3 {
            let a = rx_a.recv_record().await.unwrap();
            let mut b_buf = Vec::new();
            let b = rx_b.recv_record_into(&mut b_buf).await.unwrap();
            assert_eq!(b, Some(()));
            assert_eq!(a.as_deref(), Some(b_buf.as_slice()));
            assert_eq!(b_buf, payload);
        }
    }

    /// On drop, the `rx_aead_scratch` must be scrubbed. This is a
    /// "did we wire up Zeroize?" sanity check — not a perfect test
    /// (a successful zeroize can't be observed post-drop), but
    /// catches the "forgot to add .zeroize() in Drop" regression.
    #[test]
    fn rx_aead_scratch_zeroize_on_drop_does_not_panic() {
        let reader = OnceReader {
            data: Vec::new(),
            pos: 0,
        };
        let metrics = std::sync::Arc::new(SessionMetrics::default());
        let mut rx =
            AlphaReceiver::new(reader, keys(), zeroize::Zeroizing::new([0u8; 32]), metrics);
        // Push some plaintext-looking bytes into the scratch as if a
        // decrypt had landed there.
        rx.rx_aead_scratch.extend_from_slice(b"sensitive-plaintext");
        // Drop is implicit — must not panic and must complete cleanly.
        drop(rx);
    }
}
