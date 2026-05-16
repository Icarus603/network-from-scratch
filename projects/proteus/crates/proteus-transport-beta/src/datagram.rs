//! Proteus-AEAD'd QUIC DATAGRAM channel.
//!
//! Adds a **zero-HoL unreliable** side channel on top of the
//! established β-profile session. Same handshake, same crypto suite
//! (ChaCha20-Poly1305), but the keys are independently derived via
//! HKDF-Expand-Label so the datagram channel's nonce counter can
//! never collide with the reliable stream's nonce counter.
//!
//! ## Why this matters
//!
//! The current β profile uses ONE QUIC bidirectional stream — every
//! byte must arrive in order, so a single packet loss head-of-line-
//! blocks every byte behind it. That's the same failure mode TCP
//! has and a major part of why Hysteria2's DATAGRAM-based design
//! wins on lossy paths.
//!
//! With this module, applications that don't need ordering (DNS,
//! RTP, QUIC-inside-QUIC, the inner "media path" of a video call)
//! can drop into the unreliable channel and not pay the HoL tax.
//!
//! ## Crypto
//!
//! Keys derived via:
//! - `key = HKDF-Expand-Label(send_secret, "proteus-β-datagram-key-v1", "", 32)`
//! - `iv  = HKDF-Expand-Label(send_secret, "proteus-β-datagram-iv-v1",  "", 12)`
//!
//! Per-datagram nonce: `iv ^ counter_be64_padded_to_12`. Counter
//! starts at 0, increments by 1 per send. AAD is empty (the
//! ciphertext itself already binds the connection via the derived
//! key, and DATAGRAM frames carry no application-level metadata).
//!
//! ## Replay / reordering policy
//!
//! Per RFC 9221 § 5.2 DATAGRAM frames may be reordered, duplicated,
//! or dropped. We **reject** duplicates via a 64-entry sliding
//! window on the receive nonce counter — strictly stronger than
//! the "anti-replay window for the reliable stream" defense, since
//! datagrams have no inherent ordering. Forward gaps are tolerated
//! (caller sees them as drops).
//!
//! ## What this does NOT solve
//!
//! - **Multipath**: still one QUIC connection. M3+.
//! - **Auth-in-datagram**: the AEAD already authenticates; we do
//!   not add a separate MAC.
//! - **MTU discovery**: callers must check
//!   [`Channel::max_datagram_size`] before sending. quinn surfaces
//!   the negotiated peer limit.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use proteus_crypto::aead;
use proteus_transport_alpha::session::AlphaSession;
use tokio::io::{AsyncRead, AsyncWrite};
use zeroize::Zeroizing;

use crate::error::BetaError;

/// HKDF-Expand-Label tags for the two direction key/iv pairs. The
/// `v1` suffix exists so we can rotate without ambiguity in a
/// future revision.
const LABEL_KEY: &[u8] = b"proteus-beta-datagram-key-v1";
const LABEL_IV: &[u8] = b"proteus-beta-datagram-iv-v1";

const KEY_LEN: usize = 32;
const IV_LEN: usize = 12;
const REPLAY_WINDOW: usize = 64;

/// One direction's per-datagram crypto state. Caller MUST keep this
/// alive for the lifetime of the [`Channel`]. The key is zeroized
/// on drop.
struct DirectionState {
    key: Zeroizing<Vec<u8>>,
    iv: Zeroizing<Vec<u8>>,
    /// Send: next counter to use. Receive: highest seen counter.
    counter: AtomicU64,
    /// Replay-window bitmap (receive side only — unused on send).
    /// Each bit `b` tracks whether `highest - b` has been seen.
    replay: Mutex<u64>,
}

impl DirectionState {
    fn new(key: Zeroizing<Vec<u8>>, iv: Zeroizing<Vec<u8>>) -> Self {
        Self {
            key,
            iv,
            counter: AtomicU64::new(0),
            replay: Mutex::new(0),
        }
    }

    fn key_array(&self) -> [u8; KEY_LEN] {
        let mut k = [0u8; KEY_LEN];
        k.copy_from_slice(&self.key);
        k
    }

    fn iv_array(&self) -> [u8; IV_LEN] {
        let mut i = [0u8; IV_LEN];
        i.copy_from_slice(&self.iv);
        i
    }

    /// Receive-side replay check. Returns `true` if `counter` is
    /// new (caller proceeds), `false` if it's already-seen or
    /// outside the window (caller drops the datagram).
    fn check_replay(&self, counter: u64) -> bool {
        let mut window = self.replay.lock().expect("datagram replay mutex");
        let highest = self.counter.load(Ordering::Relaxed);
        if counter > highest {
            // Shift the bitmap left by the delta and mark the new
            // highest as seen.
            let shift = counter - highest;
            if shift >= 64 {
                *window = 1;
            } else {
                *window = (*window << shift) | 1;
            }
            self.counter.store(counter, Ordering::Relaxed);
            true
        } else {
            let delta = highest - counter;
            if delta >= REPLAY_WINDOW as u64 {
                return false; // too old
            }
            let bit = 1u64 << delta;
            if *window & bit != 0 {
                return false; // duplicate
            }
            *window |= bit;
            true
        }
    }
}

/// QUIC DATAGRAM channel bound to an established β session.
///
/// One per direction-pair; clone-cheap (internal `Arc`s).
#[derive(Clone)]
pub struct Channel {
    send: Arc<DirectionState>,
    recv: Arc<DirectionState>,
    conn: quinn::Connection,
}

impl Channel {
    /// Derive both direction keys from `session` and bind to the
    /// `conn` for actual datagram send/receive. The session's
    /// reliable stream is unaffected — applications can use both
    /// channels concurrently.
    pub fn from_session<R, W>(
        session: &AlphaSession<R, W>,
        conn: quinn::Connection,
    ) -> Result<Self, BetaError>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let send_key = session.sender.derive_subkey(LABEL_KEY, KEY_LEN)?;
        let send_iv = session.sender.derive_subkey(LABEL_IV, IV_LEN)?;
        let recv_key = session.receiver.derive_subkey(LABEL_KEY, KEY_LEN)?;
        let recv_iv = session.receiver.derive_subkey(LABEL_IV, IV_LEN)?;
        Ok(Self {
            send: Arc::new(DirectionState::new(send_key, send_iv)),
            recv: Arc::new(DirectionState::new(recv_key, recv_iv)),
            conn,
        })
    }

    /// Maximum **plaintext** payload that fits in one datagram,
    /// after the AEAD overhead (16 bytes Poly1305 tag + 8 bytes
    /// counter prefix). Returns `None` if the peer doesn't support
    /// DATAGRAM frames.
    #[must_use]
    pub fn max_plaintext_size(&self) -> Option<usize> {
        // quinn returns the max ciphertext payload it will accept.
        // We use 8 bytes for the counter + 16 bytes for the Poly1305
        // tag, so plaintext capacity is (limit - 24).
        self.conn.max_datagram_size()?.checked_sub(24)
    }

    /// Send a datagram. Returns `Err(BetaError::Quinn*)` if the
    /// peer hasn't negotiated DATAGRAM support, the payload is too
    /// large, or QUIC back-pressure rejects the write.
    pub fn try_send(&self, plaintext: &[u8]) -> Result<(), BetaError> {
        let counter = self.send.counter.fetch_add(1, Ordering::Relaxed);
        let key = self.send.key_array();
        let iv = self.send.iv_array();
        let mut framed =
            aead::seal(&key, &iv, counter, &[], plaintext).map_err(|_| BetaError::CryptoInstall)?;
        // 8-byte counter prefix so the receiver knows which nonce
        // to reconstruct. Plain BE-encoded u64.
        let mut payload = Vec::with_capacity(8 + framed.len());
        payload.extend_from_slice(&counter.to_be_bytes());
        payload.append(&mut framed);
        self.conn
            .send_datagram(payload.into())
            .map_err(|e| BetaError::Io(std::io::Error::other(format!("send_datagram: {e}"))))?;
        Ok(())
    }

    /// Receive one datagram. Drops replays / too-old datagrams
    /// silently and re-awaits the next valid one. Cancellation-safe
    /// at await points.
    pub async fn recv(&self) -> Result<Vec<u8>, BetaError> {
        loop {
            let raw = self
                .conn
                .read_datagram()
                .await
                .map_err(BetaError::QuinnConn)?;
            if raw.len() < 8 + 16 {
                // smaller than counter prefix + tag — malformed
                continue;
            }
            let mut ctr_bytes = [0u8; 8];
            ctr_bytes.copy_from_slice(&raw[..8]);
            let counter = u64::from_be_bytes(ctr_bytes);
            let ciphertext = &raw[8..];
            // Replay window check BEFORE we pay the AEAD-open cost,
            // so a flood of replays from a network observer can't
            // burn CPU.
            if !self.recv.check_replay(counter) {
                continue;
            }
            let key = self.recv.key_array();
            let iv = self.recv.iv_array();
            match aead::open(&key, &iv, counter, &[], ciphertext) {
                Ok(plain) => return Ok(plain.into_vec()),
                Err(_) => continue, // bad-AEAD — silently drop
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_state() -> DirectionState {
        DirectionState::new(
            Zeroizing::new(vec![0u8; KEY_LEN]),
            Zeroizing::new(vec![0u8; IV_LEN]),
        )
    }

    #[test]
    fn replay_window_accepts_fresh_counters() {
        let s = fresh_state();
        for i in 1..=10u64 {
            assert!(s.check_replay(i), "counter {i} should be accepted");
        }
    }

    #[test]
    fn replay_window_rejects_duplicates() {
        let s = fresh_state();
        assert!(s.check_replay(5));
        assert!(
            !s.check_replay(5),
            "duplicate of just-seen counter must be rejected"
        );
    }

    #[test]
    fn replay_window_tolerates_reordering() {
        let s = fresh_state();
        // Receive 1, 2, 3, then 5, then the delayed 4. All should
        // be accepted as-new since none are duplicates.
        assert!(s.check_replay(1));
        assert!(s.check_replay(2));
        assert!(s.check_replay(3));
        assert!(s.check_replay(5));
        assert!(s.check_replay(4), "delayed 4 after 5 must be accepted");
        // But a duplicate 4 must be rejected.
        assert!(!s.check_replay(4));
    }

    #[test]
    fn replay_window_rejects_too_old() {
        let s = fresh_state();
        assert!(s.check_replay(100));
        // 100 - 64 = 36, so anything <= 36 is outside the window.
        assert!(!s.check_replay(36), "older than window must be rejected");
        // Edge: exactly at window boundary (highest - 63) is in.
        assert!(s.check_replay(37));
    }

    #[test]
    fn replay_window_handles_large_jump() {
        let s = fresh_state();
        assert!(s.check_replay(1));
        assert!(s.check_replay(1_000_000));
        // After a >64 jump, everything below the new high - 64 is
        // out of the window.
        assert!(!s.check_replay(1));
        // But the new neighborhood is fresh.
        assert!(s.check_replay(999_999));
    }
}
