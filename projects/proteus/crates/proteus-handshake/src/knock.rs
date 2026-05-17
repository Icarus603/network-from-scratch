//! Probing-resistant pre-handshake knock protocol.
//!
//! ## Why this exists
//!
//! Proteus α already does cover-forwarding on auth FAIL (spec §7.5):
//! when a malformed payload arrives, the server byte-verbatim splices
//! the connection to a real HTTPS endpoint. This passes **passive**
//! DPI — the wire looks like a benign HTTPS reverse proxy.
//!
//! It does NOT pass **active** GFW probes. The standard 2024+ probe
//! sequence is:
//!
//!   1. Open a TLS connection to the candidate IP:443.
//!   2. Send a TYPICAL ClientHello (Chrome shape).
//!   3. After TLS terminates, send a benign HTTP/1.1 request
//!      (`GET / HTTP/1.1\r\nHost: ...`).
//!   4. Compare the response shape against a real HTTPS site:
//!      - Did the server's cert chain include a public CA?
//!        (Self-signed → flagged.)
//!      - Did the server respond to the GET in <100 ms with a
//!        sane HTTP 200 / 301 / 404 page body?
//!      - Does the server's TLS ALPN list match what real
//!        nginx/Caddy/Cloudflare advertise?
//!
//! Proteus α today fails step 4 because the auth-fail
//! cover-forward path only triggers AFTER the inner Proteus
//! handshake's auth tag is observed — which means by then the
//! prober has already seen Proteus-specific bytes on the wire,
//! AND the server's TLS terminator returned a non-CA-anchored
//! cert.
//!
//! ## REALITY's solution (and what this primitive enables)
//!
//! REALITY's trick: the server runs as a transparent TLS proxy
//! to a real cover site (`www.microsoft.com`, etc.). EVERY
//! connection — Proteus client OR GFW prober — first sees a
//! cert chain anchored at a public CA, served by a real backend.
//! The Proteus client signals "I'm legitimate" via a **knock**
//! embedded in the ClientHello (specifically, a magic value in
//! `session_ticket`'s leading bytes). When the server sees the
//! knock, it switches the connection from passthrough-to-cover
//! to Proteus-handshake mode AFTER the outer TLS termiates.
//! Probers don't know the knock, so their connection stays in
//! passthrough mode forever — they see the cover site's response.
//!
//! ## What this module provides
//!
//! A **cryptographic knock primitive**:
//!
//!   * Stateless on both sides except for a 32-byte
//!     `server_knock_psk` distributed out-of-band (same channel
//!     the operator already uses for `server_mlkem_pk` /
//!     `server_x25519_pk`).
//!   * Replay-resistant via a 90-second timestamp window (matches
//!     the existing anti-replay grammar in [`crate::replay`]).
//!   * 16-byte wire signature small enough to fit in a TLS
//!     `session_id` field, a `session_ticket` extension prefix,
//!     OR a ClientHello extension payload — operator choice on
//!     the wire-binding (separate iteration).
//!   * Constant-time verification (subtle::ConstantTimeEq) so
//!     timing-side-channel probes can't distinguish "almost
//!     right" knocks from "completely wrong" ones.
//!
//! ## What this is NOT
//!
//! - **Not the full REALITY-style passthrough.** That requires
//!   server-side TLS forwarding to a cover site, which is a
//!   transport-layer concern (proteus-transport-alpha). This
//!   module just provides the knock that the future passthrough
//!   layer will consume.
//! - **Not a replacement for the existing handshake auth.** The
//!   knock proves "the client knows the server PSK"; the inner
//!   Proteus handshake still has to run for cryptographic
//!   session establishment, post-quantum KEM, channel binding,
//!   etc. The knock just decides "do I drop you on the cover
//!   site or do I let you talk to Proteus".
//!
//! ## Wire format (`KnockToken`, 16 bytes)
//!
//! ```text
//!   bytes 0..4   : truncated Unix seconds (be u32, mod 2^32 —
//!                  wraps in 2106; replay window discards stale)
//!   bytes 4..16  : HMAC-SHA-256-trunc-96 of (timestamp || client_random)
//!                  where client_random is the 32-byte
//!                  TLS-ClientHello random field. Binds the knock
//!                  to THIS handshake — replaying the knock with
//!                  a different ClientHello fails verification.
//! ```
//!
//! 16 bytes is enough collision resistance for the probing use
//! case (2^96 work to forge), small enough to fit in a TLS
//! session_id (RFC 8446 allows up to 32 bytes), and trivially
//! embeddable in any extension payload. Truncating HMAC to 96
//! bits is a documented HMAC use (RFC 4868 §2.1.2 truncates
//! HMAC-SHA-256 to 128 bits routinely; 96 bits is the IPsec ESP
//! HMAC-MD5/96 precedent and remains forge-resistant under
//! standard PRF assumptions).
//!
//! ## Threat model
//!
//! Adversary capabilities:
//!   * Full passive observation of the wire.
//!   * Active replay of captured ClientHellos.
//!   * Concurrent probing — millions of probes/sec to any IP.
//!   * Knowledge of every Proteus binary + spec (open source).
//!
//! Adversary CANNOT:
//!   * Read the server_knock_psk (operator's secret).
//!   * Forge HMAC-SHA-256 without the PSK.
//!   * Wind the wall clock backward by >90 seconds at the
//!     server side.
//!
//! Result: a prober's connection arrives without a valid knock
//! → the server's transport layer keeps the connection in
//! cover-passthrough mode → the prober sees the cover site's
//! response, indistinguishable from a real `curl
//! https://cover.example/`. A legitimate Proteus client
//! computes the correct knock for THIS ClientHello's random
//! → server switches to Proteus-mode after outer TLS terminates.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// Length of the server's pre-shared knock key. Same length as
/// the existing channel-binding tags + AEAD keys throughout the
/// codebase so operators can re-use the same out-of-band key
/// distribution channel.
pub const KNOCK_PSK_LEN: usize = 32;

/// Length of the wire token: 4-byte timestamp + 12-byte HMAC-96.
pub const KNOCK_TOKEN_LEN: usize = 16;

/// Length of the timestamp field (truncated Unix seconds, big-endian u32).
pub const KNOCK_TIMESTAMP_LEN: usize = 4;

/// Length of the HMAC tag (truncated to 96 bits).
pub const KNOCK_TAG_LEN: usize = KNOCK_TOKEN_LEN - KNOCK_TIMESTAMP_LEN;

/// Max acceptable skew between the timestamp embedded in a
/// `KnockToken` and the server's wall clock. Matches the existing
/// 90-second window in [`crate::replay`] so a single broken-NTP
/// failure mode surfaces with one consistent error message.
pub const KNOCK_MAX_SKEW_SECS: u64 = 90;

/// Domain-separation tag mixed into the HMAC input. Distinct
/// from any other HMAC tag in the codebase so a primitive
/// recycled into a different role (e.g. cookie auth) can't
/// produce a knock-compatible MAC.
pub const KNOCK_DOMAIN_TAG: &[u8] = b"Proteus-Knock-v1\0";

/// Length of the TLS ClientHello random field. RFC 8446 §4.1.2.
/// Caller MUST pass exactly this many bytes when computing / verifying
/// a knock.
pub const CLIENT_RANDOM_LEN: usize = 32;

/// Errors from [`verify_knock`].
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum KnockError {
    /// Token didn't match the expected wire length.
    #[error("wrong knock token length: got {got}, want {KNOCK_TOKEN_LEN}")]
    BadTokenLength {
        /// The actual length we received.
        got: usize,
    },
    /// HMAC verification failed. Constant-time check.
    #[error("knock HMAC mismatch")]
    BadTag,
    /// Embedded timestamp was further than `KNOCK_MAX_SKEW_SECS` in
    /// the future. Suspicious; reject.
    #[error("knock timestamp is {skew}s in the future (max skew {KNOCK_MAX_SKEW_SECS})")]
    TimestampFuture {
        /// How many seconds in the future the token claimed to be.
        skew: i64,
    },
    /// Embedded timestamp was further than `KNOCK_MAX_SKEW_SECS` in
    /// the past. Likely replay; reject.
    #[error("knock timestamp is {skew}s in the past (max skew {KNOCK_MAX_SKEW_SECS})")]
    TimestampStale {
        /// How many seconds in the past the token claimed to be.
        skew: i64,
    },
}

/// Pre-shared knock key. Operator generates this at provisioning
/// time and distributes alongside the existing
/// `server_mlkem_pk` / `server_x25519_pk` bundle.
///
/// Wrapped in [`Zeroizing`] so the bytes don't linger in the
/// allocator after the binary exits.
#[derive(Debug, Clone)]
pub struct KnockPsk(Zeroizing<[u8; KNOCK_PSK_LEN]>);

impl KnockPsk {
    /// Wrap an existing 32-byte key (loaded from disk by the
    /// caller).
    #[must_use]
    pub fn from_bytes(bytes: [u8; KNOCK_PSK_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Const-eq comparison against a raw byte slice (used by
    /// integration tests that need to verify "two operators
    /// loaded the same bytes"). Not for hot-path use.
    pub fn raw_bytes(&self) -> &[u8; KNOCK_PSK_LEN] {
        &self.0
    }
}

/// Compute a fresh knock token for the supplied `client_random`
/// AND `unix_seconds` AND PSK.
///
/// The operator-facing helper. Used by:
///   * the proteus-client side: mints a fresh token to send to
///     the server (embedded in TLS session_id / session_ticket /
///     extension payload — choice of binding is a separate
///     transport-layer concern).
///   * test fixtures verifying round-trip correctness.
///
/// Production callers MUST supply `unix_seconds` from a real
/// clock (typically `SystemTime::now()`); the function does not
/// read a clock itself so it stays pure / fuzzable.
#[must_use]
pub fn compute_knock(
    psk: &KnockPsk,
    client_random: &[u8; CLIENT_RANDOM_LEN],
    unix_seconds: u64,
) -> [u8; KNOCK_TOKEN_LEN] {
    let ts_bytes: [u8; KNOCK_TIMESTAMP_LEN] = (unix_seconds as u32).to_be_bytes();
    let tag = hmac_truncated_96(psk, &ts_bytes, client_random);
    let mut out = [0u8; KNOCK_TOKEN_LEN];
    out[..KNOCK_TIMESTAMP_LEN].copy_from_slice(&ts_bytes);
    out[KNOCK_TIMESTAMP_LEN..].copy_from_slice(&tag);
    out
}

/// Verify a knock token against the supplied `client_random` +
/// `now_unix_seconds`. Server-facing helper.
///
/// Verification flow:
///   1. Length check.
///   2. Compute expected HMAC over the embedded timestamp +
///      client_random.
///   3. Constant-time tag compare. Mismatch → reject WITHOUT
///      considering timestamp (avoids leaking via early-out).
///   4. Timestamp window check (`|now - embedded_ts| <= 90 s`).
///
/// The order matters for side-channel resistance: probers
/// sending random tokens must see the EXACT SAME wall-clock
/// cost regardless of how close their token was to a valid
/// one. Tag check before timestamp check means a future probe
/// that learns the timestamp window (trivial — just sniff one
/// real client connection) still can't distinguish "PSK guess
/// was wrong" from "PSK was right but clock was off" via
/// timing.
pub fn verify_knock(
    psk: &KnockPsk,
    client_random: &[u8; CLIENT_RANDOM_LEN],
    token: &[u8],
    now_unix_seconds: u64,
) -> Result<(), KnockError> {
    if token.len() != KNOCK_TOKEN_LEN {
        return Err(KnockError::BadTokenLength { got: token.len() });
    }
    let ts_bytes: [u8; KNOCK_TIMESTAMP_LEN] = token[..KNOCK_TIMESTAMP_LEN]
        .try_into()
        .expect("slice length checked above");
    let received_tag = &token[KNOCK_TIMESTAMP_LEN..];
    let expected_tag = hmac_truncated_96(psk, &ts_bytes, client_random);
    // Constant-time compare.
    if expected_tag.ct_eq(received_tag).unwrap_u8() != 1 {
        return Err(KnockError::BadTag);
    }
    // Tag matched — check timestamp window.
    let embedded_secs = u32::from_be_bytes(ts_bytes) as u64;
    // Use i128 to safely handle both directions (wall clock
    // behind embedded ts AND ahead of it) without underflow.
    let skew_i = now_unix_seconds as i128 - embedded_secs as i128;
    if skew_i > KNOCK_MAX_SKEW_SECS as i128 {
        return Err(KnockError::TimestampStale {
            skew: skew_i as i64,
        });
    }
    if skew_i < -(KNOCK_MAX_SKEW_SECS as i128) {
        return Err(KnockError::TimestampFuture {
            skew: (-skew_i) as i64,
        });
    }
    Ok(())
}

/// HMAC-SHA-256 truncated to 96 bits, with domain separation.
/// Output is the leading 12 bytes of `HMAC(psk, domain_tag ||
/// timestamp || client_random)`.
fn hmac_truncated_96(
    psk: &KnockPsk,
    timestamp: &[u8; KNOCK_TIMESTAMP_LEN],
    client_random: &[u8; CLIENT_RANDOM_LEN],
) -> [u8; KNOCK_TAG_LEN] {
    let mut mac = HmacSha256::new_from_slice(psk.raw_bytes()).expect("HMAC accepts any key length");
    mac.update(KNOCK_DOMAIN_TAG);
    mac.update(timestamp);
    mac.update(client_random);
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; KNOCK_TAG_LEN];
    out.copy_from_slice(&full[..KNOCK_TAG_LEN]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn psk_alpha() -> KnockPsk {
        KnockPsk::from_bytes([0xA1; KNOCK_PSK_LEN])
    }

    fn psk_beta() -> KnockPsk {
        KnockPsk::from_bytes([0xB2; KNOCK_PSK_LEN])
    }

    fn random_alpha() -> [u8; CLIENT_RANDOM_LEN] {
        let mut r = [0u8; CLIENT_RANDOM_LEN];
        for (i, b) in r.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37);
        }
        r
    }

    #[test]
    fn round_trip_compute_then_verify_succeeds() {
        let psk = psk_alpha();
        let random = random_alpha();
        let now = 1_715_900_000u64;
        let tok = compute_knock(&psk, &random, now);
        assert_eq!(tok.len(), KNOCK_TOKEN_LEN);
        verify_knock(&psk, &random, &tok, now).expect("fresh knock must verify");
    }

    #[test]
    fn verify_fails_with_wrong_psk() {
        let random = random_alpha();
        let now = 1_715_900_000u64;
        let tok = compute_knock(&psk_alpha(), &random, now);
        let err = verify_knock(&psk_beta(), &random, &tok, now).unwrap_err();
        assert_eq!(err, KnockError::BadTag);
    }

    #[test]
    fn verify_fails_with_wrong_client_random() {
        let psk = psk_alpha();
        let random_a = random_alpha();
        let mut random_b = random_alpha();
        random_b[0] ^= 0x01;
        let now = 1_715_900_000u64;
        let tok = compute_knock(&psk, &random_a, now);
        let err = verify_knock(&psk, &random_b, &tok, now).unwrap_err();
        assert_eq!(err, KnockError::BadTag);
    }

    #[test]
    fn verify_fails_on_truncated_token() {
        let psk = psk_alpha();
        let random = random_alpha();
        let tok = compute_knock(&psk, &random, 1_715_900_000);
        let truncated = &tok[..KNOCK_TOKEN_LEN - 1];
        let err = verify_knock(&psk, &random, truncated, 1_715_900_000).unwrap_err();
        assert!(matches!(err, KnockError::BadTokenLength { got } if got == KNOCK_TOKEN_LEN - 1));
    }

    #[test]
    fn verify_fails_on_oversized_token() {
        let psk = psk_alpha();
        let random = random_alpha();
        let tok = compute_knock(&psk, &random, 1_715_900_000);
        let mut padded = tok.to_vec();
        padded.push(0);
        let err = verify_knock(&psk, &random, &padded, 1_715_900_000).unwrap_err();
        assert!(matches!(err, KnockError::BadTokenLength { got } if got == KNOCK_TOKEN_LEN + 1));
    }

    #[test]
    fn verify_succeeds_within_skew_window_into_past() {
        let psk = psk_alpha();
        let random = random_alpha();
        let issued_at = 1_715_900_000u64;
        let tok = compute_knock(&psk, &random, issued_at);
        // 60 s later (within the 90 s window).
        verify_knock(&psk, &random, &tok, issued_at + 60).expect("60s skew should pass");
    }

    #[test]
    fn verify_fails_outside_skew_window_into_past() {
        let psk = psk_alpha();
        let random = random_alpha();
        let issued_at = 1_715_900_000u64;
        let tok = compute_knock(&psk, &random, issued_at);
        // 91 s later (past the 90 s window).
        let err = verify_knock(&psk, &random, &tok, issued_at + 91).unwrap_err();
        assert!(matches!(err, KnockError::TimestampStale { skew } if skew == 91));
    }

    #[test]
    fn verify_succeeds_within_skew_window_into_future() {
        // Client's clock 60s ahead of server's. Within window.
        let psk = psk_alpha();
        let random = random_alpha();
        let server_now = 1_715_900_000u64;
        let client_now = server_now + 60;
        let tok = compute_knock(&psk, &random, client_now);
        verify_knock(&psk, &random, &tok, server_now).expect("60s future-skew should pass");
    }

    #[test]
    fn verify_fails_outside_skew_window_into_future() {
        let psk = psk_alpha();
        let random = random_alpha();
        let server_now = 1_715_900_000u64;
        let client_now = server_now + 91;
        let tok = compute_knock(&psk, &random, client_now);
        let err = verify_knock(&psk, &random, &tok, server_now).unwrap_err();
        assert!(matches!(err, KnockError::TimestampFuture { skew } if skew == 91));
    }

    #[test]
    fn timestamp_check_runs_only_after_tag_check_passes() {
        // Sanity: if the tag is bad AND the timestamp is way out
        // of range, the error returned MUST be BadTag (the tag
        // check is the FIRST check). Documents the side-channel
        // resistance order — a prober that knows the server's
        // clock skew can't distinguish "PSK wrong" from "PSK
        // right + clock off".
        let random = random_alpha();
        let bad_tok = compute_knock(&psk_alpha(), &random, 1_000_000_000u64);
        // Verify with wrong PSK at a wildly different clock —
        // both checks would fail, but tag check is first.
        let err = verify_knock(&psk_beta(), &random, &bad_tok, 2_000_000_000u64).unwrap_err();
        assert_eq!(err, KnockError::BadTag);
    }

    #[test]
    fn two_distinct_psks_produce_distinct_tokens() {
        let random = random_alpha();
        let now = 1_715_900_000u64;
        let tok_a = compute_knock(&psk_alpha(), &random, now);
        let tok_b = compute_knock(&psk_beta(), &random, now);
        // Same timestamp prefix.
        assert_eq!(&tok_a[..KNOCK_TIMESTAMP_LEN], &tok_b[..KNOCK_TIMESTAMP_LEN]);
        // Different tag suffix.
        assert_ne!(&tok_a[KNOCK_TIMESTAMP_LEN..], &tok_b[KNOCK_TIMESTAMP_LEN..]);
    }

    #[test]
    fn replay_with_different_random_fails() {
        // The PRIMARY anti-replay property — a captured token
        // is bound to its original ClientHello's random and can
        // NOT be replayed with a new random.
        let psk = psk_alpha();
        let random_orig = random_alpha();
        let mut random_replay = random_alpha();
        random_replay[31] ^= 0xff;
        let now = 1_715_900_000u64;
        let tok = compute_knock(&psk, &random_orig, now);
        // The capturing prober is within the 90 s window AND
        // has the right tag-input for random_orig, but the
        // server sees a NEW ClientHello with random_replay.
        let err = verify_knock(&psk, &random_replay, &tok, now).unwrap_err();
        assert_eq!(err, KnockError::BadTag);
    }

    #[test]
    fn domain_separation_tag_prevents_cross_use() {
        // If a future iteration recycles HMAC-SHA256 for a
        // different role (cookie auth, etc.), the domain
        // separation tag MUST keep the two MACs disjoint.
        // This test pins the bytes of the domain tag so
        // changing it breaks the test (and any deployed knock
        // PSKs become incompatible — exactly what we want).
        assert_eq!(KNOCK_DOMAIN_TAG, b"Proteus-Knock-v1\0");
    }

    #[test]
    fn token_constants_are_pinned() {
        // Wire-format invariants. Operators baking knock-token
        // parsers on the receive side rely on these never
        // changing without a version bump.
        assert_eq!(KNOCK_PSK_LEN, 32);
        assert_eq!(KNOCK_TOKEN_LEN, 16);
        assert_eq!(KNOCK_TIMESTAMP_LEN, 4);
        assert_eq!(KNOCK_TAG_LEN, 12);
        assert_eq!(KNOCK_MAX_SKEW_SECS, 90);
        assert_eq!(CLIENT_RANDOM_LEN, 32);
    }
}
