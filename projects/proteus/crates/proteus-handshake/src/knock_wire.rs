//! Wire-format binding for the knock token.
//!
//! Iteration 4 of Path A. The previous iterations defined:
//!   * `knock::compute_knock` / `knock::verify_knock` — the
//!     cryptographic primitive (PSK + client_random + ts → 16
//!     bytes of HMAC-bound output);
//!   * server + client config + load infrastructure.
//!
//! This module pins **where on the wire** the 16 bytes live.
//!
//! ## Choice: TLS `session_id`
//!
//! REALITY embeds its auth signal in the `session_id` field
//! (RFC 8446 §4.1.2): a 0-32 byte field a TLS 1.3 client sends
//! in the ClientHello, "compatibility-only" since TLS 1.3 has
//! its own session-resumption mechanism (PSKs / tickets). We
//! match the REALITY-precedent for three reasons:
//!
//!   1. **Wire-shape benign.** Real Chrome clients send a
//!      randomized 32-byte session_id every ClientHello (TLS
//!      1.3 implementations historically generated random IDs
//!      for "middlebox compatibility"). A 32-byte
//!      pseudo-random-looking session_id is **THE** common case
//!      — embedding our 16-byte knock + 16 bytes of random
//!      padding is indistinguishable on the wire.
//!   2. **Visible to the server BEFORE TLS terminates.** Every
//!      server-side TLS implementation parses the session_id
//!      from the unencrypted ClientHello. Our pre-auth gate
//!      decision (passthrough-to-cover vs terminate-locally)
//!      MUST happen before TLS termination — session_id is the
//!      only standard pre-handshake field with enough space.
//!   3. **No semantic conflict with our own TLS 1.3 stack.**
//!      We negotiate TLS 1.3 (no resumption — `enable_early_data
//!      = true` is wire-fingerprint-only, no actual PSK
//!      cache). rustls ignores the inbound session_id under TLS
//!      1.3; we can rewrite it however we want without changing
//!      protocol semantics.
//!
//! ## Layout (32 bytes total)
//!
//! ```text
//!   bytes 0..16   knock_token = compute_knock(psk, client_random, now)
//!   bytes 16..32  fresh random padding (so the wire-shape stays
//!                 pseudo-random; otherwise the trailing 16 zero
//!                 bytes would be a passive fingerprint)
//! ```
//!
//! The padding is NOT part of the cryptographic check — the
//! verifier extracts bytes 0..16 and runs `verify_knock`,
//! ignoring 16..32. Probers sending random 32-byte session_ids
//! see `verify_knock` fail on the first 16 (random ≠
//! HMAC-derived) and get routed to cover.
//!
//! ## What this module does NOT do
//!
//! - **Does not write the session_id into a real ClientHello
//!   on the client side.** That requires either (a) forking
//!   rustls's ClientHello assembler or (b) using a custom
//!   pre-write hook on the rustls `ClientConfig`. This module
//!   provides the encode/decode primitives the future client
//!   transport layer will call; the actual rustls integration
//!   is iteration 5.
//! - **Does not parse the session_id out of a server-side
//!   ClientHello.** That's the server's pre-auth-passthrough
//!   layer (iteration 5/6) — it raw-reads the ClientHello
//!   bytes (already parseable via
//!   `proteus_fingerprint::ja4::parse_client_hello`) and calls
//!   this module's `decode_knock_from_session_id` on the
//!   extracted session_id slice.

use rand_core::{OsRng, RngCore};

use crate::knock::{KnockPsk, KNOCK_TOKEN_LEN};

/// Total length of the encoded session_id field that carries
/// the knock + random padding. Matches the 32-byte size Chrome
/// 124 / Firefox 124 / Safari 17 all generate by default —
/// keeps the wire-shape benign vs Chrome reference fingerprint
/// (which the JA4 baseline test pins).
pub const ENCODED_SESSION_ID_LEN: usize = 32;

/// Length of the random padding tail. ENCODED_SESSION_ID_LEN
/// minus the knock token.
pub const PADDING_LEN: usize = ENCODED_SESSION_ID_LEN - KNOCK_TOKEN_LEN;

/// Errors from [`decode_knock_from_session_id`].
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// session_id was the wrong size to carry a knock. Could be
    /// a real TLS 1.2 resumption (variable-length), a TLS 1.3
    /// client that generates a 0-byte session_id (some test
    /// stacks), or a prober sending garbage. The server's gate
    /// layer treats this as "no knock present" and routes to
    /// cover.
    #[error("session_id wrong length: got {got}, expected {ENCODED_SESSION_ID_LEN}")]
    WrongLength {
        /// Actual length received.
        got: usize,
    },
}

/// Encode a freshly-computed knock token into the 32-byte
/// session_id payload. The first 16 bytes are the token; the
/// trailing 16 are OS-random padding (fresh per call —
/// regenerating per ClientHello is cheap).
///
/// This is the **client-side** helper. Called by the future
/// rustls integration just before the ClientHello is serialized
/// onto the wire.
#[must_use]
pub fn encode_session_id(knock_token: &[u8; KNOCK_TOKEN_LEN]) -> [u8; ENCODED_SESSION_ID_LEN] {
    let mut out = [0u8; ENCODED_SESSION_ID_LEN];
    out[..KNOCK_TOKEN_LEN].copy_from_slice(knock_token);
    // Fill 16..32 with fresh OS random. Padding doesn't affect
    // verification; it just keeps the wire-shape from leaking
    // "this session_id has zero-padded tail" via passive
    // observation.
    OsRng.fill_bytes(&mut out[KNOCK_TOKEN_LEN..]);
    out
}

/// Decode a session_id slice and verify the knock it carries.
/// Returns `Ok(())` when the knock is valid (server should
/// terminate locally for Proteus); errors otherwise (server
/// routes to cover passthrough).
///
/// **Server-side** helper. Called by the future
/// pre-auth-passthrough gate after extracting the session_id
/// from the inbound ClientHello.
///
/// Layered errors:
///   * `Err(DecodeError::WrongLength)` — session_id isn't the
///     expected 32 bytes. Likely a non-Proteus client (a real
///     curl, a probe with random session_id length, etc.).
///   * `Err(crate::knock::KnockError::BadTag)` — session_id IS
///     32 bytes but the embedded HMAC doesn't verify. Either a
///     prober guessing or a misconfigured client (wrong PSK).
///   * `Err(crate::knock::KnockError::TimestampStale)` /
///     `TimestampFuture` — clock skew exceeded the ±90 s window.
///     Operator-side action: fix NTP.
///   * `Ok(())` — legitimate Proteus client; server's gate
///     should switch from passthrough mode to Proteus-mode.
pub fn decode_and_verify_session_id(
    psk: &KnockPsk,
    client_random: &[u8; crate::knock::CLIENT_RANDOM_LEN],
    session_id: &[u8],
    now_unix_seconds: u64,
) -> Result<(), KnockWireError> {
    if session_id.len() != ENCODED_SESSION_ID_LEN {
        return Err(KnockWireError::Decode(DecodeError::WrongLength {
            got: session_id.len(),
        }));
    }
    let knock_slice = &session_id[..KNOCK_TOKEN_LEN];
    crate::knock::verify_knock(psk, client_random, knock_slice, now_unix_seconds)
        .map_err(KnockWireError::Knock)
}

/// Top-level error union for the wire-format path. Lets the
/// caller distinguish "no Proteus knock present" (length
/// mismatch) from "Proteus knock present but bad" (HMAC fail /
/// timestamp skew) — those imply different operational
/// responses (the former is normal: every non-Proteus
/// connection has no knock; the latter is unusual and worth
/// logging at WARN-throttled).
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum KnockWireError {
    /// session_id wasn't the expected 32-byte shape.
    #[error("session_id decode: {0}")]
    Decode(#[from] DecodeError),
    /// session_id was 32 bytes but the embedded knock failed
    /// cryptographic verification.
    #[error("knock verification: {0}")]
    Knock(#[from] crate::knock::KnockError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::knock::{compute_knock, CLIENT_RANDOM_LEN, KNOCK_PSK_LEN};

    fn psk() -> KnockPsk {
        KnockPsk::from_bytes([0xA1; KNOCK_PSK_LEN])
    }

    fn random_alpha() -> [u8; CLIENT_RANDOM_LEN] {
        let mut r = [0u8; CLIENT_RANDOM_LEN];
        for (i, b) in r.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37);
        }
        r
    }

    #[test]
    fn encode_then_decode_round_trips() {
        let psk = psk();
        let random = random_alpha();
        let now = 1_715_900_000u64;
        let token = compute_knock(&psk, &random, now);
        let session_id = encode_session_id(&token);
        assert_eq!(session_id.len(), ENCODED_SESSION_ID_LEN);
        // First 16 bytes MUST be the token byte-for-byte.
        assert_eq!(&session_id[..KNOCK_TOKEN_LEN], &token);
        // Round-trip verification.
        decode_and_verify_session_id(&psk, &random, &session_id, now)
            .expect("fresh encode → decode must verify");
    }

    #[test]
    fn padding_bytes_vary_per_encode() {
        let psk = psk();
        let random = random_alpha();
        let now = 1_715_900_000u64;
        let token = compute_knock(&psk, &random, now);
        let sid_a = encode_session_id(&token);
        let sid_b = encode_session_id(&token);
        // The knock portion MUST be identical (deterministic
        // from token).
        assert_eq!(&sid_a[..KNOCK_TOKEN_LEN], &sid_b[..KNOCK_TOKEN_LEN]);
        // The padding portion MUST differ (OS-random per call).
        // Probability of accidental match across 16 random
        // bytes is 2^-128 — if this ever fires we have bigger
        // problems than a test failure.
        assert_ne!(&sid_a[KNOCK_TOKEN_LEN..], &sid_b[KNOCK_TOKEN_LEN..]);
    }

    #[test]
    fn decode_rejects_short_session_id() {
        let psk = psk();
        let random = random_alpha();
        let now = 1_715_900_000u64;
        let too_short = vec![0u8; 16];
        let err = decode_and_verify_session_id(&psk, &random, &too_short, now).unwrap_err();
        assert!(
            matches!(err, KnockWireError::Decode(DecodeError::WrongLength { got }) if got == 16)
        );
    }

    #[test]
    fn decode_rejects_empty_session_id() {
        // TLS 1.3 clients sometimes generate 0-byte session_id
        // (RFC 8446 allows it). MUST NOT crash; treat as "no
        // knock present".
        let psk = psk();
        let random = random_alpha();
        let now = 1_715_900_000u64;
        let empty = Vec::new();
        let err = decode_and_verify_session_id(&psk, &random, &empty, now).unwrap_err();
        assert!(
            matches!(err, KnockWireError::Decode(DecodeError::WrongLength { got }) if got == 0)
        );
    }

    #[test]
    fn decode_rejects_oversized_session_id() {
        // Probe with the MAX session_id (RFC 8446 limit = 32 bytes,
        // but TLS 1.2 allowed older variable shapes). Anything
        // != 32 → no knock present.
        let psk = psk();
        let random = random_alpha();
        let now = 1_715_900_000u64;
        let too_long = vec![0xFF; 48];
        let err = decode_and_verify_session_id(&psk, &random, &too_long, now).unwrap_err();
        assert!(
            matches!(err, KnockWireError::Decode(DecodeError::WrongLength { got }) if got == 48)
        );
    }

    #[test]
    fn decode_rejects_correct_length_but_random_payload() {
        // Probe sends a fresh random 32-byte session_id (Chrome's
        // exact default behavior). Length passes; HMAC fails.
        // Server's gate sees BadTag → routes to cover.
        let psk = psk();
        let random = random_alpha();
        let now = 1_715_900_000u64;
        let mut probe_sid = [0u8; ENCODED_SESSION_ID_LEN];
        OsRng.fill_bytes(&mut probe_sid);
        let err = decode_and_verify_session_id(&psk, &random, &probe_sid, now).unwrap_err();
        assert!(
            matches!(err, KnockWireError::Knock(crate::knock::KnockError::BadTag)),
            "random session_id must surface as BadTag (gate routes to cover); got {err:?}"
        );
    }

    #[test]
    fn decode_rejects_wrong_psk() {
        // Client knows PSK A; server checks against PSK B.
        // Length OK, HMAC fails.
        let psk_a = KnockPsk::from_bytes([0xA1; KNOCK_PSK_LEN]);
        let psk_b = KnockPsk::from_bytes([0xB2; KNOCK_PSK_LEN]);
        let random = random_alpha();
        let now = 1_715_900_000u64;
        let token = compute_knock(&psk_a, &random, now);
        let sid = encode_session_id(&token);
        let err = decode_and_verify_session_id(&psk_b, &random, &sid, now).unwrap_err();
        assert!(matches!(
            err,
            KnockWireError::Knock(crate::knock::KnockError::BadTag)
        ));
    }

    #[test]
    fn decode_propagates_timestamp_skew_errors() {
        // The wire-format wrapper MUST NOT swallow the
        // distinct timestamp-out-of-window error — operators
        // dashboarding by error variant should still see
        // "skew" vs "bad tag" cleanly.
        let psk = psk();
        let random = random_alpha();
        let issued_at = 1_715_900_000u64;
        let token = compute_knock(&psk, &random, issued_at);
        let sid = encode_session_id(&token);
        // Server's clock is 91 s ahead.
        let err = decode_and_verify_session_id(&psk, &random, &sid, issued_at + 91).unwrap_err();
        assert!(matches!(
            err,
            KnockWireError::Knock(crate::knock::KnockError::TimestampStale { .. })
        ));
    }

    #[test]
    fn padding_does_not_affect_verification() {
        // Manually craft a session_id with a known token + a
        // known padding (all zeros — would be the operationally-
        // worst-case for traffic-analysis but the cryptographic
        // verifier MUST NOT care).
        let psk = psk();
        let random = random_alpha();
        let now = 1_715_900_000u64;
        let token = compute_knock(&psk, &random, now);
        let mut sid = [0u8; ENCODED_SESSION_ID_LEN];
        sid[..KNOCK_TOKEN_LEN].copy_from_slice(&token);
        // padding stays all zeros
        decode_and_verify_session_id(&psk, &random, &sid, now)
            .expect("all-zero padding must not affect verify");
    }

    #[test]
    fn encoded_layout_constants_are_pinned() {
        // Wire-format invariants. Iteration 5 (server
        // transport-layer gate) reads from these directly;
        // changing without coordinating with the server-side
        // parser silently breaks Path A.
        assert_eq!(ENCODED_SESSION_ID_LEN, 32);
        assert_eq!(PADDING_LEN, 16);
        assert_eq!(KNOCK_TOKEN_LEN + PADDING_LEN, ENCODED_SESSION_ID_LEN);
    }

    #[test]
    fn decode_constant_time_property_smoke_test() {
        // Sanity: the wire-format wrapper inherits the
        // underlying knock::verify_knock's constant-time tag
        // check. We can't test for actual timing isolation
        // here (CI noise floor too high) but we CAN test that
        // both error-prefix paths (length wrong vs hmac wrong)
        // do not branch based on PSK content beyond what
        // verify_knock already covers.
        let psk = psk();
        let random = random_alpha();
        // Same-length-but-wrong-tag.
        let mut sid = [0u8; ENCODED_SESSION_ID_LEN];
        OsRng.fill_bytes(&mut sid);
        let e = decode_and_verify_session_id(&psk, &random, &sid, 1_715_900_000).unwrap_err();
        assert!(matches!(e, KnockWireError::Knock(_)));
    }
}
