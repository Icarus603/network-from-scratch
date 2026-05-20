//! Auth-tag compute / verify routines (spec §4.1.3).
//!
//! ```text
//! auth_key   = HKDF-Extract(salt=server_pq_fingerprint,
//!                           IKM=client_x25519_pub || client_nonce)
//! auth_input = byte_concat(all fields above auth_tag, in order)
//! auth_tag   = HMAC-SHA-256(auth_key, auth_input)
//! ```
//!
//! The HKDF-Extract step uses `proteus_crypto::kdf::extract`; the HMAC
//! step uses RustCrypto's `hmac` crate directly. Verification is
//! constant-time via `subtle::ConstantTimeEq`.

use hmac::{Hmac, Mac};
use proteus_crypto::kdf;
use proteus_spec::HMAC_TAG_LEN;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// Derive `auth_key = HKDF-Extract(salt=fp, IKM=x25519_pub || client_nonce)`.
///
/// The returned key is wrapped in [`Zeroizing`] so the caller's stack
/// copy is scrubbed on drop. `kdf::extract` already produces a
/// `Zeroizing<[u8;32]>`; iter-157 propagates that wrapper through the
/// public API instead of dropping it via the prior `*prk` deref. The
/// auth_key is a long-lived secret per `(server_pq_fingerprint,
/// client_x25519_pub, client_nonce)` triple — anyone who recovers it
/// from a stale stack page can forge tags for that user across the
/// 90 s timestamp window, so leaving the bytes resident is
/// gratuitous risk.
#[must_use]
pub fn derive_auth_key(
    server_pq_fingerprint: &[u8; 32],
    client_x25519_pub: &[u8; 32],
    client_nonce: &[u8; 16],
) -> Zeroizing<[u8; 32]> {
    // IKM is also wrapped in Zeroizing — it contains the client_nonce
    // (low entropy on its own but a piece of the auth tuple) and the
    // client_x25519_pub (public, but the concatenation is what HKDF
    // sees). Zeroize-on-drop costs one extra 48-byte memset and
    // closes a stale-stack-page residue.
    let mut ikm = Zeroizing::new([0u8; 32 + 16]);
    ikm[..32].copy_from_slice(client_x25519_pub);
    ikm[32..].copy_from_slice(client_nonce);
    let prk = kdf::extract(server_pq_fingerprint, ikm.as_ref());
    Zeroizing::new(*prk)
}

/// Compute `HMAC-SHA-256(auth_key, auth_input)`.
#[must_use]
pub fn compute(auth_key: &[u8; 32], auth_input: &[u8]) -> [u8; HMAC_TAG_LEN] {
    use zeroize::Zeroize as _;
    let mut mac = HmacSha256::new_from_slice(auth_key).expect("HMAC accepts any key length");
    mac.update(auth_input);
    let mut result = mac.finalize().into_bytes();
    let mut out = [0u8; HMAC_TAG_LEN];
    out.copy_from_slice(&result);
    // Iter-189: scrub the GenericArray that hmac's `finalize`
    // returned BEFORE we drop. hmac-0.12's `into_bytes()` returns
    // a `GenericArray<u8, U32>` that doesn't impl Zeroize/
    // ZeroizeOnDrop, so the 32-byte HMAC output lingers on the
    // stack until later activity overwrites the slot.
    //
    // The function's RETURN value `out` is moved to the caller
    // (who's expected to wrap it in Zeroizing — iter-189
    // `verify` does, and other call sites either zeroize
    // themselves OR pass the tag straight to AEAD context).
    // What this scrubs is just the function-local copy in
    // `result`.
    {
        let bytes: &mut [u8] = result.as_mut();
        bytes.zeroize();
    }
    out
}

/// Verify `auth_tag` in constant time.
///
/// Iter-189: wrap the freshly-computed `actual` HMAC tag in
/// `Zeroizing` so its 32 bytes scrub on drop. The HMAC tag is
/// the proof-of-knowledge of `auth_key` — recovery via coredump
/// against the server's verify call lets an attacker
/// independently forge an `auth_tag` for whatever auth_input
/// they captured. The matching iter-157 fix wrapped the
/// auth_key itself in Zeroizing; this closes the matching
/// residue on the COMPUTED-TAG side.
#[must_use]
pub fn verify(auth_key: &[u8; 32], auth_input: &[u8], expected_tag: &[u8; HMAC_TAG_LEN]) -> bool {
    let actual = Zeroizing::new(compute(auth_key, auth_input));
    bool::from(actual.ct_eq(expected_tag))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let fp = [0x33u8; 32];
        let pub_ = [0x44u8; 32];
        let nonce = [0x55u8; 16];
        let key = derive_auth_key(&fp, &pub_, &nonce);
        let input = b"hello proteus auth";
        let tag = compute(&key, input);
        assert!(verify(&key, input, &tag));
    }

    /// Iter-157: `derive_auth_key` MUST return a `Zeroizing`-wrapped
    /// key so the caller's stack copy is scrubbed on drop. The
    /// `Zeroizing<[u8;32]>` return type is a load-bearing invariant
    /// — downgrading it back to `[u8;32]` would silently re-introduce
    /// the residue.
    ///
    /// This test is a compile-time pin: if the return type changes,
    /// the closure-coerced `Zeroizing<[u8;32]>` annotation below
    /// stops compiling.
    #[test]
    fn derive_auth_key_returns_zeroizing_wrapper() {
        let fp = [0u8; 32];
        let pub_ = [0u8; 32];
        let nonce = [0u8; 16];
        let key: Zeroizing<[u8; 32]> = derive_auth_key(&fp, &pub_, &nonce);
        // Reach into the wrapped value to confirm the deref works.
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn flipped_byte_rejects() {
        let key = [0xaau8; 32];
        let input = b"hello";
        let mut tag = compute(&key, input);
        tag[0] ^= 0x01;
        assert!(!verify(&key, input, &tag));
    }

    #[test]
    fn different_inputs_diverge() {
        let key = [0xbbu8; 32];
        let a = compute(&key, b"input a");
        let b = compute(&key, b"input b");
        assert_ne!(a, b);
    }

    #[test]
    fn auth_key_depends_on_both_inputs() {
        let fp = [0x10u8; 32];
        let nonce = [0x20u8; 16];
        let k1 = derive_auth_key(&fp, &[0x30u8; 32], &nonce);
        let k2 = derive_auth_key(&fp, &[0x31u8; 32], &nonce);
        assert_ne!(*k1, *k2);

        let pub_ = [0x40u8; 32];
        let k3 = derive_auth_key(&fp, &pub_, &[0x50u8; 16]);
        let k4 = derive_auth_key(&fp, &pub_, &[0x51u8; 16]);
        assert_ne!(*k3, *k4);
    }
}
