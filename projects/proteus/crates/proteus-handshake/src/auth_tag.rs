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

type HmacSha256 = Hmac<Sha256>;

/// Derive `auth_key = HKDF-Extract(salt=fp, IKM=x25519_pub || client_nonce)`.
#[must_use]
pub fn derive_auth_key(
    server_pq_fingerprint: &[u8; 32],
    client_x25519_pub: &[u8; 32],
    client_nonce: &[u8; 16],
) -> [u8; 32] {
    let mut ikm = [0u8; 32 + 16];
    ikm[..32].copy_from_slice(client_x25519_pub);
    ikm[32..].copy_from_slice(client_nonce);
    let prk = kdf::extract(server_pq_fingerprint, &ikm);
    *prk
}

/// Compute `HMAC-SHA-256(auth_key, auth_input)`.
#[must_use]
pub fn compute(auth_key: &[u8; 32], auth_input: &[u8]) -> [u8; HMAC_TAG_LEN] {
    let mut mac = HmacSha256::new_from_slice(auth_key).expect("HMAC accepts any key length");
    mac.update(auth_input);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; HMAC_TAG_LEN];
    out.copy_from_slice(&result);
    out
}

/// Verify `auth_tag` in constant time.
#[must_use]
pub fn verify(auth_key: &[u8; 32], auth_input: &[u8], expected_tag: &[u8; HMAC_TAG_LEN]) -> bool {
    let actual = compute(auth_key, auth_input);
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
        assert_ne!(k1, k2);

        let pub_ = [0x40u8; 32];
        let k3 = derive_auth_key(&fp, &pub_, &[0x50u8; 16]);
        let k4 = derive_auth_key(&fp, &pub_, &[0x51u8; 16]);
        assert_ne!(k3, k4);
    }
}
