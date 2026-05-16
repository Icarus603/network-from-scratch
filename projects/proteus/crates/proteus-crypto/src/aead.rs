//! ChaCha20-Poly1305 AEAD wrapper following spec §6.
//!
//! Nonces are computed by XOR-ing the 12-byte per-direction `iv` (derived
//! by HKDF-Expand-Label) with a zero-padded packet sequence (spec §4.5.2).
//! This module enforces the XOR construction at the API surface so callers
//! cannot reuse a nonce by accident.

use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use sha2::digest::typenum::Unsigned;
use zeroize::Zeroize;

use crate::CryptoError;

/// AEAD key length (32 bytes for both ciphers we support, spec §6).
pub const KEY_LEN: usize = 32;

/// AEAD nonce length (12 bytes, spec §6).
pub const NONCE_LEN: usize = 12;

/// AEAD tag length (16 bytes).
pub const TAG_LEN: usize = 16;

/// Construct the AEAD nonce for inner packet `(epoch:24 || seqnum:40)`
/// per spec §4.5.2.
///
/// `combined` is the 64-bit big-endian packing of `(epoch || seqnum)`.
/// The remaining 4 bytes are left-padded with zeros.
#[must_use]
pub fn nonce_for(iv: &[u8; NONCE_LEN], combined: u64) -> [u8; NONCE_LEN] {
    let mut nonce_input = [0u8; NONCE_LEN];
    nonce_input[NONCE_LEN - 8..].copy_from_slice(&combined.to_be_bytes());
    let mut out = [0u8; NONCE_LEN];
    for i in 0..NONCE_LEN {
        out[i] = iv[i] ^ nonce_input[i];
    }
    out
}

/// Encrypt `plaintext` under `(key, iv)` using `combined` as the nonce
/// counter, with `aad` as additional authenticated data.
pub fn seal(
    key: &[u8; KEY_LEN],
    iv: &[u8; NONCE_LEN],
    combined: u64,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let nonce_bytes = nonce_for(iv, combined);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::AeadAuth)
}

/// Decrypted plaintext wrapper that zeroizes on drop.
///
/// `Zeroizing<Vec<u8>>` is unavailable (`Vec` does not implement
/// `DefaultIsZeroes`); we manually wrap.
pub struct Plaintext(Vec<u8>);

impl Plaintext {
    /// Borrow the plaintext bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Consume the wrapper, returning the underlying vec.
    #[must_use]
    pub fn into_vec(mut self) -> Vec<u8> {
        core::mem::take(&mut self.0)
    }
}

impl Drop for Plaintext {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Decrypt `ciphertext` under `(key, iv)` and return the plaintext.
pub fn open(
    key: &[u8; KEY_LEN],
    iv: &[u8; NONCE_LEN],
    combined: u64,
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Plaintext, CryptoError> {
    let nonce_bytes = nonce_for(iv, combined);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Plaintext)
        .map_err(|_| CryptoError::AeadAuth)
}

/// Convenience accessor for the AEAD's expected nonce length, useful for
/// generic callers.
#[must_use]
pub fn expected_nonce_len() -> usize {
    <<ChaCha20Poly1305 as AeadCore>::NonceSize as Unsigned>::USIZE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_succeeds() {
        let key = [0x42u8; KEY_LEN];
        let iv = [0x11u8; NONCE_LEN];
        let aad = b"proteus inner header";
        let msg = b"hello proteus";
        let ct = seal(&key, &iv, 0x12_3456_0000_0001, aad, msg).unwrap();
        let pt = open(&key, &iv, 0x12_3456_0000_0001, aad, &ct).unwrap();
        assert_eq!(pt.as_slice(), msg);
    }

    #[test]
    fn nonce_mismatch_rejects() {
        let key = [0x42u8; KEY_LEN];
        let iv = [0x11u8; NONCE_LEN];
        let aad = b"";
        let ct = seal(&key, &iv, 0x01, aad, b"x").unwrap();
        // Decrypt with a different combined counter → AEAD authentication MUST fail.
        assert!(open(&key, &iv, 0x02, aad, &ct).is_err());
    }

    #[test]
    fn aad_mismatch_rejects() {
        let key = [0x42u8; KEY_LEN];
        let iv = [0x11u8; NONCE_LEN];
        let ct = seal(&key, &iv, 0x01, b"aad-a", b"hi").unwrap();
        assert!(open(&key, &iv, 0x01, b"aad-b", &ct).is_err());
    }

    #[test]
    fn nonce_for_xors_correctly() {
        let iv = [0x01u8; NONCE_LEN];
        // combined = 0 → nonce = iv (all-zero XOR)
        let nonce = nonce_for(&iv, 0);
        assert_eq!(nonce, iv);

        // combined = 0xff_ffff_ffff_ffff_ffff (max u64) → high 4 bytes still iv,
        // low 8 bytes are iv[8..] ^ ff…ff
        let nonce = nonce_for(&iv, u64::MAX);
        assert_eq!(&nonce[..4], &[0x01, 0x01, 0x01, 0x01]);
        assert_eq!(&nonce[4..], &[0xfe; 8]);
    }
}
