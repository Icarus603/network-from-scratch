//! ChaCha20-Poly1305 AEAD wrapper following spec §6.
//!
//! Nonces are computed by XOR-ing the 12-byte per-direction `iv` (derived
//! by HKDF-Expand-Label) with a zero-padded packet sequence (spec §4.5.2).
//! This module enforces the XOR construction at the API surface so callers
//! cannot reuse a nonce by accident.

use chacha20poly1305::aead::{Aead, AeadCore, AeadInPlace, KeyInit, Payload};
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

/// AEAD key with the ChaCha20-Poly1305 cipher state **pre-built once**
/// at construction. The hot data path can then encrypt/decrypt without
/// paying the per-record `ChaCha20Poly1305::new(&key)` cost.
///
/// ## Why this exists
///
/// `aead::seal` / `aead::open` (the free functions above) take a raw
/// `[u8; 32]` key and rebuild the cipher state on every call. That's
/// fine for low-frequency call sites (CID encryption — once per
/// session; β QUIC DATAGRAM — sub-Mbps trickle channel) but is
/// measurably wasteful on the α data plane, which calls seal/open
/// once per record (potentially thousands of times per second on a
/// loaded session). The ChaCha20-Poly1305 key schedule is cheap in
/// absolute terms but non-zero, and inlining it into every record
/// adds branch mispredict + cache pressure that show up in flame
/// graphs above the AEAD itself.
///
/// ## Allocation behavior
///
/// `seal_into` and `open_in_place` both take a caller-supplied buffer
/// so the hot loop can reuse a single allocation across records.
/// `seal_into` extends the buffer by 16 bytes (AEAD tag);
/// `open_in_place` shrinks the buffer by 16 bytes (tag stripped).
/// Neither allocates internally on the happy path.
///
/// ## Zeroize on drop
///
/// The underlying `ChaCha20Poly1305` cipher holds the key in its
/// internal state. `chacha20poly1305 = 0.10` does not implement
/// `Zeroize` on `ChaCha20Poly1305` itself (the type doesn't even
/// expose a way to access its internals), so we don't lose any
/// security property here vs the `aead::seal` path which also
/// transiently stored the key in a `ChaCha20Poly1305` on the stack
/// before drop. Operators who need stronger key hygiene should use
/// the `Zeroizing<[u8;32]>` wrapper at the source.
#[derive(Clone)]
pub struct AeadKey {
    cipher: ChaCha20Poly1305,
    iv: [u8; NONCE_LEN],
}

impl AeadKey {
    /// Build the cached cipher from a 32-byte key + 12-byte IV. Done
    /// once per epoch in the α data path, then `seal_into` /
    /// `open_in_place` is called many times against this instance.
    #[must_use]
    pub fn new(key: &[u8; KEY_LEN], iv: &[u8; NONCE_LEN]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(Key::from_slice(key)),
            iv: *iv,
        }
    }

    /// In-place seal. `buf` enters with `plaintext`; on return, `buf`
    /// holds `ciphertext || tag` (`buf.len()` grows by `TAG_LEN = 16`).
    ///
    /// Caller is responsible for reusing the same `Vec<u8>` across
    /// records to avoid allocations. Capacity hint:
    /// `Vec::with_capacity(quantum + TAG_LEN)` once at sender
    /// construction; the vec's capacity sticks around even after
    /// drain/clear.
    pub fn seal_into(
        &self,
        combined: u64,
        aad: &[u8],
        buf: &mut Vec<u8>,
    ) -> Result<(), CryptoError> {
        let nonce_bytes = nonce_for(&self.iv, combined);
        self.cipher
            .encrypt_in_place(Nonce::from_slice(&nonce_bytes), aad, buf)
            .map_err(|_| CryptoError::AeadAuth)
    }

    /// In-place open. `buf` enters with `ciphertext || tag`; on
    /// success `buf` holds `plaintext` (`buf.len()` shrinks by
    /// `TAG_LEN = 16`). On failure (tag mismatch) the buffer
    /// contents are scrubbed by the underlying impl.
    pub fn open_in_place(
        &self,
        combined: u64,
        aad: &[u8],
        buf: &mut Vec<u8>,
    ) -> Result<(), CryptoError> {
        let nonce_bytes = nonce_for(&self.iv, combined);
        self.cipher
            .decrypt_in_place(Nonce::from_slice(&nonce_bytes), aad, buf)
            .map_err(|_| CryptoError::AeadAuth)
    }
}

impl std::fmt::Debug for AeadKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately omit cipher + iv — no key material in Debug.
        f.debug_struct("AeadKey").finish_non_exhaustive()
    }
}

/// Iter-199: scrub the IV field on drop. `chacha20poly1305 = 0.10`
/// impls `ZeroizeOnDrop` on its `ChaCha20Poly1305` so the KEY
/// field already scrubs — but the bare `[u8; NONCE_LEN]` IV
/// field does not. The IV is the HKDF-derived "iv" leaf of the
/// per-direction key schedule (see `direction_keys_from_secret`
/// in proteus_crypto::key_schedule); recovering it from a
/// coredump in tandem with a recovered key field would yield
/// per-record nonces directly. Defense-in-depth even though the
/// matching key field is already protected: same residue
/// discipline as iter-189/190's HMAC-tag closures and the
/// session.rs Drop impls on `AlphaSender` / `AlphaReceiver`.
impl Drop for AeadKey {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.iv.zeroize();
        // The `cipher` field's ZeroizeOnDrop fires automatically
        // when the struct drops; we don't need to call it here.
    }
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

    /// `AeadKey::seal_into` MUST produce byte-for-byte the same
    /// ciphertext as the free-function `seal`. If this regresses,
    /// every existing wire-format peer becomes incompatible with
    /// the new sender.
    #[test]
    fn aead_key_seal_matches_free_function_seal() {
        let key = [0x42u8; KEY_LEN];
        let iv = [0x11u8; NONCE_LEN];
        let aad = b"proteus inner header";
        let msg = b"hello proteus over the fast path";
        let combined = 0x12_3456_0000_0001u64;

        let ct_free = seal(&key, &iv, combined, aad, msg).unwrap();

        let mut buf = msg.to_vec();
        let ak = AeadKey::new(&key, &iv);
        ak.seal_into(combined, aad, &mut buf).unwrap();
        assert_eq!(buf, ct_free);
    }

    #[test]
    fn aead_key_open_in_place_round_trips() {
        let key = [0x99u8; KEY_LEN];
        let iv = [0xCDu8; NONCE_LEN];
        let ak = AeadKey::new(&key, &iv);
        let aad = b"aad-x";
        let msg = b"in-place round-trip via AeadKey";
        let mut buf = msg.to_vec();
        ak.seal_into(7, aad, &mut buf).unwrap();
        assert_eq!(buf.len(), msg.len() + TAG_LEN);
        ak.open_in_place(7, aad, &mut buf).unwrap();
        assert_eq!(buf, msg);
    }

    #[test]
    fn aead_key_open_rejects_wrong_nonce() {
        let key = [0x99u8; KEY_LEN];
        let iv = [0xCDu8; NONCE_LEN];
        let ak = AeadKey::new(&key, &iv);
        let mut buf = b"x".to_vec();
        ak.seal_into(1, b"", &mut buf).unwrap();
        assert!(ak.open_in_place(2, b"", &mut buf).is_err());
    }

    #[test]
    fn aead_key_open_rejects_wrong_aad() {
        let key = [0x99u8; KEY_LEN];
        let iv = [0xCDu8; NONCE_LEN];
        let ak = AeadKey::new(&key, &iv);
        let mut buf = b"hi".to_vec();
        ak.seal_into(1, b"aad-a", &mut buf).unwrap();
        assert!(ak.open_in_place(1, b"aad-b", &mut buf).is_err());
    }

    #[test]
    fn aead_key_seal_can_be_called_repeatedly_on_reused_buffer() {
        // Documents the intended hot-path usage: a single Vec<u8>
        // is reused across thousands of records by clearing it
        // back to the plaintext between calls.
        let key = [0x77u8; KEY_LEN];
        let iv = [0x88u8; NONCE_LEN];
        let ak = AeadKey::new(&key, &iv);
        let aad = b"";
        let mut buf: Vec<u8> = Vec::with_capacity(1024);

        for combined in 1..=100u64 {
            let pt = format!("record number {combined:05}");
            buf.clear();
            buf.extend_from_slice(pt.as_bytes());
            ak.seal_into(combined, aad, &mut buf).unwrap();
            // Decrypt right back to verify.
            ak.open_in_place(combined, aad, &mut buf).unwrap();
            assert_eq!(buf, pt.as_bytes());
        }
    }

    #[test]
    fn aead_key_debug_does_not_leak_key_material() {
        let key = [0xABu8; KEY_LEN];
        let iv = [0xCDu8; NONCE_LEN];
        let ak = AeadKey::new(&key, &iv);
        let s = format!("{ak:?}");
        // Must not stringify any bytes from key or iv.
        for b in &key {
            assert!(
                !s.contains(&format!("{b:02x}")),
                "Debug leaked key byte 0x{b:02x}"
            );
        }
        for b in &iv {
            assert!(
                !s.contains(&format!("{b:02x}")),
                "Debug leaked iv byte 0x{b:02x}"
            );
        }
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
