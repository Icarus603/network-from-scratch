//! Full TLS 1.3-style key schedule with hybrid PQ extension (spec §5.2).
//!
//! Mirrors RFC 8446 §7.1 exactly, with the single modification that
//! `HKDF-Extract`'s IKM at the Handshake-Secret stage is the concatenation
//! `K_classic || K_pq` (draft-ietf-tls-hybrid-design-11 concatenation hybrid).

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{kdf, CryptoError};

/// Length of a single secret (SHA-256 output / AEAD key).
pub const SECRET_LEN: usize = 32;

/// Per-direction AEAD key + IV bundle. Both fields are zeroized on drop.
pub struct DirectionKeys {
    /// AEAD encryption key (ChaCha20-Poly1305 or AES-256-GCM, 32 bytes).
    pub key: Zeroizing<[u8; 32]>,
    /// 12-byte IV used as the static portion of the AEAD nonce (§4.5.2).
    pub iv: Zeroizing<[u8; 12]>,
}

/// All secrets derived from the handshake. Owns its key material with
/// zeroize-on-drop semantics.
pub struct HandshakeSecrets {
    /// `c_ap_secret_(ep=0,sub=0)` — application data, client→server direction.
    pub c_ap_secret: Zeroizing<[u8; SECRET_LEN]>,
    /// `s_ap_secret_(ep=0,sub=0)` — application data, server→client direction.
    pub s_ap_secret: Zeroizing<[u8; SECRET_LEN]>,
    /// `exporter_master_secret` for derived telemetry / external keys.
    pub exporter: Zeroizing<[u8; SECRET_LEN]>,
    /// `resumption_master_secret` for 0-RTT tickets.
    pub resumption: Zeroizing<[u8; SECRET_LEN]>,
}

impl HandshakeSecrets {
    /// Materialize the AEAD direction keys.
    pub fn direction_keys(&self) -> Result<(DirectionKeys, DirectionKeys), CryptoError> {
        let c = direction_keys_from_secret(&self.c_ap_secret)?;
        let s = direction_keys_from_secret(&self.s_ap_secret)?;
        Ok((c, s))
    }
}

fn direction_keys_from_secret(secret: &[u8; SECRET_LEN]) -> Result<DirectionKeys, CryptoError> {
    let mut key = Zeroizing::new([0u8; 32]);
    let mut iv = Zeroizing::new([0u8; 12]);
    kdf::expand_label(secret, b"key", b"", key.as_mut())?;
    kdf::expand_label(secret, b"iv", b"", iv.as_mut())?;
    Ok(DirectionKeys { key, iv })
}

/// Run the full Proteus key schedule (spec §5.2).
///
/// Inputs:
/// - `client_nonce`: 16 bytes, drives the Early Secret.
/// - `hybrid_shared` = `K_classic || K_pq` (64 bytes total).
/// - `transcript_hash_ch_sh`: SHA-256 of `(ClientHello || ServerHello)`-equivalent
///   bytes (in Proteus α profile this is the handshake-frame prefix bytes).
/// - `transcript_hash_ch_sf`: SHA-256 of `(ClientHello || ... || ServerFinished)`.
/// - `transcript_hash_ch_cf`: SHA-256 of `(ClientHello || ... || ClientFinished)`.
///
/// Output: the four post-handshake secrets.
pub fn derive(
    client_nonce: &[u8; 16],
    hybrid_shared: &[u8; 64],
    transcript_hash_ch_sh: &[u8; 32],
    transcript_hash_ch_sf: &[u8; 32],
    transcript_hash_ch_cf: &[u8; 32],
) -> Result<HandshakeSecrets, CryptoError> {
    // Early Secret = HKDF-Extract(salt=0^32, IKM=client_nonce-padded-to-32).
    let mut es_ikm = [0u8; 32];
    es_ikm[..16].copy_from_slice(client_nonce);
    let salt_zero = [0u8; 32];
    let es = kdf::extract(&salt_zero, &es_ikm);

    // derived_es = Derive-Secret(ES, "derived", "")  →  next-stage salt.
    let empty_hash = sha256_empty();
    let derived_es = kdf::derive_secret(&es, b"derived", &empty_hash)?;

    // Handshake Secret = HKDF-Extract(salt=derived_es, IKM=K_classic||K_pq).
    let hs = kdf::extract(derived_es.as_ref(), hybrid_shared);

    // We do not currently consume the handshake-traffic-secrets in α profile
    // (no encrypted handshake records); derive them anyway to keep the
    // schedule audit-trail in tests.
    let _c_hs = kdf::derive_secret(&hs, b"c hs traffic", transcript_hash_ch_sh)?;
    let _s_hs = kdf::derive_secret(&hs, b"s hs traffic", transcript_hash_ch_sh)?;

    let derived_hs = kdf::derive_secret(&hs, b"derived", &empty_hash)?;

    // Master Secret = HKDF-Extract(salt=derived_hs, IKM=0^32).
    let ms = kdf::extract(derived_hs.as_ref(), &[0u8; 32]);

    let c_ap = kdf::derive_secret(&ms, b"c ap traffic", transcript_hash_ch_sf)?;
    let s_ap = kdf::derive_secret(&ms, b"s ap traffic", transcript_hash_ch_sf)?;
    let exp = kdf::derive_secret(&ms, b"exp master", transcript_hash_ch_sf)?;
    let res = kdf::derive_secret(&ms, b"res master", transcript_hash_ch_cf)?;

    Ok(HandshakeSecrets {
        c_ap_secret: c_ap,
        s_ap_secret: s_ap,
        exporter: exp,
        resumption: res,
    })
}

fn sha256_empty() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([]);
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

/// Helper: SHA-256 hash of arbitrary bytes.
#[must_use]
pub fn sha256(input: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(input);
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

/// Append-only transcript accumulator. SHA-256-based, RFC 8446-style.
pub struct Transcript {
    h: Sha256,
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new()
    }
}

impl Transcript {
    /// Create an empty transcript.
    #[must_use]
    pub fn new() -> Self {
        Self { h: Sha256::new() }
    }

    /// Append bytes (e.g. a full handshake frame) to the transcript.
    pub fn update(&mut self, bytes: &[u8]) {
        self.h.update(bytes);
    }

    /// Snapshot the current digest without consuming the transcript.
    #[must_use]
    pub fn snapshot(&self) -> [u8; 32] {
        let h = self.h.clone();
        let d = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&d);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedule_is_deterministic() {
        let nonce = [0x11u8; 16];
        let shared = [0x22u8; 64];
        let th_a = [0x33u8; 32];
        let th_b = [0x44u8; 32];
        let th_c = [0x55u8; 32];

        let s1 = derive(&nonce, &shared, &th_a, &th_b, &th_c).unwrap();
        let s2 = derive(&nonce, &shared, &th_a, &th_b, &th_c).unwrap();
        assert_eq!(s1.c_ap_secret.as_slice(), s2.c_ap_secret.as_slice());
        assert_eq!(s1.s_ap_secret.as_slice(), s2.s_ap_secret.as_slice());
        assert_eq!(s1.exporter.as_slice(), s2.exporter.as_slice());
        assert_eq!(s1.resumption.as_slice(), s2.resumption.as_slice());
    }

    #[test]
    fn directions_diverge() {
        let s = derive(&[0u8; 16], &[1u8; 64], &[2u8; 32], &[3u8; 32], &[4u8; 32]).unwrap();
        assert_ne!(
            s.c_ap_secret.as_slice(),
            s.s_ap_secret.as_slice(),
            "c_ap_secret MUST differ from s_ap_secret"
        );
        let (c_keys, s_keys) = s.direction_keys().unwrap();
        assert_ne!(c_keys.key.as_slice(), s_keys.key.as_slice());
        assert_ne!(c_keys.iv.as_slice(), s_keys.iv.as_slice());
    }

    #[test]
    fn different_shared_diverge() {
        let nonce = [0u8; 16];
        let th = [0u8; 32];
        let s1 = derive(&nonce, &[1u8; 64], &th, &th, &th).unwrap();
        let s2 = derive(&nonce, &[2u8; 64], &th, &th, &th).unwrap();
        assert_ne!(s1.c_ap_secret.as_slice(), s2.c_ap_secret.as_slice());
    }

    #[test]
    fn different_transcript_diverges_ap_traffic() {
        let nonce = [0u8; 16];
        let shared = [0u8; 64];
        let s1 = derive(&nonce, &shared, &[0u8; 32], &[1u8; 32], &[2u8; 32]).unwrap();
        let s2 = derive(&nonce, &shared, &[0u8; 32], &[9u8; 32], &[2u8; 32]).unwrap();
        // c_ap_secret depends on ch_sf transcript → must differ
        assert_ne!(s1.c_ap_secret.as_slice(), s2.c_ap_secret.as_slice());
    }

    #[test]
    fn transcript_snapshot_is_idempotent() {
        let mut t = Transcript::new();
        t.update(b"hello ");
        t.update(b"world");
        let a = t.snapshot();
        let b = t.snapshot();
        assert_eq!(a, b);
        let expected = sha256(b"hello world");
        assert_eq!(a, expected);
    }
}
