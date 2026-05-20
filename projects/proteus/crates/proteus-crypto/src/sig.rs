//! Ed25519 long-term identity signatures (RFC 8032).
//!
//! Proteus also defines a truncated ML-DSA-65 sidecar (spec §5.3); that
//! truncated mode is not yet implemented here because the RustCrypto
//! `ml-dsa` crate is still pre-1.0. For now this module exposes the
//! Ed25519 portion of the hybrid signature; the truncated ML-DSA-65
//! companion is planned for M2.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::CryptoError;

/// Signature length in bytes (Ed25519 fixed 64).
pub const SIG_LEN: usize = 64;

/// Generate a fresh Ed25519 signing key.
///
/// Iter-166: wrap the 32-byte secret seed in `Zeroizing` so the
/// stack copy is scrubbed on drop. ed25519_dalek's `SigningKey`
/// is itself `ZeroizeOnDrop`, but the raw `[u8; 32]` seed we
/// pass to `from_bytes` is not — pre-iter-166 the seed bytes
/// lingered in the caller's stack frame after `generate()`
/// returned. Same defect class as iter-163/164 closed for the
/// ml-kem K_pq stack residue. The seed allows direct
/// reconstruction of the signing key (Ed25519 derives the
/// signing scalar from H(seed)), so a coredump / heap-spray
/// recovery is a full identity-key compromise.
pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> SigningKey {
    let mut secret = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(&mut *secret);
    SigningKey::from_bytes(&secret)
}

/// Sign `msg` with `sk`.
#[must_use]
pub fn sign(sk: &SigningKey, msg: &[u8]) -> [u8; SIG_LEN] {
    sk.sign(msg).to_bytes()
}

/// Verify `(msg, sig)` against `pk`.
pub fn verify(pk: &VerifyingKey, msg: &[u8], sig: &[u8; SIG_LEN]) -> Result<(), CryptoError> {
    let sig = Signature::from_bytes(sig);
    pk.verify(msg, &sig).map_err(|_| CryptoError::Ed25519Verify)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn round_trip() {
        let mut rng = OsRng;
        let sk = generate(&mut rng);
        let pk = sk.verifying_key();
        let msg = b"proteus v1 handshake transcript";
        let sig = sign(&sk, msg);
        verify(&pk, msg, &sig).unwrap();
    }

    #[test]
    fn flipped_byte_rejects() {
        let mut rng = OsRng;
        let sk = generate(&mut rng);
        let pk = sk.verifying_key();
        let msg = b"proteus v1 handshake transcript";
        let mut sig = sign(&sk, msg);
        sig[0] ^= 0x01;
        assert!(matches!(
            verify(&pk, msg, &sig),
            Err(CryptoError::Ed25519Verify)
        ));
    }
}
