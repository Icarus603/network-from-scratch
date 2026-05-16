//! HKDF-SHA-256 helpers using the Proteus label space.
//!
//! The TLS 1.3 `HKDF-Expand-Label` construction (RFC 8446 §7.1) is
//! reused verbatim, with our own protocol-string `"proteus v1 "` prefix
//! injected into the `info` parameter for domain separation.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::CryptoError;

/// Domain-separation prefix for every Proteus `HKDF-Expand-Label` call.
///
/// The TLS 1.3 spec uses `"tls13 "` as its prefix; we use `"proteus v1 "`
/// to ensure a Proteus and TLS 1.3 implementation cannot collide labels
/// even when the underlying SHA-256 instance is shared.
pub const PROTEUS_LABEL_PREFIX: &[u8] = b"proteus v1 ";

/// `HKDF-Extract(salt, ikm) → prk`.
///
/// Returns the 32-byte PRK wrapped in [`Zeroizing`] so it cannot outlive
/// its drop without explicit clone.
#[must_use]
pub fn extract(salt: &[u8], ikm: &[u8]) -> Zeroizing<[u8; 32]> {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&prk);
    out
}

/// `HKDF-Expand-Label(secret, label, context, length)` per RFC 8446 §7.1
/// with the Proteus prefix prepended.
///
/// `info = uint16(length) || uint8(label.len) || PROTEUS_LABEL_PREFIX‖label || uint8(context.len) || context`
pub fn expand_label(
    secret: &[u8; 32],
    label: &[u8],
    context: &[u8],
    output: &mut [u8],
) -> Result<(), CryptoError> {
    let length: u16 = u16::try_from(output.len()).map_err(|_| CryptoError::Hkdf)?;
    let full_label_len = PROTEUS_LABEL_PREFIX
        .len()
        .checked_add(label.len())
        .ok_or(CryptoError::Hkdf)?;
    let mut info = Vec::with_capacity(2 + 1 + full_label_len + 1 + context.len());
    info.extend_from_slice(&length.to_be_bytes());
    info.push(u8::try_from(full_label_len).map_err(|_| CryptoError::Hkdf)?);
    info.extend_from_slice(PROTEUS_LABEL_PREFIX);
    info.extend_from_slice(label);
    info.push(u8::try_from(context.len()).map_err(|_| CryptoError::Hkdf)?);
    info.extend_from_slice(context);

    let hk = Hkdf::<Sha256>::from_prk(secret).map_err(|_| CryptoError::Hkdf)?;
    hk.expand(&info, output).map_err(|_| CryptoError::Hkdf)?;
    Ok(())
}

/// `Derive-Secret(secret, label, messages) = HKDF-Expand-Label(secret, label, transcript_hash(messages), 32)`
/// per RFC 8446 §7.1.
pub fn derive_secret(
    secret: &[u8; 32],
    label: &[u8],
    transcript_hash: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let mut out = Zeroizing::new([0u8; 32]);
    expand_label(secret, label, transcript_hash, out.as_mut())?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_then_expand_label_is_deterministic() {
        let salt = b"salt";
        let ikm = b"ikm value";
        let prk1 = extract(salt, ikm);
        let prk2 = extract(salt, ikm);
        assert_eq!(prk1.as_slice(), prk2.as_slice());

        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        let prk_arr: &[u8; 32] = &prk1;
        expand_label(prk_arr, b"key", b"", &mut out1).unwrap();
        expand_label(prk_arr, b"key", b"", &mut out2).unwrap();
        assert_eq!(out1, out2);
    }

    #[test]
    fn different_labels_yield_different_keys() {
        let prk = extract(b"salt", b"ikm");
        let prk_arr: &[u8; 32] = &prk;
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        expand_label(prk_arr, b"key", b"", &mut a).unwrap();
        expand_label(prk_arr, b"iv", b"", &mut b).unwrap();
        assert_ne!(a, b, "different labels MUST diverge");
    }

    #[test]
    fn derive_secret_round_trip() {
        let prk = extract(b"salt", b"ikm");
        let prk_arr: &[u8; 32] = &prk;
        let transcript_hash = [0x42u8; 32];
        let s = derive_secret(prk_arr, b"c hs traffic", &transcript_hash).unwrap();
        assert_eq!(s.len(), 32);
        // determinism
        let s2 = derive_secret(prk_arr, b"c hs traffic", &transcript_hash).unwrap();
        assert_eq!(s.as_slice(), s2.as_slice());
    }
}
