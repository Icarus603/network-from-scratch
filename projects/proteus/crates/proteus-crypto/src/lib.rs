//! Proteus cryptographic primitives.
//!
//! This crate implements the spec-mandated operations from §5 and §6:
//!
//! - [`kex`] — hybrid X25519 + ML-KEM-768 key exchange (concatenation hybrid,
//!   draft-ietf-tls-hybrid-design-11 / Bindel PQCrypto 2019).
//! - [`sig`] — Ed25519 long-term identity signatures (RFC 8032).
//! - [`aead`] — ChaCha20-Poly1305 wrapper with Proteus AAD discipline.
//! - [`kdf`] — HKDF-SHA-256 helpers using the Proteus label space
//!   (`proteus_spec::hkdf_label::*`).
//! - [`ratchet`] — asymmetric DH ratchet delivering PCS-strong per spec §5.4.
//!
//! All symmetric key material is wrapped in [`zeroize::Zeroizing`] containers.

#![deny(missing_docs)]

use thiserror::Error;

pub mod aead;
pub mod kdf;
pub mod kex;
pub mod key_schedule;
pub mod ratchet;
pub mod sig;

/// Top-level errors surfaced by the crypto layer.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// AEAD authentication failed (tag mismatch). Per spec §4.5 §11.16,
    /// callers MUST silently drop the offending packet.
    #[error("AEAD authentication failed")]
    AeadAuth,

    /// AEAD operation produced an invalid-length output. Defensive only.
    #[error("AEAD operation produced an invalid-length output")]
    AeadLength,

    /// X25519 produced an all-zero shared secret (invalid contributory key).
    /// Per RFC 7748 §6.1, this MUST be treated as a peer-supplied failure.
    #[error("X25519 zero-output (low-order point detected)")]
    X25519ZeroOutput,

    /// ML-KEM decapsulation failed. spec §5.2.
    #[error("ML-KEM-768 decapsulation failed")]
    KemDecap,

    /// Ed25519 signature verification failed.
    #[error("Ed25519 signature verification failed")]
    Ed25519Verify,

    /// HKDF expansion failed (typically zero-length output requested).
    #[error("HKDF operation failed")]
    Hkdf,
}
