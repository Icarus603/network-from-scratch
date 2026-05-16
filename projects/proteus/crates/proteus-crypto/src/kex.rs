//! Hybrid X25519 + ML-KEM-768 key exchange (spec §5.2).
//!
//! ## Concatenation hybrid
//!
//! Following draft-ietf-tls-hybrid-design-11 ("concatenation hybrid" mode)
//! and the Bindel PQCrypto 2019 IND-CCA reduction:
//!
//! ```text
//! K_classic = X25519(c_eph_sk, s_eph_pk)            // 32 bytes
//! K_pq      = ML-KEM-768.Decaps(s_pq_sk, c_mlkem_ct) // 32 bytes
//! DH_input  = K_classic || K_pq                      // 64 bytes
//! ```
//!
//! The combined `DH_input` is then fed as `IKM` to `HKDF-Extract` to derive
//! the TLS 1.3-style Handshake Secret.

use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Ciphertext, KemCore, MlKem768};
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::CryptoError;

/// Length of the combined `(K_classic || K_pq)` input to HKDF-Extract.
pub const HYBRID_SHARED_LEN: usize = 32 + 32;

/// Client-side ephemeral key material produced before the handshake.
pub struct ClientEphemeral {
    /// Server-bound X25519 secret (kept until the SH arrives).
    pub x25519_sk: StaticSecret,
    /// X25519 public share, embedded in the auth extension.
    pub x25519_pub: [u8; 32],
    /// Decapsulation key for ML-KEM (the *client* generated the ciphertext
    /// to the *server's* PK, so the client only needs to remember the
    /// shared secret it produced).
    pub mlkem_shared: Zeroizing<[u8; 32]>,
    /// Ciphertext bound for the server, embedded in the auth extension.
    pub mlkem_ct: [u8; 1088],
}

/// Generate a fresh client ephemeral and encapsulate to the server's
/// long-term ML-KEM-768 public key. spec §5.2.
pub fn client_ephemeral<R: RngCore + CryptoRng>(
    rng: &mut R,
    server_mlkem_pub: &<MlKem768 as KemCore>::EncapsulationKey,
) -> Result<ClientEphemeral, CryptoError> {
    let x25519_sk = StaticSecret::random_from_rng(&mut *rng);
    let x25519_pub = XPublicKey::from(&x25519_sk).to_bytes();

    let (ct, shared) = server_mlkem_pub
        .encapsulate(rng)
        .map_err(|_| CryptoError::KemDecap)?;

    let mut shared_arr = Zeroizing::new([0u8; 32]);
    shared_arr.copy_from_slice(shared.as_ref());

    // Pack ciphertext into a fixed 1088-byte array.
    let ct_bytes: &[u8] = ct.as_ref();
    if ct_bytes.len() != 1088 {
        return Err(CryptoError::KemDecap);
    }
    let mut ct_arr = [0u8; 1088];
    ct_arr.copy_from_slice(ct_bytes);

    Ok(ClientEphemeral {
        x25519_sk,
        x25519_pub,
        mlkem_shared: shared_arr,
        mlkem_ct: ct_arr,
    })
}

/// Server-side: given the client's X25519 share and ML-KEM ciphertext,
/// recover `(K_classic, K_pq)` and concatenate them.
pub fn server_combine(
    server_x25519_sk: &StaticSecret,
    server_mlkem_sk: &<MlKem768 as KemCore>::DecapsulationKey,
    client_x25519_pub: &[u8; 32],
    client_mlkem_ct: &[u8; 1088],
) -> Result<Zeroizing<[u8; HYBRID_SHARED_LEN]>, CryptoError> {
    let client_pub = XPublicKey::from(*client_x25519_pub);
    let k_classic = server_x25519_sk.diffie_hellman(&client_pub);

    // Reject all-zero shared secret (RFC 7748 §6.1).
    let zero = [0u8; 32];
    if bool::from(k_classic.as_bytes().ct_eq(&zero)) {
        return Err(CryptoError::X25519ZeroOutput);
    }

    let ct = Ciphertext::<MlKem768>::try_from(&client_mlkem_ct[..])
        .map_err(|_| CryptoError::KemDecap)?;
    let k_pq = server_mlkem_sk
        .decapsulate(&ct)
        .map_err(|_| CryptoError::KemDecap)?;

    let mut combined = Zeroizing::new([0u8; HYBRID_SHARED_LEN]);
    combined[..32].copy_from_slice(k_classic.as_bytes());
    combined[32..].copy_from_slice(k_pq.as_ref());
    Ok(combined)
}

/// Client-side: combine its stored X25519 secret with the server's
/// ephemeral X25519 public, then prepend the ML-KEM shared it generated.
pub fn client_combine(
    client_eph: &ClientEphemeral,
    server_x25519_pub: &[u8; 32],
) -> Result<Zeroizing<[u8; HYBRID_SHARED_LEN]>, CryptoError> {
    let server_pub = XPublicKey::from(*server_x25519_pub);
    let k_classic = client_eph.x25519_sk.diffie_hellman(&server_pub);

    let zero = [0u8; 32];
    if bool::from(k_classic.as_bytes().ct_eq(&zero)) {
        return Err(CryptoError::X25519ZeroOutput);
    }

    let mut combined = Zeroizing::new([0u8; HYBRID_SHARED_LEN]);
    combined[..32].copy_from_slice(k_classic.as_bytes());
    combined[32..].copy_from_slice(client_eph.mlkem_shared.as_slice());
    Ok(combined)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn round_trip_hybrid_kex() {
        // Server long-term keys.
        let mut rng = OsRng;
        let (server_mlkem_sk, server_mlkem_pk) = MlKem768::generate(&mut rng);
        let server_x25519_sk = StaticSecret::random_from_rng(rng);
        let server_x25519_pub = XPublicKey::from(&server_x25519_sk).to_bytes();

        // Client builds the auth-extension material.
        let client_eph = client_ephemeral(&mut rng, &server_mlkem_pk).unwrap();
        let client_combined = client_combine(&client_eph, &server_x25519_pub).unwrap();

        // Server combines using the wire-shipped material.
        let server_combined = server_combine(
            &server_x25519_sk,
            &server_mlkem_sk,
            &client_eph.x25519_pub,
            &client_eph.mlkem_ct,
        )
        .unwrap();

        assert_eq!(client_combined.as_slice(), server_combined.as_slice());
        assert_eq!(client_combined.len(), HYBRID_SHARED_LEN);
    }

    #[test]
    fn corrupted_ciphertext_yields_diverging_shared() {
        let mut rng = OsRng;
        let (server_mlkem_sk, server_mlkem_pk) = MlKem768::generate(&mut rng);
        let server_x25519_sk = StaticSecret::random_from_rng(rng);
        let server_x25519_pub = XPublicKey::from(&server_x25519_sk).to_bytes();

        let client_eph = client_ephemeral(&mut rng, &server_mlkem_pk).unwrap();
        let client_combined = client_combine(&client_eph, &server_x25519_pub).unwrap();

        let mut bad_ct = client_eph.mlkem_ct;
        bad_ct[42] ^= 0xff;

        // ML-KEM-768 implicit rejection: decapsulation succeeds with a
        // pseudorandom secret, so K_pq diverges but no error is raised.
        // The shared MUST therefore differ — that's the security property.
        let server_combined = server_combine(
            &server_x25519_sk,
            &server_mlkem_sk,
            &client_eph.x25519_pub,
            &bad_ct,
        )
        .unwrap();
        assert_ne!(client_combined.as_slice(), server_combined.as_slice());
    }
}
