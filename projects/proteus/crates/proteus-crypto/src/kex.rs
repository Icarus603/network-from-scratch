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
    use zeroize::Zeroize as _;

    let x25519_sk = StaticSecret::random_from_rng(&mut *rng);
    let x25519_pub = XPublicKey::from(&x25519_sk).to_bytes();

    let (ct, mut shared) = server_mlkem_pub
        .encapsulate(rng)
        .map_err(|_| CryptoError::KemDecap)?;

    let mut shared_arr = Zeroizing::new([0u8; 32]);
    shared_arr.copy_from_slice(shared.as_ref());
    // Iter-163: scrub the raw `shared` stack copy from ml-kem.
    // ml-kem 0.2.3's `SharedKey = B32` (generic hybrid_array::Array
    // alias) does NOT implement `Zeroize`/`ZeroizeOnDrop` on the
    // SharedKey output of `encapsulate`. The bytes we just copied
    // into `shared_arr` would otherwise linger in the caller's stack
    // frame until later stack activity overwrites them — long enough
    // for a heap-spray or coredump to recover the K_pq half of the
    // hybrid shared. Explicit memset closes the residue.
    //
    // Matching server-side decapsulate residue is closed by
    // iter-164 inside `server_combine`.
    {
        let bytes: &mut [u8] = shared.as_mut();
        bytes.zeroize();
    }

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
    use zeroize::Zeroize as _;

    let client_pub = XPublicKey::from(*client_x25519_pub);
    let k_classic = server_x25519_sk.diffie_hellman(&client_pub);

    // Reject all-zero shared secret (RFC 7748 §6.1).
    let zero = [0u8; 32];
    if bool::from(k_classic.as_bytes().ct_eq(&zero)) {
        return Err(CryptoError::X25519ZeroOutput);
    }

    let ct = Ciphertext::<MlKem768>::try_from(&client_mlkem_ct[..])
        .map_err(|_| CryptoError::KemDecap)?;
    let mut k_pq = server_mlkem_sk
        .decapsulate(&ct)
        .map_err(|_| CryptoError::KemDecap)?;

    let mut combined = Zeroizing::new([0u8; HYBRID_SHARED_LEN]);
    // Copy into combined FIRST, then scrub the source stack
    // copies. Order matters: zeroizing before the copy would
    // write all-zero bytes into combined.
    combined[..32].copy_from_slice(k_classic.as_bytes());
    combined[32..].copy_from_slice(k_pq.as_ref());

    // Iter-164: scrub the raw `k_pq` stack copy from ml-kem.
    //
    // ml-kem 0.2.3's `SharedKey = B32` (hybrid_array Array)
    // doesn't impl `Zeroize`/`ZeroizeOnDrop` on the encap/decap
    // output — only DecapsulationKey is ZeroizeOnDrop. The
    // 32-byte stack-resident copy of K_pq would otherwise linger
    // in the caller's stack frame until later activity overwrites
    // it. Same defect closed on the client-side encapsulate path
    // in iter-163; this is the matching fix on the server-side
    // decapsulate path.
    //
    // K_pq is the post-quantum half of the hybrid shared input to
    // HKDF-Extract at the Handshake-Secret stage. On the server
    // side this function is called for every accepted handshake —
    // leaving residue would accumulate one stack-image of every
    // session's PQ-strong key in the process's recent stack
    // pages, with a heap-spray / coredump primitive amplifying
    // the blast radius to many sessions at once.
    //
    // Block-scoped reference binding works around ml-kem's generic
    // `AsMut` impl needing explicit `&mut [u8]` typing.
    {
        let bytes: &mut [u8] = k_pq.as_mut();
        bytes.zeroize();
    }
    //
    // `k_classic` (x25519_dalek `SharedSecret`) is intentionally
    // NOT scrubbed inline here. `SharedSecret(MontgomeryPoint)`
    // does not impl Drop, but the inner `MontgomeryPoint` impls
    // Zeroize — and the type doesn't expose a public `as_mut() ->
    // &mut [u8]` (only `as_bytes() -> &[u8; 32]`). Reaching the
    // inner bytes through unsafe pointer arithmetic just to scrub
    // them is a worse trade than waiting for upstream
    // x25519_dalek to add ZeroizeOnDrop (issue #131 in
    // dalek-cryptography/curve25519-dalek). The K_classic residue
    // on its own is half of a hybrid shared — without the
    // matching K_pq (which iter-163/164 now scrub on both sides)
    // it doesn't open any session's keys.
    //
    // Filed as a TODO against upstream; meanwhile we've removed
    // the ML-KEM residue, which was the other half of the
    // problem.
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

    /// Iter-163: a happy-path encapsulate must still produce a
    /// usable `ClientEphemeral.mlkem_shared` — the
    /// post-iter-163 stack-zeroize on the raw `shared` copy
    /// must not corrupt the value we already copied into the
    /// `Zeroizing<[u8; 32]>` wrapper.
    ///
    /// This is a regression pin: a sloppy fix that zeroized the
    /// wrong buffer (or zeroized before the copy) would surface
    /// here as `client_combined == server_combined` failing in
    /// the existing round-trip test, but having a dedicated test
    /// for the wrapper's contents makes the regression cause
    /// obvious.
    #[test]
    fn iter163_client_ephemeral_preserves_mlkem_shared_after_stack_zeroize() {
        let mut rng = OsRng;
        let (_sk, pk) = MlKem768::generate(&mut rng);
        let eph = client_ephemeral(&mut rng, &pk).unwrap();
        // The shared must be non-zero (vanishingly unlikely for a
        // real ML-KEM-768 encapsulate output to be all-zero, but
        // the post-iter-163 `shared.zeroize()` could regress to
        // wiping `shared_arr` instead).
        assert!(
            eph.mlkem_shared.iter().any(|&b| b != 0),
            "iter-163: mlkem_shared must contain the encapsulated K_pq, \
             not be wiped by the post-copy zeroize"
        );
        assert_eq!(eph.mlkem_shared.len(), 32);
    }

    /// Iter-164: server-side decapsulate must STILL produce a usable
    /// K_pq inside the combined hybrid shared after the post-iter-164
    /// stack-zeroize of `k_pq`. The wire-format value (= `combined`
    /// returned by `server_combine`) must equal the client's
    /// `client_combine` output — the round-trip test already covers
    /// this end-to-end, but a dedicated test here makes the
    /// regression cause obvious if a future fix zeroizes the wrong
    /// buffer (e.g. wipes `combined[32..]` instead of the source
    /// stack copy).
    #[test]
    fn iter164_server_combine_preserves_k_pq_in_combined() {
        let mut rng = OsRng;
        let (sk, pk) = MlKem768::generate(&mut rng);
        let s_x_sk = StaticSecret::random_from_rng(rng);
        let s_x_pub = XPublicKey::from(&s_x_sk).to_bytes();

        let eph = client_ephemeral(&mut rng, &pk).unwrap();
        let combined = server_combine(&s_x_sk, &sk, &eph.x25519_pub, &eph.mlkem_ct).unwrap();
        // Pin: K_pq half (bytes 32..64) must equal the client's
        // remembered shared. A sloppy iter-164 that wiped
        // `combined[32..]` after the copy would surface here as
        // an all-zero PQ half.
        assert_eq!(
            &combined[32..],
            eph.mlkem_shared.as_slice(),
            "iter-164: server_combine must preserve K_pq in combined; \
             the post-copy zeroize must scrub the source `k_pq` stack \
             copy, not the destination."
        );
        // And K_pq must not itself be all-zero (vanishingly
        // unlikely for a real ML-KEM-768 output, but a sloppy
        // fix would land here too).
        assert!(
            combined[32..].iter().any(|&b| b != 0),
            "iter-164: K_pq half must be non-zero — sloppy fix likely \
             wiped the destination buffer"
        );
        // K_classic half (bytes 0..32) must also be intact.
        let s_diff_check = client_combine(&eph, &s_x_pub).expect("client_combine for cross-check");
        assert_eq!(
            &combined[..],
            s_diff_check.as_slice(),
            "iter-164: full combined hybrid shared must match the \
             client-derived value"
        );
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
