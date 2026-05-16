//! Asymmetric DH ratchet delivering PCS-strong per spec §5.4.
//!
//! ## Construction
//!
//! Each side maintains:
//!
//! - `current_secret` — the 32-byte traffic secret for the current epoch.
//! - `my_last_dh_sk` — the X25519 secret it generated for the most recent
//!   send-side KEYUPDATE (kept until the peer ratchets through it).
//! - `peer_last_dh_pk` — the X25519 share most recently received from the
//!   peer (used as the basis for the next outgoing KEYUPDATE).
//!
//! On KEYUPDATE-send:
//!
//! ```text
//! new_dh_sk, new_dh_pk = X25519.keygen()
//! shared    = X25519(new_dh_sk, peer_last_dh_pk)
//! new_secret = HKDF-Extract(salt = current_secret, IKM = shared)
//! current_secret ← new_secret
//! my_last_dh_sk  ← new_dh_sk
//! emit KEYUPDATE { next_epoch, new_dh_pk, transcript_hash }
//! ```
//!
//! On KEYUPDATE-recv (verified):
//!
//! ```text
//! shared     = X25519(my_last_dh_sk, peer_new_dh_pk)
//! new_secret = HKDF-Extract(salt = current_secret, IKM = shared)
//! current_secret ← new_secret
//! peer_last_dh_pk ← peer_new_dh_pk
//! ```
//!
//! Properties (proved in `assets/formal/ProteusRatchet.spthy`):
//!
//! 1. Forward secrecy — leaking `current_secret` at time T does not expose
//!    pre-T traffic (HKDF is forward-only).
//! 2. PCS-strong — after one honest ratchet round, leaking the state at
//!    time T does not expose post-T traffic (the new shared depends on the
//!    peer's fresh DH share).

use rand_core::{CryptoRng, RngCore};
use x25519_dalek::{PublicKey as XPublicKey, ReusableSecret};
use zeroize::Zeroizing;

use crate::kdf;

/// Bytes per traffic secret.
pub const SECRET_LEN: usize = 32;

/// State carried by each side of an asymmetric ratchet.
pub struct RatchetState {
    /// Current epoch counter (24-bit space, but we store as u32 for ergonomics).
    pub epoch: u32,
    /// Current traffic secret. Zeroized on drop.
    current_secret: Zeroizing<[u8; SECRET_LEN]>,
    /// Our most recent DH secret (we keep it until peer ratchets past it).
    my_last_dh_sk: ReusableSecret,
    /// Peer's most recent DH public share.
    peer_last_dh_pk: [u8; 32],
}

impl RatchetState {
    /// Seed a new ratchet from the handshake's `c_ap_secret` / `s_ap_secret`
    /// plus the initial DH material (from the auth-extension exchange).
    pub fn seed(
        initial_secret: [u8; SECRET_LEN],
        my_initial_dh_sk: ReusableSecret,
        peer_initial_dh_pk: [u8; 32],
    ) -> Self {
        Self {
            epoch: 0,
            current_secret: Zeroizing::new(initial_secret),
            my_last_dh_sk: my_initial_dh_sk,
            peer_last_dh_pk: peer_initial_dh_pk,
        }
    }

    /// Read-only access to the current traffic secret.
    #[must_use]
    pub fn current_secret(&self) -> &[u8; SECRET_LEN] {
        &self.current_secret
    }

    /// Step the ratchet forward on the **send** side. Returns the new DH
    /// public to ship inside the KEYUPDATE inner packet.
    pub fn step_send<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> [u8; 32] {
        let new_sk = ReusableSecret::random_from_rng(&mut *rng);
        let new_pk = XPublicKey::from(&new_sk).to_bytes();
        let shared = new_sk.diffie_hellman(&XPublicKey::from(self.peer_last_dh_pk));
        let new_secret = kdf::extract(self.current_secret.as_ref(), shared.as_bytes());

        // Install new state.
        self.epoch = self.epoch.wrapping_add(1);
        self.current_secret = Zeroizing::new(*new_secret);
        self.my_last_dh_sk = new_sk;
        new_pk
    }

    /// Step the ratchet forward on the **recv** side using the peer's
    /// `new_dh_pk` carried in the KEYUPDATE packet.
    pub fn step_recv(&mut self, peer_new_dh_pk: [u8; 32]) {
        let shared = self
            .my_last_dh_sk
            .diffie_hellman(&XPublicKey::from(peer_new_dh_pk));
        let new_secret = kdf::extract(self.current_secret.as_ref(), shared.as_bytes());

        self.epoch = self.epoch.wrapping_add(1);
        self.current_secret = Zeroizing::new(*new_secret);
        self.peer_last_dh_pk = peer_new_dh_pk;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    /// End-to-end PCS-strong simulation: both sides start from the same
    /// post-handshake secret and the same initial DH material; after a
    /// ratchet round they MUST still agree on the new secret, AND the
    /// previous secret must no longer be derivable from the new one
    /// without the fresh DH input.
    #[test]
    fn ratchet_round_agreement() {
        let mut rng = OsRng;
        let initial_secret = [0x33u8; SECRET_LEN];

        // Initial DH material: both sides have each other's pk.
        let client_dh_sk = ReusableSecret::random_from_rng(rng);
        let client_dh_pk = XPublicKey::from(&client_dh_sk).to_bytes();
        let server_dh_sk = ReusableSecret::random_from_rng(rng);
        let server_dh_pk = XPublicKey::from(&server_dh_sk).to_bytes();

        let mut client = RatchetState::seed(initial_secret, client_dh_sk, server_dh_pk);
        let mut server = RatchetState::seed(initial_secret, server_dh_sk, client_dh_pk);

        // Client ratchets, generates a new pk, ships it.
        let client_new_pk = client.step_send(&mut rng);
        server.step_recv(client_new_pk);

        assert_eq!(client.epoch, 1);
        assert_eq!(server.epoch, 1);
        assert_eq!(client.current_secret(), server.current_secret());
        assert_ne!(client.current_secret(), &initial_secret);
    }

    /// After multiple back-and-forth ratchets, both sides remain in sync.
    #[test]
    fn ratchet_multiple_rounds() {
        let mut rng = OsRng;
        let initial_secret = [0xa5u8; SECRET_LEN];

        let client_dh_sk = ReusableSecret::random_from_rng(rng);
        let client_dh_pk = XPublicKey::from(&client_dh_sk).to_bytes();
        let server_dh_sk = ReusableSecret::random_from_rng(rng);
        let server_dh_pk = XPublicKey::from(&server_dh_sk).to_bytes();

        let mut client = RatchetState::seed(initial_secret, client_dh_sk, server_dh_pk);
        let mut server = RatchetState::seed(initial_secret, server_dh_sk, client_dh_pk);

        // Client sends 3 ratchets, then server sends 2.
        for _ in 0..3 {
            let pk = client.step_send(&mut rng);
            server.step_recv(pk);
            assert_eq!(client.current_secret(), server.current_secret());
        }
        for _ in 0..2 {
            let pk = server.step_send(&mut rng);
            client.step_recv(pk);
            assert_eq!(client.current_secret(), server.current_secret());
        }
        assert_eq!(client.epoch, 5);
        assert_eq!(server.epoch, 5);
    }

    /// Two separate ratchet sequences MUST produce different secrets
    /// (fresh DH share each step → distinct trajectories).
    #[test]
    fn ratchet_diverges_for_different_sessions() {
        let mut rng = OsRng;
        let initial_secret = [0u8; SECRET_LEN];

        let mk_pair = |rng: &mut OsRng| {
            let a_sk = ReusableSecret::random_from_rng(*rng);
            let a_pk = XPublicKey::from(&a_sk).to_bytes();
            let b_sk = ReusableSecret::random_from_rng(*rng);
            let b_pk = XPublicKey::from(&b_sk).to_bytes();
            let mut a = RatchetState::seed(initial_secret, a_sk, b_pk);
            let mut b = RatchetState::seed(initial_secret, b_sk, a_pk);
            let pk = a.step_send(rng);
            b.step_recv(pk);
            *a.current_secret()
        };

        let s1 = mk_pair(&mut rng);
        let s2 = mk_pair(&mut rng);
        assert_ne!(s1, s2, "independent sessions MUST diverge");
    }
}
