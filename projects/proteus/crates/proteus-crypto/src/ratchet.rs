//! Asymmetric DH ratchet primitive used by the experimental ratchet API.
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
//! Security boundary:
//!
//! 1. Forward secrecy — leaking `current_secret` at time T does not expose
//!    pre-T traffic (HKDF is forward-only).
//! 2. A traffic-secret-only leak can heal after a fresh DH step if the
//!    retained peer DH private state was not compromised.
//! 3. This is not full endpoint-state PCS: an attacker who learns both the
//!    current traffic secret and the retained DH private state can combine
//!    that private share with the next public KEYUPDATE and derive the next
//!    secret. `formal/proverif/proteus-one-shot-ratchet.pv` proves the
//!    limited property and produces the expected full-state attack witness.

use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as XPublicKey, ReusableSecret};
use zeroize::Zeroizing;

use crate::{kdf, CryptoError};

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
    ///
    /// Iter-165: returns `Err(CryptoError::X25519ZeroOutput)` if the
    /// peer's last-known DH public is one of the X25519 low-order
    /// points (RFC 7748 §6.1) — those force the DH output to all-zero,
    /// reducing the new secret to a deterministic
    /// `HKDF(current_secret, 0)` and DEFEATING post-compromise
    /// security for this step. The recv-side wire path
    /// (`session::apply_ratchet`) has the equivalent check; this
    /// closes the matching gap on the send-side `RatchetState` API
    /// so any future user of this module (the α data path, a future
    /// β/γ transport, integration-test harness) inherits the
    /// defense.
    pub fn step_send<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<[u8; 32], CryptoError> {
        let new_sk = ReusableSecret::random_from_rng(&mut *rng);
        let new_pk = XPublicKey::from(&new_sk).to_bytes();
        let shared = new_sk.diffie_hellman(&XPublicKey::from(self.peer_last_dh_pk));
        let zero = [0u8; 32];
        if bool::from(shared.as_bytes().ct_eq(&zero)) {
            // X25519 low-order point on the peer's stored share —
            // either an attacker injected a malicious previous
            // ratchet pubkey OR upstream code seeded the ratchet
            // with one. Either way refuse to advance; the session's
            // current secret stays intact and the caller surfaces
            // the failure to the operator.
            return Err(CryptoError::X25519ZeroOutput);
        }
        let new_secret = kdf::extract(self.current_secret.as_ref(), shared.as_bytes());

        // Install new state.
        self.epoch = self.epoch.wrapping_add(1);
        self.current_secret = Zeroizing::new(*new_secret);
        self.my_last_dh_sk = new_sk;
        Ok(new_pk)
    }

    /// Step the ratchet forward on the **recv** side using the peer's
    /// `new_dh_pk` carried in the KEYUPDATE packet.
    ///
    /// Iter-165: same RFC 7748 §6.1 low-order-point rejection as
    /// `step_send`. A malicious peer who sends a low-order public
    /// in their KEYUPDATE would otherwise force `DH(my_sk,
    /// peer_low_order) = 0`, reducing the new traffic secret to
    /// `HKDF(current_secret, 0)` — a deterministic function of the
    /// pre-compromise state. PCS is broken for any future ratchet
    /// step the attacker can compose this on.
    pub fn step_recv(&mut self, peer_new_dh_pk: [u8; 32]) -> Result<(), CryptoError> {
        let shared = self
            .my_last_dh_sk
            .diffie_hellman(&XPublicKey::from(peer_new_dh_pk));
        let zero = [0u8; 32];
        if bool::from(shared.as_bytes().ct_eq(&zero)) {
            return Err(CryptoError::X25519ZeroOutput);
        }
        let new_secret = kdf::extract(self.current_secret.as_ref(), shared.as_bytes());

        self.epoch = self.epoch.wrapping_add(1);
        self.current_secret = Zeroizing::new(*new_secret);
        self.peer_last_dh_pk = peer_new_dh_pk;
        Ok(())
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
        let client_new_pk = client.step_send(&mut rng).expect("send step");
        server.step_recv(client_new_pk).expect("recv step");

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
            let pk = client.step_send(&mut rng).expect("send step");
            server.step_recv(pk).expect("recv step");
            assert_eq!(client.current_secret(), server.current_secret());
        }
        for _ in 0..2 {
            let pk = server.step_send(&mut rng).expect("send step");
            client.step_recv(pk).expect("recv step");
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
            let pk = a.step_send(rng).expect("send step");
            b.step_recv(pk).expect("recv step");
            *a.current_secret()
        };

        let s1 = mk_pair(&mut rng);
        let s2 = mk_pair(&mut rng);
        assert_ne!(s1, s2, "independent sessions MUST diverge");
    }

    /// Iter-165: a peer who supplies an X25519 low-order point as
    /// their stored DH public (either at seed time or via a
    /// previous KEYUPDATE) must NOT be allowed to advance the
    /// ratchet, because the resulting DH output is the all-zero
    /// shared (RFC 7748 §6.1) and the new traffic secret becomes
    /// a deterministic function of the pre-step `current_secret`
    /// — DEFEATING post-compromise security for that step.
    ///
    /// The seven X25519 low-order points (curve25519-dalek's
    /// `LOW_ORDER_POINTS`) all produce the same all-zero output;
    /// we exercise the first one (`u = 0`) here as representative.
    #[test]
    fn iter165_step_send_rejects_low_order_peer_pubkey() {
        let mut rng = OsRng;
        let initial_secret = [0xfeu8; SECRET_LEN];
        let my_sk = ReusableSecret::random_from_rng(rng);
        // `u = 0` is the X25519 low-order point of order 1 (RFC 7748
        // §6.1 / curve25519-dalek's LOW_ORDER_POINTS[0]).
        let peer_low_order = [0u8; 32];
        let mut state = RatchetState::seed(initial_secret, my_sk, peer_low_order);
        let prev_epoch = state.epoch;
        let prev_secret = *state.current_secret();

        let res = state.step_send(&mut rng);
        assert!(
            matches!(res, Err(CryptoError::X25519ZeroOutput)),
            "iter-165: step_send must reject low-order peer DH pubkey, got {res:?}"
        );
        // CRITICAL: the failed step must NOT advance the ratchet —
        // otherwise an attacker could force the session into a
        // deterministic-key state by sending a low-order pubkey.
        assert_eq!(state.epoch, prev_epoch);
        assert_eq!(state.current_secret(), &prev_secret);
    }

    /// Iter-165: the same low-order-point rejection on the recv
    /// side. A malicious KEYUPDATE carrying `peer_new_dh_pk = [0;
    /// 32]` would otherwise force DH = 0 and a deterministic
    /// post-step secret.
    #[test]
    fn iter165_step_recv_rejects_low_order_peer_pubkey() {
        let rng = OsRng;
        let initial_secret = [0xfeu8; SECRET_LEN];
        let my_sk = ReusableSecret::random_from_rng(rng);
        let peer_normal_sk = ReusableSecret::random_from_rng(rng);
        let peer_normal_pk = XPublicKey::from(&peer_normal_sk).to_bytes();
        let mut state = RatchetState::seed(initial_secret, my_sk, peer_normal_pk);
        let prev_epoch = state.epoch;
        let prev_secret = *state.current_secret();

        // Attacker's KEYUPDATE carries the low-order point.
        let res = state.step_recv([0u8; 32]);
        assert!(
            matches!(res, Err(CryptoError::X25519ZeroOutput)),
            "iter-165: step_recv must reject low-order peer DH pubkey, got {res:?}"
        );
        assert_eq!(state.epoch, prev_epoch);
        assert_eq!(state.current_secret(), &prev_secret);
        // peer_last_dh_pk MUST also be unchanged — otherwise a
        // future step_send would feed the attacker-chosen
        // low-order point as its DH partner.
        assert_eq!(state.peer_last_dh_pk, peer_normal_pk);
    }
}
