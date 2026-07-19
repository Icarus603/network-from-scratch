//! Two-party fresh/fresh DH ratchet primitive.
//!
//! This module implements the cryptographic core required by
//! `formal/proverif/proteus-two-party-pcs-ratchet.pv`. Both endpoints
//! generate a new X25519 secret *after* the compromise point, exchange
//! public offers, and derive canonical client→server and server→client
//! traffic secrets from:
//!
//! - both old directional traffic secrets;
//! - the fresh/fresh X25519 result;
//! - the generation number and ordered public-share transcript.
//!
//! The wire/state machine is deliberately separate. In particular,
//! callers must not describe this primitive as active PCS when the
//! offer exchange is authenticated only by compromised session keys.

use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::{kdf, CryptoError};

const C2S_LABEL: &[u8] = b"two-party pcs c2s v1";
const S2C_LABEL: &[u8] = b"two-party pcs s2c v1";
const TRANSCRIPT_DOMAIN: &[u8] = b"proteus two-party pcs transcript v1";
const OLD_STATE_DOMAIN: &[u8] = b"proteus two-party pcs old state v1";

/// Endpoint role fixes the public-share transcript ordering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PcsRole {
    /// Client endpoint.
    Client,
    /// Server endpoint.
    Server,
}

/// Public half of a two-party PCS proposal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PcsOffer {
    /// Monotonic session-local rekey generation.
    pub generation: u64,
    /// Fresh X25519 public share.
    pub public_key: [u8; 32],
}

/// Canonically ordered replacement traffic secrets.
pub struct PcsTrafficSecrets {
    /// Client-to-server traffic secret.
    pub client_to_server: Zeroizing<[u8; 32]>,
    /// Server-to-client traffic secret.
    pub server_to_client: Zeroizing<[u8; 32]>,
    /// Hash of generation plus ordered client/server public shares.
    pub transcript_hash: [u8; 32],
}

/// Local fresh proposal. Consumed exactly once on completion.
pub struct PcsProposal {
    role: PcsRole,
    offer: PcsOffer,
    secret: StaticSecret,
}

impl PcsProposal {
    /// Generate a fresh proposal for `generation`.
    pub fn generate<R: RngCore + CryptoRng>(role: PcsRole, generation: u64, rng: &mut R) -> Self {
        let secret = StaticSecret::random_from_rng(rng);
        let public_key = XPublicKey::from(&secret).to_bytes();
        Self {
            role,
            offer: PcsOffer {
                generation,
                public_key,
            },
            secret,
        }
    }

    /// Return the public offer to send to the peer.
    #[must_use]
    pub fn offer(&self) -> PcsOffer {
        self.offer
    }

    /// Consume this proposal and derive both replacement directional
    /// secrets from the matching peer offer.
    ///
    /// `old_client_to_server` and `old_server_to_client` must always
    /// be passed in canonical wire direction, regardless of local role.
    pub fn complete(
        self,
        peer: PcsOffer,
        old_client_to_server: &[u8; 32],
        old_server_to_client: &[u8; 32],
    ) -> Result<PcsTrafficSecrets, CryptoError> {
        if peer.generation != self.offer.generation {
            return Err(CryptoError::PcsGeneration);
        }

        let peer_public = XPublicKey::from(peer.public_key);
        let shared = self.secret.diffie_hellman(&peer_public);
        let zero = [0u8; 32];
        if bool::from(shared.as_bytes().ct_eq(&zero)) {
            return Err(CryptoError::X25519ZeroOutput);
        }

        let (client_public, server_public) = match self.role {
            PcsRole::Client => (self.offer.public_key, peer.public_key),
            PcsRole::Server => (peer.public_key, self.offer.public_key),
        };

        let mut transcript = Sha256::new();
        transcript.update(TRANSCRIPT_DOMAIN);
        transcript.update(self.offer.generation.to_be_bytes());
        transcript.update(client_public);
        transcript.update(server_public);
        let transcript_hash: [u8; 32] = transcript.finalize().into();

        let mut old_state = Sha256::new();
        old_state.update(OLD_STATE_DOMAIN);
        old_state.update(old_client_to_server);
        old_state.update(old_server_to_client);
        let mut old_state_hash: [u8; 32] = old_state.finalize().into();

        let root = kdf::extract(&old_state_hash, shared.as_bytes());
        old_state_hash.zeroize();

        let mut client_to_server = Zeroizing::new([0u8; 32]);
        let mut server_to_client = Zeroizing::new([0u8; 32]);
        kdf::expand_label(
            &root,
            C2S_LABEL,
            &transcript_hash,
            client_to_server.as_mut(),
        )?;
        kdf::expand_label(
            &root,
            S2C_LABEL,
            &transcript_hash,
            server_to_client.as_mut(),
        )?;

        Ok(PcsTrafficSecrets {
            client_to_server,
            server_to_client,
            transcript_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::*;

    #[test]
    fn client_and_server_derive_identical_directional_secrets() {
        let mut rng = OsRng;
        let client = PcsProposal::generate(PcsRole::Client, 7, &mut rng);
        let server = PcsProposal::generate(PcsRole::Server, 7, &mut rng);
        let client_offer = client.offer();
        let server_offer = server.offer();
        let old_c2s = [0x11; 32];
        let old_s2c = [0x22; 32];

        let client_result = client
            .complete(server_offer, &old_c2s, &old_s2c)
            .expect("client completes");
        let server_result = server
            .complete(client_offer, &old_c2s, &old_s2c)
            .expect("server completes");

        assert_eq!(
            client_result.client_to_server,
            server_result.client_to_server
        );
        assert_eq!(
            client_result.server_to_client,
            server_result.server_to_client
        );
        assert_eq!(client_result.transcript_hash, server_result.transcript_hash);
        assert_ne!(&*client_result.client_to_server, &old_c2s);
        assert_ne!(&*client_result.server_to_client, &old_s2c);
        assert_ne!(
            client_result.client_to_server,
            client_result.server_to_client
        );
    }

    #[test]
    fn same_compromised_old_state_heals_to_distinct_fresh_results() {
        let mut rng = OsRng;
        let old_c2s = [0x44; 32];
        let old_s2c = [0x55; 32];

        let derive_once = |rng: &mut OsRng| {
            let client = PcsProposal::generate(PcsRole::Client, 9, rng);
            let server = PcsProposal::generate(PcsRole::Server, 9, rng);
            let client_offer = client.offer();
            let server_offer = server.offer();
            let client_result = client
                .complete(server_offer, &old_c2s, &old_s2c)
                .expect("client completes");
            let server_result = server
                .complete(client_offer, &old_c2s, &old_s2c)
                .expect("server completes");
            assert_eq!(
                client_result.client_to_server,
                server_result.client_to_server
            );
            *client_result.client_to_server
        };

        let first = derive_once(&mut rng);
        let second = derive_once(&mut rng);
        assert_ne!(first, second);
    }

    #[test]
    fn generation_mismatch_fails_closed() {
        let mut rng = OsRng;
        let local = PcsProposal::generate(PcsRole::Client, 3, &mut rng);
        let peer = PcsProposal::generate(PcsRole::Server, 4, &mut rng).offer();
        let result = local.complete(peer, &[0x11; 32], &[0x22; 32]);
        assert!(matches!(result, Err(CryptoError::PcsGeneration)));
    }

    #[test]
    fn low_order_peer_share_fails_closed() {
        let mut rng = OsRng;
        let local = PcsProposal::generate(PcsRole::Client, 3, &mut rng);
        let malicious = PcsOffer {
            generation: 3,
            public_key: [0; 32],
        };
        let result = local.complete(malicious, &[0x11; 32], &[0x22; 32]);
        assert!(matches!(result, Err(CryptoError::X25519ZeroOutput)));
    }
}
