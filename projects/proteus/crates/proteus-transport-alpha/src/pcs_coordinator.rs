//! Pure state machine for the v1.3 two-party PCS exchange.
//!
//! Network I/O and task wakeups stay in `session`; this module owns
//! generation, offer, commit, directional-secret, and fail-closed
//! transition invariants without taking a lock on the data hot path.

use proteus_crypto::pcs_ratchet::{PcsOffer, PcsProposal, PcsRole, PcsTrafficSecrets};
use proteus_crypto::CryptoError;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PcsCommit {
    pub(crate) generation: u64,
    pub(crate) transcript_hash: [u8; 32],
}

pub(crate) enum PcsOutbound {
    Offer(PcsOffer),
    Commit(PcsCommit, Zeroizing<[u8; 32]>),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum PcsCoordinatorError {
    #[error("PCS generation exhausted")]
    GenerationExhausted,
    #[error("PCS generation mismatch: expected {expected}, got {got}")]
    GenerationMismatch { expected: u64, got: u64 },
    #[error("conflicting PCS offer for generation {0}")]
    ConflictingOffer(u64),
    #[error("PCS commit arrived before both offers were derived")]
    CommitBeforeDerived,
    #[error("PCS commit transcript mismatch")]
    CommitMismatch,
    #[error("local PCS commit already emitted")]
    LocalCommitAlreadyEmitted,
    #[error("peer PCS commit already consumed")]
    PeerCommitAlreadyConsumed,
    #[error("PCS cryptographic failure: {0}")]
    Crypto(#[from] CryptoError),
}

pub(crate) struct PcsCoordinator {
    role: PcsRole,
    current_generation: u64,
    old_client_to_server: Zeroizing<[u8; 32]>,
    old_server_to_client: Zeroizing<[u8; 32]>,
    local_proposal: Option<PcsProposal>,
    local_offer: Option<PcsOffer>,
    peer_offer: Option<PcsOffer>,
    derived: Option<PcsTrafficSecrets>,
    local_offer_emitted: bool,
    local_commit_emitted: bool,
    peer_commit_consumed: bool,
}

impl PcsCoordinator {
    pub(crate) fn new(
        role: PcsRole,
        old_client_to_server: [u8; 32],
        old_server_to_client: [u8; 32],
    ) -> Self {
        Self {
            role,
            current_generation: 0,
            old_client_to_server: Zeroizing::new(old_client_to_server),
            old_server_to_client: Zeroizing::new(old_server_to_client),
            local_proposal: None,
            local_offer: None,
            peer_offer: None,
            derived: None,
            local_offer_emitted: false,
            local_commit_emitted: false,
            peer_commit_consumed: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn current_generation(&self) -> u64 {
        self.current_generation
    }

    pub(crate) fn has_outbound(&self) -> bool {
        (self.local_offer.is_some() && !self.local_offer_emitted)
            || (self.derived.is_some() && !self.local_commit_emitted)
    }

    pub(crate) fn exchange_in_flight(&self) -> bool {
        self.local_proposal.is_some()
            || self.local_offer.is_some()
            || self.peer_offer.is_some()
            || self.derived.is_some()
            || self.local_commit_emitted
            || self.peer_commit_consumed
    }

    pub(crate) fn initiate<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<PcsOffer, PcsCoordinatorError> {
        if let Some(offer) = self.local_offer {
            return Ok(offer);
        }
        let generation = self
            .current_generation
            .checked_add(1)
            .ok_or(PcsCoordinatorError::GenerationExhausted)?;
        let proposal = PcsProposal::generate(self.role, generation, rng);
        let offer = proposal.offer();
        self.local_proposal = Some(proposal);
        self.local_offer = Some(offer);
        self.derive_if_ready()?;
        Ok(offer)
    }

    /// Accept a peer offer and return the local offer that must be sent
    /// (newly generated or the existing simultaneous-initiation offer).
    pub(crate) fn receive_offer<R: RngCore + CryptoRng>(
        &mut self,
        offer: PcsOffer,
        rng: &mut R,
    ) -> Result<PcsOffer, PcsCoordinatorError> {
        let expected = self
            .current_generation
            .checked_add(1)
            .ok_or(PcsCoordinatorError::GenerationExhausted)?;
        if offer.generation != expected {
            return Err(PcsCoordinatorError::GenerationMismatch {
                expected,
                got: offer.generation,
            });
        }
        if let Some(existing) = self.peer_offer {
            if existing != offer {
                return Err(PcsCoordinatorError::ConflictingOffer(offer.generation));
            }
        } else {
            self.peer_offer = Some(offer);
        }

        let local = self.initiate(rng)?;
        self.derive_if_ready()?;
        Ok(local)
    }

    pub(crate) fn next_outbound(&mut self) -> Result<Option<PcsOutbound>, PcsCoordinatorError> {
        if let Some(offer) = self.local_offer {
            if !self.local_offer_emitted {
                self.local_offer_emitted = true;
                return Ok(Some(PcsOutbound::Offer(offer)));
            }
        }
        if self.derived.is_some() && !self.local_commit_emitted {
            let (commit, secret) = self.emit_local_commit()?;
            return Ok(Some(PcsOutbound::Commit(commit, secret)));
        }
        Ok(None)
    }

    /// Emit the local commit and return the replacement local send secret.
    pub(crate) fn emit_local_commit(
        &mut self,
    ) -> Result<(PcsCommit, Zeroizing<[u8; 32]>), PcsCoordinatorError> {
        if self.local_commit_emitted {
            return Err(PcsCoordinatorError::LocalCommitAlreadyEmitted);
        }
        let derived = self
            .derived
            .as_ref()
            .ok_or(PcsCoordinatorError::CommitBeforeDerived)?;
        let commit = PcsCommit {
            generation: self
                .current_generation
                .checked_add(1)
                .ok_or(PcsCoordinatorError::GenerationExhausted)?,
            transcript_hash: derived.transcript_hash,
        };
        let send_secret = match self.role {
            PcsRole::Client => Zeroizing::new(*derived.client_to_server),
            PcsRole::Server => Zeroizing::new(*derived.server_to_client),
        };
        self.local_commit_emitted = true;
        self.finish_if_complete();
        Ok((commit, send_secret))
    }

    /// Validate the peer commit and return the replacement local receive secret.
    pub(crate) fn receive_peer_commit(
        &mut self,
        commit: PcsCommit,
    ) -> Result<Zeroizing<[u8; 32]>, PcsCoordinatorError> {
        if self.peer_commit_consumed {
            return Err(PcsCoordinatorError::PeerCommitAlreadyConsumed);
        }
        let expected_generation = self
            .current_generation
            .checked_add(1)
            .ok_or(PcsCoordinatorError::GenerationExhausted)?;
        if commit.generation != expected_generation {
            return Err(PcsCoordinatorError::GenerationMismatch {
                expected: expected_generation,
                got: commit.generation,
            });
        }
        let derived = self
            .derived
            .as_ref()
            .ok_or(PcsCoordinatorError::CommitBeforeDerived)?;
        if commit.transcript_hash != derived.transcript_hash {
            return Err(PcsCoordinatorError::CommitMismatch);
        }
        let receive_secret = match self.role {
            PcsRole::Client => Zeroizing::new(*derived.server_to_client),
            PcsRole::Server => Zeroizing::new(*derived.client_to_server),
        };
        self.peer_commit_consumed = true;
        self.finish_if_complete();
        Ok(receive_secret)
    }

    fn derive_if_ready(&mut self) -> Result<(), PcsCoordinatorError> {
        if self.derived.is_some() {
            return Ok(());
        }
        let Some(peer) = self.peer_offer else {
            return Ok(());
        };
        let Some(proposal) = self.local_proposal.take() else {
            return Ok(());
        };
        self.derived = Some(proposal.complete(
            peer,
            &self.old_client_to_server,
            &self.old_server_to_client,
        )?);
        Ok(())
    }

    fn finish_if_complete(&mut self) {
        if !(self.local_commit_emitted && self.peer_commit_consumed) {
            return;
        }
        let derived = self
            .derived
            .take()
            .expect("both commits imply derived PCS secrets");
        self.old_client_to_server = derived.client_to_server;
        self.old_server_to_client = derived.server_to_client;
        self.current_generation = self
            .current_generation
            .checked_add(1)
            .expect("generation exhaustion rejected before proposal");
        self.local_proposal = None;
        self.local_offer = None;
        self.peer_offer = None;
        self.local_offer_emitted = false;
        self.local_commit_emitted = false;
        self.peer_commit_consumed = false;
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::*;

    fn pair() -> (PcsCoordinator, PcsCoordinator) {
        let old_c2s = [0x11; 32];
        let old_s2c = [0x22; 32];
        (
            PcsCoordinator::new(PcsRole::Client, old_c2s, old_s2c),
            PcsCoordinator::new(PcsRole::Server, old_c2s, old_s2c),
        )
    }

    #[test]
    fn simultaneous_offers_commit_matching_directional_secrets() {
        let mut rng = OsRng;
        let (mut client, mut server) = pair();
        let client_offer = client.initiate(&mut rng).unwrap();
        let server_offer = server.initiate(&mut rng).unwrap();
        assert_eq!(
            client.receive_offer(server_offer, &mut rng).unwrap(),
            client_offer
        );
        assert_eq!(
            server.receive_offer(client_offer, &mut rng).unwrap(),
            server_offer
        );

        let (client_commit, client_send) = client.emit_local_commit().unwrap();
        let (server_commit, server_send) = server.emit_local_commit().unwrap();
        let client_receive = client.receive_peer_commit(server_commit).unwrap();
        let server_receive = server.receive_peer_commit(client_commit).unwrap();

        assert_eq!(client_send, server_receive);
        assert_eq!(server_send, client_receive);
        assert_ne!(client_send, server_send);
        assert_eq!(client.current_generation(), 1);
        assert_eq!(server.current_generation(), 1);
    }

    #[test]
    fn peer_offer_auto_generates_local_response() {
        let mut rng = OsRng;
        let (mut client, mut server) = pair();
        let client_offer = client.initiate(&mut rng).unwrap();
        let server_offer = server.receive_offer(client_offer, &mut rng).unwrap();
        assert_eq!(
            client.receive_offer(server_offer, &mut rng).unwrap(),
            client_offer
        );

        let (server_commit, server_send) = server.emit_local_commit().unwrap();
        let (client_commit, client_send) = client.emit_local_commit().unwrap();
        let client_receive = client.receive_peer_commit(server_commit).unwrap();
        let server_receive = server.receive_peer_commit(client_commit).unwrap();
        assert_eq!(client_send, server_receive);
        assert_eq!(server_send, client_receive);
    }

    #[test]
    fn conflicting_offer_same_generation_fails_closed() {
        let mut rng = OsRng;
        let (_, mut server) = pair();
        let first = PcsProposal::generate(PcsRole::Client, 1, &mut rng).offer();
        let second = PcsProposal::generate(PcsRole::Client, 1, &mut rng).offer();
        server.receive_offer(first, &mut rng).unwrap();
        let err = server.receive_offer(second, &mut rng).unwrap_err();
        assert!(matches!(err, PcsCoordinatorError::ConflictingOffer(1)));
    }

    #[test]
    fn commit_before_both_offers_fails_closed() {
        let (mut client, _) = pair();
        let err = client
            .receive_peer_commit(PcsCommit {
                generation: 1,
                transcript_hash: [0; 32],
            })
            .unwrap_err();
        assert!(matches!(err, PcsCoordinatorError::CommitBeforeDerived));
    }

    #[test]
    fn transcript_mismatch_fails_closed() {
        let mut rng = OsRng;
        let (mut client, mut server) = pair();
        let client_offer = client.initiate(&mut rng).unwrap();
        let server_offer = server.receive_offer(client_offer, &mut rng).unwrap();
        client.receive_offer(server_offer, &mut rng).unwrap();
        let err = client
            .receive_peer_commit(PcsCommit {
                generation: 1,
                transcript_hash: [0; 32],
            })
            .unwrap_err();
        assert!(matches!(err, PcsCoordinatorError::CommitMismatch));
    }

    #[test]
    fn completed_generation_can_advance_again_with_fresh_keys() {
        let mut rng = OsRng;
        let (mut client, mut server) = pair();
        let mut first_client_send = None;

        for generation in 1..=2 {
            let client_offer = client.initiate(&mut rng).unwrap();
            let server_offer = server.receive_offer(client_offer, &mut rng).unwrap();
            client.receive_offer(server_offer, &mut rng).unwrap();
            let (client_commit, client_send) = client.emit_local_commit().unwrap();
            let (server_commit, _) = server.emit_local_commit().unwrap();
            client.receive_peer_commit(server_commit).unwrap();
            server.receive_peer_commit(client_commit).unwrap();
            if let Some(first) = first_client_send {
                assert_ne!(first, *client_send);
            } else {
                first_client_send = Some(*client_send);
            }
            assert_eq!(client.current_generation(), generation);
            assert_eq!(server.current_generation(), generation);
        }
    }
}
