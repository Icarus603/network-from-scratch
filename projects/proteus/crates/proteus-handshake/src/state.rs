//! Handshake state machine (spec §5.1).

use thiserror::Error;

/// Handshake states, mirroring spec §5.1's Mermaid diagram exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(missing_docs)] // each variant is documented in the spec
pub enum State {
    Init,
    AuthParsed,
    AuthVerified,
    DecapsDone,
    SecretsDerived,
    ServerHelloSent,
    WaitClientFinished,
    Connected,
    Ratcheting,
    MultipathProbing,
    ShapeTransitioning,
    Closing,
    Fallback,
    FallbackForwarding,
    FatalClose,
}

/// Transition triggers — high-level events fed into the state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Event {
    RecvClientHelloWithAuthExt,
    AuthExtMalformed,
    AuthTagOk,
    AuthTagBad,
    DecapsOk,
    DecapsFail,
    SecretsReady,
    ServerSendDone,
    RecvClientFinishedOk,
    RecvClientFinishedBad,
    SendKeyUpdate,
    RecvKeyUpdate,
    KeyUpdateConfirmed,
    NewPathInitiated,
    PathChallengeAnswered,
    ShapeTickStarted,
    ShapeTickComplete,
    RecvClose,
    IdleTimeout,
    AeadFailureInData, // silently dropped, not a state change
    CoverForwardOpened,
    CoverConnectionClosed,
}

/// Errors raised by an invalid transition.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TransitionError {
    /// The given event is illegal in the current state.
    #[error("illegal transition: {from:?} --({event:?})-->")]
    Illegal {
        /// Source state.
        from: State,
        /// Triggering event.
        event: Event,
    },
}

impl State {
    /// Apply `event` and return the next state, or
    /// [`TransitionError::Illegal`] if the transition is undefined.
    ///
    /// Defined transitions (spec §5.1):
    ///
    /// | From | Event | To |
    /// |---|---|---|
    /// | Init | RecvClientHelloWithAuthExt | AuthParsed |
    /// | Init | AuthExtMalformed | Fallback |
    /// | AuthParsed | AuthTagOk | AuthVerified |
    /// | AuthParsed | AuthTagBad | Fallback |
    /// | AuthVerified | DecapsOk | DecapsDone |
    /// | AuthVerified | DecapsFail | Fallback |
    /// | DecapsDone | SecretsReady | SecretsDerived |
    /// | SecretsDerived | ServerSendDone | ServerHelloSent |
    /// | ServerHelloSent | (impl-detail) | WaitClientFinished |
    /// | WaitClientFinished | RecvClientFinishedOk | Connected |
    /// | WaitClientFinished | RecvClientFinishedBad | FatalClose |
    /// | Connected | SendKeyUpdate \| RecvKeyUpdate | Ratcheting |
    /// | Ratcheting | KeyUpdateConfirmed | Connected |
    /// | Connected | NewPathInitiated | MultipathProbing |
    /// | MultipathProbing | PathChallengeAnswered | Connected |
    /// | Connected | ShapeTickStarted | ShapeTransitioning |
    /// | ShapeTransitioning | ShapeTickComplete | Connected |
    /// | Connected | RecvClose \| IdleTimeout | Closing |
    /// | Fallback | CoverForwardOpened | FallbackForwarding |
    /// | FallbackForwarding | CoverConnectionClosed | Closing |
    /// | Connected | AeadFailureInData | Connected (no-op; silently drop) |
    pub fn step(self, event: Event) -> Result<Self, TransitionError> {
        use Event as E;
        use State as S;
        let next = match (self, event) {
            (S::Init, E::RecvClientHelloWithAuthExt) => S::AuthParsed,
            (S::Init, E::AuthExtMalformed) => S::Fallback,
            (S::AuthParsed, E::AuthTagOk) => S::AuthVerified,
            (S::AuthParsed, E::AuthTagBad) => S::Fallback,
            (S::AuthVerified, E::DecapsOk) => S::DecapsDone,
            (S::AuthVerified, E::DecapsFail) => S::Fallback,
            (S::DecapsDone, E::SecretsReady) => S::SecretsDerived,
            (S::SecretsDerived, E::ServerSendDone) => S::ServerHelloSent,
            (S::ServerHelloSent, _) => S::WaitClientFinished, // implicit advance
            (S::WaitClientFinished, E::RecvClientFinishedOk) => S::Connected,
            (S::WaitClientFinished, E::RecvClientFinishedBad) => S::FatalClose,
            (S::Connected, E::SendKeyUpdate | E::RecvKeyUpdate) => S::Ratcheting,
            (S::Ratcheting, E::KeyUpdateConfirmed) => S::Connected,
            (S::Connected, E::NewPathInitiated) => S::MultipathProbing,
            (S::MultipathProbing, E::PathChallengeAnswered) => S::Connected,
            (S::Connected, E::ShapeTickStarted) => S::ShapeTransitioning,
            (S::ShapeTransitioning, E::ShapeTickComplete) => S::Connected,
            (S::Connected, E::RecvClose | E::IdleTimeout) => S::Closing,
            (S::Fallback, E::CoverForwardOpened) => S::FallbackForwarding,
            (S::FallbackForwarding, E::CoverConnectionClosed) => S::Closing,
            (S::Connected, E::AeadFailureInData) => S::Connected, // silent drop
            (from, event) => return Err(TransitionError::Illegal { from, event }),
        };
        Ok(next)
    }

    /// Whether this state is a terminal sink (`Closing` / `FatalClose`).
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Closing | Self::FatalClose)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_path_to_connected() {
        let mut s = State::Init;
        s = s.step(Event::RecvClientHelloWithAuthExt).unwrap();
        s = s.step(Event::AuthTagOk).unwrap();
        s = s.step(Event::DecapsOk).unwrap();
        s = s.step(Event::SecretsReady).unwrap();
        s = s.step(Event::ServerSendDone).unwrap();
        s = s.step(Event::RecvClientFinishedOk).unwrap();
        // Actually, ServerHelloSent advances to WaitClientFinished implicitly:
        assert_eq!(s, State::WaitClientFinished);
        let s = s.step(Event::RecvClientFinishedOk).unwrap();
        assert_eq!(s, State::Connected);
    }

    #[test]
    fn auth_fail_routes_to_fallback() {
        let s = State::Init
            .step(Event::RecvClientHelloWithAuthExt)
            .unwrap()
            .step(Event::AuthTagBad)
            .unwrap();
        assert_eq!(s, State::Fallback);
        let s = s.step(Event::CoverForwardOpened).unwrap();
        assert_eq!(s, State::FallbackForwarding);
        let s = s.step(Event::CoverConnectionClosed).unwrap();
        assert!(s.is_terminal());
    }

    #[test]
    fn aead_failure_in_data_is_silent_drop() {
        let s = State::Connected.step(Event::AeadFailureInData).unwrap();
        assert_eq!(s, State::Connected);
    }

    #[test]
    fn shape_transition_cycles_back_to_connected() {
        let s = State::Connected.step(Event::ShapeTickStarted).unwrap();
        assert_eq!(s, State::ShapeTransitioning);
        let s = s.step(Event::ShapeTickComplete).unwrap();
        assert_eq!(s, State::Connected);
    }

    #[test]
    fn ratchet_cycles_back_to_connected() {
        for trigger in [Event::SendKeyUpdate, Event::RecvKeyUpdate] {
            let s = State::Connected.step(trigger).unwrap();
            assert_eq!(s, State::Ratcheting);
            let s = s.step(Event::KeyUpdateConfirmed).unwrap();
            assert_eq!(s, State::Connected);
        }
    }

    #[test]
    fn multipath_probe_cycles_back_to_connected() {
        let s = State::Connected.step(Event::NewPathInitiated).unwrap();
        assert_eq!(s, State::MultipathProbing);
        let s = s.step(Event::PathChallengeAnswered).unwrap();
        assert_eq!(s, State::Connected);
    }

    #[test]
    fn illegal_transition_errors() {
        let err = State::Init.step(Event::RecvKeyUpdate).unwrap_err();
        assert!(matches!(
            err,
            TransitionError::Illegal {
                from: State::Init,
                event: Event::RecvKeyUpdate
            }
        ));
    }
}
