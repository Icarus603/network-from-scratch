//! Profile-α transport errors.

use proteus_crypto::CryptoError;
use proteus_wire::WireError;

/// Errors surfaced by the α-profile transport.
#[derive(Debug, thiserror::Error)]
pub enum AlphaError {
    /// I/O failure from the underlying TCP socket.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Wire-format parse error. Server-side: caller MUST forward to cover.
    #[error("wire format error: {0}")]
    Wire(#[from] WireError),

    /// Cryptographic operation failed. AEAD failures are *silently dropped*
    /// on the data plane (see [`session::AlphaSession::recv_record`]); they
    /// are only surfaced when raised on the handshake plane.
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),

    /// HMAC auth-tag verification failed (spec §4.1.3). On the server,
    /// triggers the cover-forward path; on the client, raises this error.
    #[error("auth tag verification failed")]
    AuthTagInvalid,

    /// Anti-replay window rejected this `(nonce, timestamp)` pair (spec §8).
    #[error("auth-extension marked as replay")]
    AuthReplay,

    /// Timestamp skew exceeded the spec §8.2 window.
    #[error("auth-extension timestamp out of window")]
    AuthStale,

    /// Server-side `Finished` MAC did not match the transcript.
    #[error("server finished MAC mismatch")]
    BadServerFinished,

    /// Client-side `Finished` MAC did not match the transcript.
    #[error("client finished MAC mismatch")]
    BadClientFinished,

    /// Connection closed by peer before the operation could complete.
    #[error("connection closed prematurely")]
    Closed,

    /// Sequence-number space exhausted (spec §4.5 — 40-bit seqnum, 2^40 packets).
    #[error("seqnum exhausted in current epoch")]
    SeqnumExhausted,
}

/// Convenience alias.
pub type AlphaResult<T> = Result<T, AlphaError>;
