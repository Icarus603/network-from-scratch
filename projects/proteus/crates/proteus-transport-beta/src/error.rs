//! β-profile error type.
//!
//! Wraps `quinn::ConnectionError` / `quinn::ConnectError` /
//! `rustls::Error` + io::Error into one operator-visible enum so
//! callers can match without pulling every QUIC crate's error type
//! into their imports.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum BetaError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("quinn-connect: {0}")]
    QuinnConnect(#[from] quinn::ConnectError),

    #[error("quinn-conn: {0}")]
    QuinnConn(#[from] quinn::ConnectionError),

    #[error("quinn-write: {0}")]
    QuinnWrite(#[from] quinn::WriteError),

    #[error("rustls: {0}")]
    Rustls(#[from] rustls::Error),

    #[error("invalid server name: {0}")]
    BadServerName(String),

    #[error("alpn mismatch: peer offered {0:?}, expected {1:?}")]
    AlpnMismatch(Vec<u8>, Vec<u8>),

    #[error("inner proteus handshake: {0}")]
    Inner(#[from] proteus_transport_alpha::error::AlphaError),

    #[error("crypto provider install failed")]
    CryptoInstall,
}
