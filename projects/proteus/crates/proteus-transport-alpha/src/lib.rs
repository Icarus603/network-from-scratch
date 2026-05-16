//! Proteus profile-α (TLS 1.3 over TCP) reference transport.
//!
//! **M1 status**: this module ships the *raw-TCP carrier* variant of
//! profile-α — a real network end-to-end handshake that exercises every
//! crypto path defined in spec §5 (hybrid X25519+ML-KEM-768, full TLS 1.3
//! key schedule, mutual nonce confirmation via Finished MACs, AEAD-protected
//! record stream). It deliberately omits the real TLS 1.3 record layer so
//! the M1 milestone can be demonstrated with `std` + `tokio` only. M2 will
//! swap the TCP carrier for a rustls-fork that injects `0xfe0d` into a
//! genuine ClientHello.
//!
//! The spec-mandated [`ProteusInnerPacket`]-format payloads (spec §4.5)
//! flow over the AEAD record stream once the handshake completes.
//!
//! ## Compatibility with the full spec
//!
//! - Auth extension byte layout (spec §4.1) — **byte-identical** to the
//!   full spec; serialized via [`proteus_wire::AuthExtension`].
//! - Hybrid KEX (spec §5.2) — full path, including X25519 zero-point
//!   rejection and ML-KEM-768 implicit-rejection-aware shared.
//! - Key schedule (spec §5.2) — full TLS 1.3 four-stage tree, see
//!   [`proteus_crypto::key_schedule::derive`].
//! - Anti-replay (spec §8) — full sliding window + 90s timestamp guard.
//! - AEAD record layer — ChaCha20-Poly1305, 12-byte XOR nonce
//!   (spec §4.5.2), 16-byte tag.
//! - State machine (spec §5.1) — every legitimate transition is taken.

pub mod client;
pub mod cover;
pub mod error;
pub mod firewall;
pub mod metrics;
pub mod metrics_http;
pub mod pow;
pub mod rate_limit;
pub mod server;
pub mod session;
pub mod tls;
