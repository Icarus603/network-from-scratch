//! Proteus profile-β — **QUIC over UDP** carrier.
//!
//! **M2 scaffolding status.** This crate ships a working QUIC carrier
//! using [`quinn`] that wraps the existing α-profile Proteus
//! handshake + AEAD stream framing. It deliberately keeps the inner
//! protocol byte-identical to α (per spec §10.2: carrier-agnostic
//! framing), so all the field-tested crypto + admission paths in
//! `proteus-transport-alpha` are reused verbatim.
//!
//! ## Why a separate crate
//!
//! The motivating gap behind β is **transport speed**. TCP carriers
//! suffer head-of-line blocking and TCP's classical CC interacts
//! badly with the loss patterns censorship environments exhibit
//! (see Hysteria2 / TUIC-v5 motivation literature). QUIC over UDP:
//!
//! - No HoL blocking — independent stream loss is recovered per-stream.
//! - 0-RTT / 1-RTT handshake amortizes the TLS+Proteus setup cost.
//! - User-space congestion control — quinn's BBR-style controller
//!   sustains throughput on the lossy long-fat-pipe scenarios the
//!   TCP α-profile underperforms on.
//!
//! ## Scope of this M2 release
//!
//! This is the **scaffolding** commit: client + server can establish
//! a QUIC connection with `proteus-β-v1` ALPN, open ONE bidirectional
//! stream, and run the existing Proteus handshake over it. What's
//! deliberately deferred:
//!
//! - **Multipath** (`draft-ietf-quic-multipath`) — spec §10.4. M4.
//! - **ECH binding** (spec §7.4) — needs a real cover URL with HTTPS
//!   RR. M3.
//! - **`0xfe0d` ClientHello injection** (spec §4.2) — needs rustls
//!   fork or quinn raw-handshake hook. M3.
//! - **Cover forwarding on QUIC failure** — UDP has no graceful
//!   forward; the spec calls this out as "stop responding for the
//!   IdleTimeout window" (§7.5 QUIC variant). Wired here as a
//!   silent drop pending the spec's full design.
//!
//! What does work end-to-end as of this crate:
//!
//! - Real QUIC 1 connection.
//! - Server-presented TLS 1.3 cert (rustls).
//! - ALPN negotiation pinning to `proteus-β-v1`.
//! - Per-connection idle timeout + max-streams = 1 (single inner
//!   stream by design for this M2; M3 will multiplex sub-flows).
//! - All α-profile crypto: hybrid X25519+ML-KEM-768, full key
//!   schedule, AEAD record stream, anti-replay, PoW, ratchet —
//!   inherited via `proteus_transport_alpha::session::AlphaSession`.

#![forbid(unsafe_code)]

pub mod client;
pub mod error;
pub mod server;

/// The β-profile ALPN identifier, per spec §14.4 ("ALPN Protocol IDs:
/// `proteus-β-v1`"). Both client and server pin this exactly; any
/// mismatch surfaces as a TLS alert at handshake time.
pub const ALPN: &[u8] = b"proteus-\xce\xb2-v1";

#[cfg(test)]
mod alpn_test {
    use super::ALPN;
    #[test]
    fn alpn_is_utf8_proteus_beta_v1() {
        // β is U+03B2 GREEK SMALL LETTER BETA, two bytes in UTF-8:
        // 0xce 0xb2. The full bytestring decodes to "proteus-β-v1".
        let s = std::str::from_utf8(ALPN).expect("ALPN must be UTF-8");
        assert_eq!(s, "proteus-β-v1");
    }
}
