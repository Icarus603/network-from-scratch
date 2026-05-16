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
pub mod datagram;
pub mod error;
pub mod server;

/// Apply the production performance tuning that motivated β in the
/// first place: switch the congestion controller from CUBIC (quinn
/// default) to BBR, and raise stream/connection flow-control windows
/// well above the QUIC defaults so a single long-fat-pipe Proteus
/// session isn't permanently flow-controlled at ~64 KiB inflight.
///
/// **Why BBR over CUBIC for censorship-resistance**: CUBIC treats
/// every packet loss as a congestion signal and halves the window.
/// On lossy long-fat-pipe paths (the typical cross-Pacific GFW
/// scenario), this collapses throughput to a small fraction of
/// available bandwidth. BBR estimates bandwidth × min-RTT directly
/// and is loss-tolerant — the same observation Hysteria2 and
/// TUIC-v5 build their entire performance story on.
///
/// **Window sizing**: defaults are 1 MiB stream-receive +
/// 12.5 MB connection-receive (quinn 0.11), which caps throughput
/// to `window / RTT`. At 100 ms RTT that's 100 Mbit/s — fine for
/// LAN, abysmal for transcontinental. We bump to:
///
///   - stream-receive: 64 MiB
///   - connection-receive: 256 MiB
///
/// Sized so 1 Gbit/s × 1 s RTT fits comfortably.
///
/// Public + idempotent — operators wiring β into their own quinn
/// stack can call this on their own [`quinn::TransportConfig`]
/// before handing it to `quinn::{ServerConfig,ClientConfig}`.
pub fn apply_perf_tuning(transport: &mut quinn::TransportConfig) {
    use std::sync::Arc;
    transport
        .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()))
        // Enable QUIC DATAGRAM frames (RFC 9221). Receive-side
        // buffer cap: 8 MiB of buffered application-unread
        // datagrams. Sent datagrams beyond send-buffer back-pressure
        // via try_send/poll_ready semantics.
        .datagram_receive_buffer_size(Some(8 * 1024 * 1024))
        .datagram_send_buffer_size(8 * 1024 * 1024)
        // Per-stream receive window — bytes the SENDER may have in
        // flight on ONE stream before the receiver acks. 64 MiB
        // sustains 1 Gbit/s at ~500 ms RTT.
        .stream_receive_window(quinn::VarInt::from_u32(64 * 1024 * 1024))
        // Per-connection receive window — sum across all streams.
        // 4× the per-stream limit so a future multi-stream config
        // (M3+) doesn't starve.
        .receive_window(quinn::VarInt::from_u32(256 * 1024 * 1024))
        // Per-stream send window — bytes the LOCAL sender will keep
        // buffered before back-pressuring writes. 8 MiB is a
        // sensible Linux-default-ish value.
        .send_window(8 * 1024 * 1024);
}

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
