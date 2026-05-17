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
    apply_perf_tuning_with(transport, PerfProfile::default());
}

/// Performance + privacy knobs for β QUIC. The defaults match what
/// `apply_perf_tuning` ships — Hy2/TUIC5-grade throughput, *plus*
/// a privacy default (`allow_spin_bit = false`) that quinn itself
/// does not enable by default.
///
/// Operators who care more about wire-fingerprint uniformity than
/// raw throughput can flip `pad_quic_datagrams_to_mtu = true`.
#[derive(Debug, Clone, Copy)]
pub struct PerfProfile {
    /// Initial UDP payload size assumed before MTU discovery
    /// negotiates a better value. `1200` is the QUIC v1 safe min;
    /// `1350` is our conservative bump covering most modern paths;
    /// `1452` is the maximum that fits under a 1500-byte Ethernet
    /// MTU with IPv6 + UDP headers (matches Hy2 / TUIC5).
    pub initial_mtu: u16,
    /// When true, quinn pads every application UDP datagram to the
    /// current path-MTU. Defense-in-depth on top of the cell-split
    /// AEAD padding (commit 105268f) — defeats UDP-packet-length
    /// traffic analysis. **OFF by default** because the bandwidth
    /// amplification can ratelimit loopback throughput tests
    /// (lo0 packet pacing on macOS) and modestly increases the
    /// cost on small writes (HTTP/2 control frames etc.). Flip on
    /// for production anti-censorship deployments where bandwidth
    /// >> detectability.
    pub pad_quic_datagrams_to_mtu: bool,
    /// **Wire-visible RTT inference via the QUIC spin bit
    /// (RFC 9000 §17.4)**. When true, on-path passive observers can
    /// measure the connection's round-trip time by watching the
    /// spin bit's toggle frequency in the 1-RTT header. The
    /// information is unencrypted by design — the spin bit is a
    /// deliberate operator-debugging escape hatch QUIC carves out
    /// of its otherwise-encrypted header.
    ///
    /// quinn's default is `true` (set by upstream for ecosystem
    /// compatibility). Proteus's default is **`false`** — we are
    /// not going to leak RTT to any GFW-class observer who has the
    /// budget to watch the spin bit. Set `true` only if you have a
    /// specific operational reason to want the leak (e.g.,
    /// debugging an enterprise network's QoS that uses spin-bit RTT
    /// as a SLA signal).
    pub allow_spin_bit: bool,
    /// **Reduced ACK frequency via RFC 9802 (draft-ietf-quic-ack-frequency)**.
    ///
    /// When set > 1, we ask the peer to bunch up to N ack-eliciting
    /// packets per ACK frame instead of the default 1-ACK-per-2-packets.
    /// On a high-bandwidth bulk-data flow at 1 Gbps (≈ 80 k pkts/s),
    /// this can cut the ACK packet rate by ~5–10× and reclaim CPU
    /// (also the per-packet small-write cost) on the data path.
    /// Hysteria2 and similar quinn-based VPN stacks tune this for
    /// bulk throughput on long-fat-pipe paths.
    ///
    /// **Default: `1` (disabled / quinn upstream behavior).**
    ///
    /// We deliberately ship the disabled default after measuring that
    /// `ack_eliciting_threshold = 10` *catastrophically* harms loopback
    /// throughput (0.5 MiB/s vs 100+ MiB/s) — BBR's bandwidth
    /// estimator cannot converge on a very-low-RTT path when the
    /// peer holds ACKs back by 10 packets. The cost manifests on any
    /// short-RTT scenario (LAN, intra-DC), which means a static
    /// default is a footgun for the operator who happens to deploy
    /// in those regimes.
    ///
    /// Operators with measured long-fat-pipe paths (e.g. cross-
    /// Pacific VPS deployments where the RTT × bandwidth product is
    /// high enough that ACK overhead is meaningful) can opt in via
    /// `beta_ack_eliciting_threshold: 10` in `server.yaml` /
    /// `client.yaml`. The peer is free to ignore the request if it
    /// doesn't support the extension; this knob is best-effort.
    ///
    /// Regression source: tests/throughput_smoke.rs went from
    /// 107 MiB/s → 0.5 MiB/s on loopback when this defaulted to 10.
    pub ack_eliciting_threshold: u32,
    /// Upper bound that MTU discovery will probe up to (bytes).
    ///
    /// quinn's default is 1452 — fits under a 1500-byte Ethernet
    /// MTU with v6 + UDP overhead. Bumping this to e.g. 9000 lets
    /// us discover jumbo-frame paths on intra-DC / IPv6-tunnel
    /// routes that support it, with no downside on standard paths
    /// (quinn just probes and stops when packets start dropping).
    ///
    /// Default: 1452 (matches quinn). Operators with a known
    /// jumbo-frame path can raise this in `server.yaml` /
    /// `client.yaml` (`beta_mtu_upper_bound: 9000`).
    pub mtu_upper_bound: u16,
}

impl Default for PerfProfile {
    fn default() -> Self {
        Self {
            initial_mtu: 1350,
            pad_quic_datagrams_to_mtu: false,
            // PRIVACY: deliberately diverge from quinn's `true`
            // default. The spin bit is a wire-visible RTT side
            // channel and we have no operational use for it.
            allow_spin_bit: false,
            // ACK-frequency reduction — see field doc for why this
            // defaults to DISABLED. Operators on long-fat-pipe paths
            // can opt in via YAML (`beta_ack_eliciting_threshold:
            // 10`); the default-disabled is what prevents the
            // loopback / LAN / intra-DC catastrophic-throughput
            // footgun.
            ack_eliciting_threshold: 1,
            // SPEED: explicit MTU discovery upper bound — matches
            // quinn's current default but pins it so a future quinn
            // upgrade can't silently regress paths that depend on it.
            mtu_upper_bound: 1452,
        }
    }
}

/// Apply the production performance tuning with an explicit
/// `PerfProfile`. Public + idempotent.
pub fn apply_perf_tuning_with(transport: &mut quinn::TransportConfig, profile: PerfProfile) {
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
        .send_window(8 * 1024 * 1024)
        // MTU bump — see PerfProfile docs.
        .initial_mtu(profile.initial_mtu)
        // Optional UDP-layer padding — see PerfProfile docs.
        .pad_to_mtu(profile.pad_quic_datagrams_to_mtu)
        // PRIVACY: spin bit off by default. See PerfProfile docs.
        .allow_spin(profile.allow_spin_bit);

    // SPEED (opt-in): ACK-frequency reduction (RFC 9802). Only set
    // when operator explicitly raised the threshold > 1 — the
    // default of `1` ships disabled because the BBR / low-RTT
    // interaction breaks loopback throughput. See PerfProfile
    // docstring for the measurement.
    if profile.ack_eliciting_threshold > 1 {
        let mut ack = quinn::AckFrequencyConfig::default();
        ack.ack_eliciting_threshold(quinn::VarInt::from_u32(profile.ack_eliciting_threshold));
        transport.ack_frequency_config(Some(ack));
    }

    // SPEED: explicit MTU discovery configuration. Pinning the
    // upper_bound prevents quinn-default drift from silently changing
    // jumbo-frame discovery behavior across version bumps. Safe to
    // always enable — quinn searches up to the bound and stops on
    // packet loss.
    let mut mtud = quinn::MtuDiscoveryConfig::default();
    mtud.upper_bound(profile.mtu_upper_bound);
    transport.mtu_discovery_config(Some(mtud));
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

#[cfg(test)]
mod perf_profile_defaults {
    use super::PerfProfile;

    /// Privacy regression guard: if some future change flips the
    /// spin-bit default back on (matching quinn upstream's default),
    /// this fails loudly. The spin bit is a wire-visible RTT side
    /// channel — defaulting it ON would silently weaken every β
    /// connection's privacy.
    #[test]
    fn spin_bit_is_off_by_default() {
        let p = PerfProfile::default();
        assert!(
            !p.allow_spin_bit,
            "PerfProfile::default().allow_spin_bit MUST be false — \
             the spin bit (RFC 9000 §17.4) is a wire-visible RTT \
             oracle for on-path observers. quinn defaults this to true \
             for ecosystem compatibility; Proteus deliberately overrides."
        );
    }

    /// ACK-frequency reduction defaults to DISABLED (= 1).
    ///
    /// **Footgun preventer**: setting this > 1 by default
    /// catastrophically harms loopback / LAN / intra-DC throughput
    /// (measured: 107 MiB/s → 0.5 MiB/s on loopback with threshold = 10).
    /// BBR's bandwidth estimator cannot converge on very-low-RTT
    /// paths when ACKs are bunched 10× behind. Operators with
    /// measured long-fat-pipe paths opt in via YAML.
    #[test]
    fn ack_eliciting_threshold_default_is_disabled() {
        let p = PerfProfile::default();
        assert_eq!(
            p.ack_eliciting_threshold, 1,
            "PerfProfile::default().ack_eliciting_threshold MUST be 1 (disabled). \
             A higher default breaks loopback / LAN throughput (BBR can't converge \
             when ACKs are bunched on a sub-ms RTT path); operators opt into the \
             long-fat-pipe optimization via `beta_ack_eliciting_threshold` in YAML.",
        );
    }

    /// MTU discovery upper bound is pinned, not relying on quinn's
    /// default. If quinn ever changes its default (e.g. raises to
    /// support jumbo frames out of the box), our wire behavior
    /// stays predictable.
    #[test]
    fn mtu_upper_bound_is_pinned_to_ethernet_max() {
        let p = PerfProfile::default();
        assert_eq!(
            p.mtu_upper_bound, 1452,
            "default MTU upper_bound must stay at 1452 (Ethernet \
             max under IPv6+UDP overhead); raise deliberately in \
             operator YAML for jumbo-frame paths",
        );
    }

    /// Initial MTU stays conservative — covers ≥ 99 % of real-world
    /// paths without triggering ICMP-blackhole drops.
    #[test]
    fn initial_mtu_default_is_safe() {
        let p = PerfProfile::default();
        assert!(
            (1200..=1452).contains(&p.initial_mtu),
            "initial_mtu must be in [1200, 1452]; got {}",
            p.initial_mtu,
        );
    }

    /// Pad-to-MTU defaults to OFF for raw throughput. The traffic-
    /// analysis defense is a deliberate operator opt-in
    /// (`beta_pad_quic_to_mtu: true`) per README.
    #[test]
    fn pad_to_mtu_default_is_off() {
        let p = PerfProfile::default();
        assert!(!p.pad_quic_datagrams_to_mtu);
    }
}
