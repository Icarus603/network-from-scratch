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
//! Client and server can establish a QUIC connection with
//! `proteus-β-v1` ALPN and multiplex independently authenticated
//! bidirectional streams. Every stream runs the existing Proteus
//! handshake and binds it to a stream-specific TLS exporter.
//! What's deliberately deferred:
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
//! - Per-connection idle timeout plus bounded multi-stream sessions.
//! - All α-profile crypto: hybrid X25519+ML-KEM-768, full key
//!   schedule, AEAD record stream, anti-replay, PoW, ratchet —
//!   inherited via `proteus_transport_alpha::session::AlphaSession`.

#![forbid(unsafe_code)]

pub mod brutal;
pub mod client;
pub mod datagram;
pub mod error;
pub mod server;

pub use brutal::{Brutal, BrutalConfig, DEFAULT_TARGET_BPS};

/// Versioned TLS-exporter context for one QUIC stream.
///
/// The raw QUIC stream ID includes initiator, direction, and index.
/// Encoding it in big-endian form avoids textual ambiguity and
/// gives both peers exactly the same context bytes.
pub fn stream_exporter_context(stream_id: quinn::StreamId) -> [u8; 30] {
    const PREFIX: &[u8; 22] = b"proteus-beta-stream-v1";
    let mut context = [0u8; 30];
    context[..PREFIX.len()].copy_from_slice(PREFIX);
    let raw = quinn::VarInt::from(stream_id).into_inner();
    context[PREFIX.len()..].copy_from_slice(&raw.to_be_bytes());
    context
}

#[cfg(test)]
mod stream_binding_tests {
    #[test]
    fn exporter_context_is_stream_specific_and_versioned() {
        let first = quinn::StreamId::new(quinn::Side::Client, quinn::Dir::Bi, 0);
        let second = quinn::StreamId::new(quinn::Side::Client, quinn::Dir::Bi, 1);
        let first_ctx = super::stream_exporter_context(first);
        let second_ctx = super::stream_exporter_context(second);

        assert_ne!(first_ctx, second_ctx);
        assert_eq!(&first_ctx[..22], b"proteus-beta-stream-v1");
        assert_eq!(&first_ctx[22..], &0u64.to_be_bytes());
        // Raw QUIC stream ID for client-initiated bidi stream #1 is 4.
        assert_eq!(&second_ctx[22..], &4u64.to_be_bytes());
    }
}

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

    /// Smallest UDP payload size that black-hole recovery may fall
    /// back to. Keep 1200 on unknown Internet paths. Operators who
    /// control the complete path (for example a 1500-byte Ethernet
    /// VPS benchmark) can pin this to `initial_mtu` so unrelated
    /// random loss is not misclassified as an MTU black hole.
    pub minimum_mtu: u16,
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
    /// QUIC packet-number reordering tolerated before declaring loss.
    ///
    /// RFC 9002's default is 3. Raising this can prevent spurious
    /// retransmission on paths that reorder packets, at the cost of
    /// slower recovery from real loss. Production therefore stays at
    /// 3; measured paths may opt into a higher value.
    pub packet_threshold: u32,
    /// Time-based QUIC loss threshold as a multiple of the
    /// conservative RTT estimate. RFC 9002 recommends 9/8 (1.125).
    ///
    /// Raising this can tolerate paths where reordered packets arrive
    /// substantially later than their successors, but delays recovery
    /// from genuine loss. Production therefore remains at 1.125.
    pub time_threshold: f32,
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
    /// Per-stream receive window override in bytes. `None` keeps the
    /// production default (64 MiB). Operators and the benchmark
    /// harness may lower it to cap per-carrier memory or raise it for
    /// a measured path whose bandwidth-delay product exceeds the
    /// default. The production YAML layer validates the operator
    /// shorthand in MiB before converting it to this byte value.
    ///
    /// Default: `None` (= 64 MiB).
    pub stream_receive_window_override: Option<u32>,
    /// Per-connection receive window override in bytes. Mirrors the
    /// per-stream override above. Production defaults to 256 MiB and
    /// validation requires this value to be at least the stream
    /// receive window.
    pub connection_receive_window_override: Option<u32>,
    /// Local send-buffer window override in bytes. `None` keeps the
    /// 64 MiB production default. Quinn accepts a `u64` here, but the
    /// production configuration deliberately caps the MiB shorthand
    /// well below pathological multi-GiB allocations.
    pub send_window_override: Option<u64>,
    /// Congestion controller selection for β QUIC.
    ///
    /// - [`CongestionKind::Bbr`] (default): quinn stock BBR — fair,
    ///   loss-tolerant enough for mild loss, collapses at 15–30 %
    ///   synthetic / GFW-throttle regimes.
    /// - [`CongestionKind::Brutal`]: Hy2-style rate-targeted CC.
    ///   Loss does not shrink the window. Requires
    ///   [`Self::brutal_target_bps`] (or the Mbps YAML shorthand).
    ///
    /// Default stays BBR so operators who never touch the knob get
    /// the safe TCP-friendly behaviour. Flip to Brutal only when you
    /// have measured the end-to-end uplink you paid for.
    pub congestion: CongestionKind,
    /// Target send rate for [`CongestionKind::Brutal`], in **bits per
    /// second**. Ignored when `congestion == Bbr`. Default
    /// [`DEFAULT_TARGET_BPS`] (100 Mbit/s) so a first flip-on without
    /// tuning still produces useful throughput on mid-tier VPS links.
    pub brutal_target_bps: u64,
}

/// Which quinn congestion controller `apply_perf_tuning_with` installs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CongestionKind {
    /// quinn's stock BBR (default).
    #[default]
    Bbr,
    /// Proteus Brutal — loss-immune, operator-rate-targeted.
    Brutal,
}

impl Default for PerfProfile {
    fn default() -> Self {
        Self {
            initial_mtu: 1350,
            minimum_mtu: 1200,
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
            packet_threshold: 3,
            time_threshold: 1.125,
            // SPEED: explicit MTU discovery upper bound — matches
            // quinn's current default but pins it so a future quinn
            // upgrade can't silently regress paths that depend on it.
            mtu_upper_bound: 1452,
            // None means "keep the 64/256/64 MiB production defaults
            // wired into apply_perf_tuning_with".
            stream_receive_window_override: None,
            connection_receive_window_override: None,
            send_window_override: None,
            congestion: CongestionKind::Bbr,
            brutal_target_bps: DEFAULT_TARGET_BPS,
        }
    }
}

/// Iter-61: target SO_RCVBUF / SO_SNDBUF for the QUIC UDP socket.
/// 7 MiB matches Hy2 / TUIC5 defaults — enough to sustain
/// 1 Gbit/s at ~500 ms RTT without OS-level UDP buffer drops.
///
/// Linux defaults: `net.core.rmem_default` and `wmem_default` are
/// typically 212 992 bytes (~208 KiB). At line-rate the kernel
/// drops UDP datagrams faster than quinn can drain — manifests as
/// throughput cliff + retransmits + BBR bw estimate collapse.
///
/// macOS defaults: `kern.ipc.maxsockbuf` caps to ~8 MiB by
/// default; our 7 MiB target fits under it.
///
/// The set is BEST-EFFORT: SO_RCVBUF/SO_SNDBUF requests above the
/// system maximum are silently clamped by the kernel (not an
/// error). The helper returns the actual achieved values so the
/// caller can warn-log a too-low result.
pub const DEFAULT_UDP_SOCKET_BUFFER_BYTES: usize = 7 * 1024 * 1024;

/// Iter-61: outcome of [`apply_udp_socket_buffers`]. Per-direction
/// pair so the caller can log "asked for 7 MiB, kernel gave us
/// X MiB" diagnostics.
#[derive(Debug, Clone, Copy)]
pub struct UdpBufferOutcome {
    /// Bytes requested via SO_RCVBUF (`target` arg).
    pub requested: usize,
    /// Bytes the kernel actually allocated for the receive side.
    /// Linux returns 2× the set value (kernel doubles for bookkeeping).
    pub achieved_recv: usize,
    /// Bytes the kernel actually allocated for the send side.
    pub achieved_send: usize,
    /// True iff both directions met or exceeded the requested
    /// target. Operators can warn-log when false to surface
    /// "kernel max is too low" before throughput degrades.
    pub met_target: bool,
}

/// Iter-61: set SO_RCVBUF + SO_SNDBUF on a pre-bound UDP socket
/// to `target` bytes (best-effort; kernel may clamp). Returns the
/// achieved sizes so the caller can warn-log clamping.
///
/// This MUST be called before the socket is handed to
/// `quinn::Endpoint::new` — quinn doesn't expose the underlying
/// fd for runtime tuning. The convention in both server.rs
/// (make_endpoint) and client.rs (connect) is:
///   1. std::net::UdpSocket::bind(...)
///   2. apply_udp_socket_buffers(&sock, DEFAULT_UDP_SOCKET_BUFFER_BYTES)
///   3. quinn::Endpoint::new(cfg, server_cfg, sock, runtime)
pub fn apply_udp_socket_buffers(
    sock: &std::net::UdpSocket,
    target: usize,
) -> std::io::Result<UdpBufferOutcome> {
    // Convert to socket2's Socket view via reference — no fd dup,
    // no ownership transfer. Drops at end of scope without
    // closing the underlying fd.
    let s2 = socket2::SockRef::from(sock);
    // Best-effort sets. Errors here mean the OS rejected the
    // request outright (very rare on Linux/macOS for sub-system-
    // max values).
    s2.set_recv_buffer_size(target)?;
    s2.set_send_buffer_size(target)?;
    let achieved_recv = s2.recv_buffer_size().unwrap_or(0);
    let achieved_send = s2.send_buffer_size().unwrap_or(0);
    // Linux kernel returns 2× the set value from getsockopt
    // (kernel-side bookkeeping). Compare against `target` (not
    // 2× target) — meeting the user-visible target counts as a
    // win even if Linux halves the reported number.
    let met_target = achieved_recv >= target && achieved_send >= target;
    Ok(UdpBufferOutcome {
        requested: target,
        achieved_recv,
        achieved_send,
        met_target,
    })
}

/// Apply the production performance tuning with an explicit
/// `PerfProfile`. Public + idempotent.
pub fn apply_perf_tuning_with(transport: &mut quinn::TransportConfig, profile: PerfProfile) {
    use std::sync::Arc;

    // Congestion controller — BBR default; Brutal on operator opt-in.
    match profile.congestion {
        CongestionKind::Bbr => {
            transport
                .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
        }
        CongestionKind::Brutal => {
            let cfg = BrutalConfig {
                target_bps: profile.brutal_target_bps.max(1_000_000), // ≥ 1 Mbit/s
            };
            transport.congestion_controller_factory(Arc::new(cfg));
        }
    }

    transport
        // Enable QUIC DATAGRAM frames (RFC 9221). Receive-side
        // buffer cap: 8 MiB of buffered application-unread
        // datagrams. Sent datagrams beyond send-buffer back-pressure
        // via try_send/poll_ready semantics.
        .datagram_receive_buffer_size(Some(8 * 1024 * 1024))
        .datagram_send_buffer_size(8 * 1024 * 1024)
        // Per-stream receive window — bytes the SENDER may have in
        // flight on ONE stream before the receiver acks. 64 MiB
        // sustains 1 Gbit/s at ~500 ms RTT. Bench can override via
        // `PerfProfile.stream_receive_window_override`.
        .stream_receive_window(quinn::VarInt::from_u32(
            profile
                .stream_receive_window_override
                .unwrap_or(64 * 1024 * 1024),
        ))
        // Per-connection receive window — sum across all streams.
        // 4× the per-stream limit so a future multi-stream config
        // (M3+) doesn't starve. Bench can override via
        // `PerfProfile.connection_receive_window_override`.
        .receive_window(quinn::VarInt::from_u32(
            profile
                .connection_receive_window_override
                .unwrap_or(256 * 1024 * 1024),
        ))
        // Per-stream send window — bytes the LOCAL sender may keep
        // buffered before back-pressuring writes. This must cover
        // the path BDP, not merely a typical Linux socket buffer:
        // 8 MiB capped a 100 ms path around 70 MiB/s and left the
        // production SOCKS relay materially behind Hysteria2 even
        // with a 1 Gbit/s Brutal target. Match the 64 MiB receive
        // window so a single long-fat-pipe stream can actually fill
        // the congestion controller's flight budget. Quinn allocates
        // this lazily as the application writes; idle sessions do not
        // preallocate 64 MiB.
        .send_window(profile.send_window_override.unwrap_or(64 * 1024 * 1024))
        // MTU bump — see PerfProfile docs.
        .initial_mtu(profile.initial_mtu)
        .min_mtu(profile.minimum_mtu)
        // Optional UDP-layer padding — see PerfProfile docs.
        .pad_to_mtu(profile.pad_quic_datagrams_to_mtu)
        // PRIVACY: spin bit off by default. See PerfProfile docs.
        .allow_spin(profile.allow_spin_bit);

    transport.packet_threshold(profile.packet_threshold.max(3));
    transport.time_threshold(profile.time_threshold.max(1.125));

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

    #[test]
    fn packet_threshold_defaults_to_rfc_recovery_value() {
        assert_eq!(PerfProfile::default().packet_threshold, 3);
        assert_eq!(PerfProfile::default().time_threshold, 1.125);
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

    #[test]
    fn minimum_mtu_default_preserves_unknown_path_safety() {
        let p = PerfProfile::default();
        assert_eq!(p.minimum_mtu, 1200);
        assert!(p.minimum_mtu <= p.initial_mtu);
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

#[cfg(test)]
mod udp_socket_buffer_tests {
    use super::*;

    /// Iter-61: requesting a sensible buffer size against a fresh
    /// loopback UDP socket should succeed AND report achieved >=
    /// requested (or the kernel-clamped value, whichever is
    /// smaller). On all mainstream kernels at the 256 KiB target
    /// we use here, the request is well below the configured
    /// system maximum, so met_target = true.
    #[test]
    fn apply_udp_socket_buffers_sets_and_reports_achieved() {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind loopback");
        // Use a modest target (256 KiB) so the test passes on
        // stock Linux + macOS without sysctl tweaks. The
        // DEFAULT_UDP_SOCKET_BUFFER_BYTES production target (7 MiB)
        // requires raised rmem_max on some systems and would
        // make this test flaky in restricted-CI environments.
        let target = 256 * 1024;
        let outcome = apply_udp_socket_buffers(&sock, target).expect("set succeeded");
        assert_eq!(outcome.requested, target);
        // Linux returns 2× the set value; macOS returns the value
        // unchanged. Either way achieved should be >= target.
        assert!(
            outcome.achieved_recv >= target,
            "achieved_recv ({} bytes) should be >= target ({target} bytes); \
             kernel may have clamped",
            outcome.achieved_recv,
        );
        assert!(
            outcome.achieved_send >= target,
            "achieved_send ({} bytes) should be >= target ({target} bytes)",
            outcome.achieved_send,
        );
        assert!(
            outcome.met_target,
            "256 KiB target should be met on every reasonable system"
        );
    }

    /// Buffer values much larger than the kernel allows are
    /// silently clamped (this is the documented best-effort
    /// behavior). The outcome reports met_target=false so the
    /// caller can warn-log. We pick an absurdly-large value
    /// (1 GiB) that no default kernel allows.
    #[test]
    fn apply_udp_socket_buffers_reports_kernel_clamp_via_met_target_false() {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind loopback");
        let absurd = 1024 * 1024 * 1024;
        let outcome = match apply_udp_socket_buffers(&sock, absurd) {
            Ok(o) => o,
            Err(_) => {
                // On some kernels setsockopt itself errors on
                // out-of-range. Either outcome is correct
                // (clamp-or-error); the test's intent is "the
                // helper does NOT panic AND the operator gets
                // some signal".
                return;
            }
        };
        assert_eq!(outcome.requested, absurd);
        // Kernel clamps to maxsockbuf / net.core.rmem_max;
        // achieved will be << absurd. met_target must reflect that.
        assert!(
            !outcome.met_target,
            "1 GiB request must NOT report met_target=true (kernel clamps); \
             achieved_recv={}, achieved_send={}",
            outcome.achieved_recv, outcome.achieved_send,
        );
    }

    /// Default target is 7 MiB — matches Hy2 / TUIC5.
    #[test]
    fn default_udp_buffer_target_matches_hy2_tuic5() {
        assert_eq!(DEFAULT_UDP_SOCKET_BUFFER_BYTES, 7 * 1024 * 1024);
    }
}
