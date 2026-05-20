//! YAML config for `proteus-client`.
//!
//! ```yaml
//! server_endpoint: "vps.example.com:8443"
//! socks_listen: "127.0.0.1:1080"
//! user_id: "alice001"
//! keys:
//!   server_mlkem_pk: ./keys/server_lt.mlkem768.pk
//!   server_x25519_pk: ./keys/server_lt.x25519.pk
//!   server_pq_fingerprint: ./keys/server_lt.pq.fingerprint
//!   client_ed25519_sk: ./keys/client/client.ed25519.sk
//! ```

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use base64::Engine;
use proteus_transport_alpha::client;
use rand_core::OsRng;
use serde::Deserialize;
use zeroize::{Zeroize as _, Zeroizing};

#[derive(Debug, Deserialize)]
pub struct ClientConfig {
    pub server_endpoint: String,
    /// Optional ordered list of fallback α endpoints, dialed in
    /// the order given when `server_endpoint` (the primary) becomes
    /// unhealthy. Per-endpoint health tracking (sibling of
    /// `CarrierHealth`) records consecutive failure streaks; after
    /// 3 consecutive failures on an endpoint the dispatcher
    /// suppresses it for 15s → 30s → ... → 300s capped exponential
    /// back-off, with a periodic recovery probe so transient
    /// outages heal automatically.
    ///
    /// Operator-opt-in for multi-VPS HA — when unset (the default)
    /// the dispatcher behaves identically to the pre-pool single-
    /// endpoint code. When set, the LIST IS USED IN ORDER: the
    /// primary `server_endpoint` is conventionally also entry [0]
    /// of `server_endpoints` so the operator can decide whether the
    /// fallbacks include or exclude the primary.
    ///
    /// Each entry is a `host:port` string (same shape as
    /// `server_endpoint`). The pool consumes one
    /// `Arc<EndpointHealth>` per entry — cheap; no per-CONNECT
    /// allocation.
    ///
    /// **WIRED 2026-05-18** (follow-up to the foundation commit
    /// of the same day): SOCKS dispatch consults the pool via
    /// `handle_socks5_with_health_and_pool`. Operators setting
    /// this field today get real failover: on per-entry handshake
    /// failure the next entry is tried, and per-entry
    /// `EndpointHealth` state survives across CONNECTs so repeated
    /// failures back off without spending the timeout cost on
    /// every request.
    #[serde(default)]
    pub server_endpoints: Vec<String>,
    pub socks_listen: String,
    pub user_id: String,
    pub keys: KeysCfg,
    /// Outer TLS 1.3 config. When present the client wraps every
    /// outbound TCP connection in TLS 1.3 before running the Proteus
    /// handshake. MUST match the server's `tls:` block.
    #[serde(default)]
    pub tls: Option<TlsClientCfg>,
    /// Server-advertised anti-DoS proof-of-work difficulty.
    /// MUST match the server's `pow_difficulty`. Default 0 = disabled.
    #[serde(default)]
    pub pow_difficulty: Option<u8>,
    /// Optional β-profile (QUIC) endpoint on the same server. When
    /// set, the client uses the **happy-eyeballs-style** dual-stack
    /// dialer: tries β first with a short timeout, falls back to α
    /// if β times out / fails. Recommended for production
    /// deployments where the server runs both carriers.
    /// Example: `"vps.example.com:8443"` (server listens on
    /// `:8443/udp` for β).
    #[serde(default)]
    pub server_endpoint_beta: Option<String>,
    /// Optional override for the β QUIC handshake's SNI / TLS
    /// server_name. Defaults to `tls.server_name` if unset (operators
    /// usually use the same cert for both carriers).
    #[serde(default)]
    pub beta_server_name: Option<String>,
    /// Per-connection timeout (seconds) for the β-first dial attempt
    /// before falling back to α. Default 3s — short enough that an
    /// EDNS-blocked client doesn't hang noticeably, long enough that
    /// a slow QUIC handshake on a marginal path still wins.
    #[serde(default)]
    pub beta_first_timeout_secs: Option<u64>,
    /// β QUIC `initial_mtu` (bytes). Default 1350. Bump to 1452
    /// for max-throughput Ethernet-MTU paths matching Hy2 / TUIC-v5.
    #[serde(default)]
    pub beta_initial_mtu: Option<u16>,
    /// β QUIC: pad every application UDP datagram to current
    /// path-MTU. Defense-in-depth on top of cell-split AEAD padding.
    /// **OFF by default** because bandwidth amplification triggers
    /// macOS loopback pacing. Flip to `true` for production anti-
    /// censorship deployments where bandwidth >> detectability.
    #[serde(default)]
    pub beta_pad_quic_to_mtu: Option<bool>,
    /// β QUIC: spin bit (RFC 9000 §17.4). **Off by default** —
    /// quinn's upstream default is `true` (set for ecosystem
    /// compatibility); Proteus deliberately overrides because the
    /// spin bit is a wire-visible passive-RTT side channel for any
    /// on-path observer including the GFW. Operators should leave
    /// this unset; the only use case for enabling it is debugging
    /// enterprise SLA dashboards that key on spin-bit RTT.
    #[serde(default)]
    pub beta_allow_spin_bit: Option<bool>,
    /// β QUIC: ACK-frequency reduction (RFC 9802 /
    /// draft-ietf-quic-ack-frequency-04). Default 10. Tells the
    /// peer it may bundle up to N ack-eliciting packets per ACK
    /// frame. Cuts ACK overhead by ~5-10× on high-bandwidth flows.
    /// Set 1 to disable (= quinn default of ACK per 2 packets);
    /// peers without the extension silently ignore it.
    #[serde(default)]
    pub beta_ack_eliciting_threshold: Option<u32>,
    /// β QUIC: MTU discovery upper bound. quinn probes path-MTU up
    /// to this value. Default 1452. Raise to 9000 on known jumbo-
    /// frame paths for a real throughput win.
    #[serde(default)]
    pub beta_mtu_upper_bound: Option<u16>,
    /// Data-plane padding quantum (bytes). When non-zero, every
    /// outgoing DATA record's plaintext is wrapped as
    /// `[4-byte BE real_len | real_payload | zero-pad]` and rounded
    /// up to a multiple of this value before AEAD seal. On the wire
    /// the ciphertext length is always `k*quantum + 16` bytes, so a
    /// passive observer learns only "which quantum bucket", not the
    /// exact payload size. Spec §4.6 / §22.
    ///
    /// Trade-off:
    /// - 0 (default): no padding, max throughput, wire length leaks
    /// - 64: ~1% overhead at 16 KiB records, kills sub-64-byte signal
    /// - 1280: matches β-profile cell, kills sub-cell length signal
    ///   but adds up to ~7% overhead at typical request sizes
    ///
    /// Recommended for any deployment where the operator cares about
    /// traffic-analysis resistance (i.e. anti-censorship use cases).
    #[serde(default)]
    pub pad_quantum: Option<u16>,
    /// Maximum number of concurrent in-flight SOCKS5 sessions. When
    /// reached, additional SOCKS5 inbound connections receive a clean
    /// `0x05 0x01` (general failure) reply and the TCP connection is
    /// dropped. Default: 1024.
    ///
    /// Production sizing: each in-flight session holds one upstream
    /// Proteus session (16 MiB receive-buffer ceiling) plus one
    /// SOCKS5 inbound socket. 1024 sessions ≈ 16 GiB worst-case
    /// memory ceiling on the receive path. Tune for the deployment.
    /// Set to 0 to disable the cap (NOT recommended in production —
    /// any local-network attacker can OOM the client process).
    #[serde(default)]
    pub max_inflight_sessions: Option<usize>,
    /// Graceful-shutdown drain window in seconds. After receiving
    /// SIGTERM / SIGINT, the client stops accepting new SOCKS5
    /// connections and waits up to this long for in-flight sessions
    /// to flush their last records cleanly. Default: 15 s.
    #[serde(default)]
    pub drain_secs: Option<u64>,
    /// Optional path to the server-knock PSK file (32 bytes,
    /// base64-encoded; same byte-for-byte content the operator
    /// distributed from `proteus-server knock-keygen`).
    ///
    /// **Path A: REALITY-grade probe resistance.** When set,
    /// the client mints an HMAC-bound knock token (via
    /// [`proteus_handshake::knock::compute_knock`]) on every
    /// outbound handshake. The future transport-layer wiring
    /// embeds the token in the TLS ClientHello so the server's
    /// pre-auth-passthrough gate can distinguish "real Proteus
    /// client" from "GFW active prober" BEFORE TLS even
    /// terminates locally — probers without the PSK get
    /// transparently forwarded to the cover endpoint and see
    /// only the real HTTPS reverse-proxy response.
    ///
    /// Must match the server's `knock_psk_file:` exactly. A
    /// mismatch (e.g. operator rotated server-side without
    /// rolling the client) produces a clean
    /// "passthrough-to-cover-only" experience at the server —
    /// the client's connection succeeds at the TLS layer but
    /// stays in cover mode and the Proteus handshake never
    /// activates. Operators detect this via the existing
    /// `proteus-client connect-test` (will report a handshake
    /// failure).
    ///
    /// Unset (default): no knock is emitted. The protocol still
    /// works end-to-end (the legacy auth-fail-then-cover path
    /// covers passive DPI); only the probe-resistance gate is
    /// off. Operators wanting REALITY-grade probe resistance
    /// MUST set this on BOTH client AND server.
    #[serde(default)]
    pub knock_psk_file: Option<PathBuf>,
    /// **TCP keepalive interval (seconds)** for the outbound dial
    /// toward the Proteus server. `None` = 30 seconds (mirrors
    /// the server's default — symmetric treatment of both ends
    /// of the connection).
    ///
    /// Iter-14 added this knob because pre-iter-14 client→server
    /// TCP connections went on the wire with NO keepalive at
    /// all. A long-idle Proteus session crossing a CGNAT / corp
    /// firewall would silently die after the NAT idle-timer
    /// (typically 2-30 min). The user-visible symptom was
    /// "everything was working, then suddenly nothing loaded;
    /// I refreshed and it worked again" — the worst kind of
    /// production bug because it masquerades as flaky network.
    ///
    /// Operators behind aggressive NAT (some mobile carriers
    /// reap idle bindings as fast as 30 s) can drop this to 15.
    /// Operators on a clean direct path can raise it to 120 or
    /// disable by setting a very large value; the option also
    /// adds tiny periodic kernel-level wire activity, which is
    /// invisible on the wire (encrypted) but does add a few
    /// bytes per minute.
    #[serde(default)]
    pub tcp_keepalive_secs: Option<u64>,
    /// **α (TCP/TLS) dial timeout (seconds)** — wraps the WHOLE
    /// α connection-setup flow: `TcpStream::connect` + TLS 1.3
    /// handshake + Proteus auth-exchange. `None` = 10 seconds.
    ///
    /// Iter-15 added this because pre-iter-15 the α path had no
    /// timeout at all (β had `beta_first_timeout_secs` since
    /// the dual-stack work, but α was unbounded). A misbehaving
    /// server — accepts TCP, then sits silent on the TLS
    /// handshake — would wedge a SOCKS5 CONNECT indefinitely.
    /// Symptoms: browser tabs hang for 30-60s before the
    /// browser's own timeout fires; downstream apps see "the
    /// proxy is broken but isn't returning errors".
    ///
    /// 10 s is generous for a normal residential-ISP-to-VPS
    /// path (~1 RTT for SYN/SYN-ACK + 1 RTT for TLS 1.3 1-RTT +
    /// 1 RTT for Proteus inner handshake = 3 RTTs, well under
    /// 1 s even on slow paths). Operators on satellite or
    /// high-latency links can raise it; operators wanting
    /// faster failover to β can drop to 5.
    #[serde(default)]
    pub alpha_dial_timeout_secs: Option<u64>,
    /// **SOCKS5 greeting timeout (seconds)** — bounds how long
    /// the client waits for the downstream app to send the
    /// SOCKS5 greeting + CONNECT request before tearing down the
    /// local TCP. `None` = 10 seconds.
    ///
    /// Pre-iter-15 the greeting/request reads were unbounded.
    /// A misbehaving local app (or `nc localhost 1080` left
    /// orphaned by a crashed parent) could open a SOCKS5 TCP
    /// connection, never write, and sit holding a
    /// `max_inflight_sessions` semaphore slot forever — slow-
    /// loris DoS against the local proxy port. With
    /// `max_inflight_sessions = 64` (typical default), 64 such
    /// orphans were enough to make the proxy refuse all new
    /// CONNECTs until the operator restarted the binary.
    ///
    /// 10 s is generous — real apps (browser, curl) send the
    /// SOCKS5 greeting within microseconds of the TCP connect.
    /// Anything that takes longer is misbehaving.
    #[serde(default)]
    pub socks_request_timeout_secs: Option<u64>,
    /// **Bootstrap DNS policy** — how to resolve the hostname half of
    /// `server_endpoint` / `server_endpoint_beta`. Defaults to
    /// `system`, which goes through the OS resolver (which in 2026
    /// may itself transit a DoH/DoT server that the GFW now
    /// identifies — see threat-intel main line 6).
    ///
    /// Production-anti-censorship recommended: `direct_ip: <literal
    /// IPv4 or IPv6>`. The TLS SNI continues to use the hostname from
    /// `tls.server_name` / `beta_server_name`, so cert verification
    /// works normally; only the network-layer resolution is skipped.
    /// This eliminates the entire bootstrap-DNS attack surface for
    /// the operator who controls a clean VPS with a known IP.
    ///
    /// Equivalent: write the IP literal directly into `server_endpoint`
    /// (e.g. `"198.51.100.42:8443"`). The `direct_ip` knob exists for
    /// operators who prefer to keep the hostname visible in the
    /// `server_endpoint` field (for SNI-matching readability) while
    /// still pinning resolution.
    ///
    /// YAML examples:
    /// ```yaml
    /// bootstrap_dns: system            # default (vulnerable to DoH ID + DNS hijack)
    /// bootstrap_dns:
    ///   direct_ip: 198.51.100.42       # IPv4 pin
    /// bootstrap_dns:
    ///   direct_ip: "2001:db8::1"       # IPv6 pin
    /// ```
    #[serde(default)]
    pub bootstrap_dns: Option<BootstrapDnsCfg>,
    /// Opt-in loopback admin endpoint. When set (typical:
    /// `admin_listen: "127.0.0.1:9091"`), the client exposes:
    ///
    /// - `GET /healthz`     — 200 once SOCKS5 has bound; 503 before.
    /// - `GET /status`      — text snapshot (CarrierHealth +
    ///   EndpointPool state).
    /// - `GET /status.json` — JSON snapshot, line-delimited.
    ///
    /// **No authentication.** Always bind loopback (`127.0.0.1:N` /
    /// `[::1]:N`); on a personal-VPN client deployment, anyone who
    /// can reach `127.0.0.1` is already running as the same user.
    /// Binding non-loopback emits a startup `warn!` but does not
    /// refuse — operators occasionally want to expose the surface
    /// for an over-SSH `curl` from another host on a trusted LAN.
    ///
    /// Default: `None` — admin endpoint disabled, no extra port
    /// bound. The `proteus-client status` subcommand only works
    /// when this is set.
    #[serde(default)]
    pub admin_listen: Option<String>,

    /// Staleness threshold (seconds) for the admin `/healthz`
    /// endpoint. When > 0, /healthz returns 503 if the upstream
    /// Proteus dial has been wedged for longer than this window
    /// (no successful dial in the last N seconds, AND at least
    /// one dial has been attempted).
    ///
    /// Downstream apps (browser, IDE, mobile app) probe
    /// /healthz to decide "send traffic through SOCKS or fall
    /// back to direct?". Without this knob, /healthz returns
    /// 200 the moment SOCKS5 binds and never re-evaluates — so
    /// downstream apps stall on a broken proxy.
    ///
    /// 0 (default) = staleness rule disabled; /healthz returns
    /// 200 as soon as SOCKS5 binds (back-compat).
    /// Recommended for production: 120 (2 min). Catches a
    /// wedged upstream within ~2 min so downstream apps fall
    /// back fast.
    #[serde(default)]
    pub healthz_staleness_secs: Option<u64>,
}

/// Bootstrap DNS resolution policy. See [`ClientConfig::bootstrap_dns`].
///
/// Untagged so YAML can use either the bare token `system` (string
/// shorthand) or a `direct_ip: <addr>` mapping. The string-vs-mapping
/// disambiguation is done by serde based on YAML node shape.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged, rename_all = "snake_case")]
pub enum BootstrapDnsCfg {
    /// String variant: `bootstrap_dns: system` or
    /// `bootstrap_dns: "system"`. Must be exactly the literal "system".
    System(SystemKind),
    /// Mapping variant: `bootstrap_dns: { direct_ip: 198.51.100.42 }`.
    DirectIp {
        /// The literal IP to use when the hostname in
        /// `server_endpoint` / `server_endpoint_beta` would otherwise
        /// require DNS resolution. SNI / cert verification continue
        /// to use the hostname; only the L3 lookup is bypassed.
        direct_ip: IpAddr,
    },
}

/// Internal enum for the string-only "system" variant — keeps the
/// untagged-deserialize behavior unambiguous.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SystemKind {
    /// `bootstrap_dns: system`.
    System,
}

impl BootstrapDnsCfg {
    /// True iff this policy forces a literal IP and skips DNS.
    #[must_use]
    pub fn is_direct_ip(&self) -> bool {
        matches!(self, BootstrapDnsCfg::DirectIp { .. })
    }

    /// Extract the pinned IP, if any.
    #[must_use]
    pub fn pinned_ip(&self) -> Option<IpAddr> {
        match self {
            BootstrapDnsCfg::DirectIp { direct_ip } => Some(*direct_ip),
            BootstrapDnsCfg::System(_) => None,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct TlsClientCfg {
    /// DNS name to verify against the server certificate's SAN.
    pub server_name: String,
    /// Optional path to a PEM-encoded CA (or self-signed cert) to add to
    /// the trust store. When absent the client uses webpki-roots.
    #[serde(default)]
    pub trusted_ca: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
pub struct KeysCfg {
    pub server_mlkem_pk: PathBuf,
    pub server_x25519_pk: PathBuf,
    pub server_pq_fingerprint: PathBuf,
    pub client_ed25519_sk: PathBuf,
}

impl ClientConfig {
    pub async fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = tokio::fs::read_to_string(path)
            .await
            .map_err(ConfigError::Io)?;
        let cfg: Self = serde_yaml::from_str(&text).map_err(ConfigError::Yaml)?;
        Ok(cfg)
    }

    /// Legacy per-call path. Used by `connect-test` (one-shot) and
    /// as the back-compat fallback when ctx didn't pre-build the
    /// cached source. Production SOCKS5 traffic should go through
    /// [`Self::build_handshake_config_source`] once at startup and
    /// call [`HandshakeConfigSource::alpha`] / [`::beta`] per
    /// request — see that struct's docs for the rationale.
    pub fn build_handshake_config(&self) -> Result<client::ClientConfig, ConfigError> {
        let source = self.build_handshake_config_source()?;
        Ok(source.alpha())
    }

    /// Build the cached handshake-config source. Call ONCE at
    /// startup; wrap the result in `Arc<HandshakeConfigSource>` and
    /// stash on `ClientCtx`.
    pub fn build_handshake_config_source(&self) -> Result<HandshakeConfigSource, ConfigError> {
        let server_mlkem_pk_bytes = decode_b64_or_raw(&std::fs::read(&self.keys.server_mlkem_pk)?);
        let server_x25519_pk_bytes =
            decode_b64_or_raw(&std::fs::read(&self.keys.server_x25519_pk)?);
        if server_x25519_pk_bytes.len() != 32 {
            return Err(ConfigError::BadKey("server_x25519_pk must be 32 bytes"));
        }
        let mut server_x25519_pub = [0u8; 32];
        server_x25519_pub.copy_from_slice(&server_x25519_pk_bytes);

        let fp_bytes = decode_b64_or_raw(&std::fs::read(&self.keys.server_pq_fingerprint)?);
        if fp_bytes.len() != 32 {
            return Err(ConfigError::BadKey(
                "server_pq_fingerprint must be 32 bytes",
            ));
        }
        let mut server_pq_fingerprint = [0u8; 32];
        server_pq_fingerprint.copy_from_slice(&fp_bytes);

        // Iter-168: wrap the Ed25519 SK file-bytes + decoded
        // intermediates in `Zeroizing` so the heap/stack copies of
        // the long-term identity seed are scrubbed on drop. The
        // SigningKey itself is ZeroizeOnDrop (closes the actual
        // signing-key residue), but the file-bytes Vec, the
        // post-b64 decoded Vec, and the `[u8; 32]` array passed
        // to `from_bytes()` are NOT. Pre-iter-168 a coredump
        // taken during startup could recover the seed bytes
        // verbatim from the heap/stack.
        let sk_raw = Zeroizing::new(std::fs::read(&self.keys.client_ed25519_sk)?);
        let sk_bytes = Zeroizing::new(decode_b64_or_raw(&sk_raw));
        if sk_bytes.len() != 32 {
            return Err(ConfigError::BadKey(
                "client_ed25519_sk must be 32 bytes (raw seed)",
            ));
        }
        let mut sk_arr: [u8; 32] = sk_bytes.as_slice().try_into().unwrap();
        let client_id_sk = ed25519_dalek::SigningKey::from_bytes(&sk_arr);
        // SigningKey::from_bytes() copies the seed into the
        // ZeroizeOnDrop SigningKey; scrub the stack copy now.
        sk_arr.zeroize();

        let user_id = encode_user_id(&self.user_id);

        // RNG seed not needed here; the OS RNG handles per-handshake nonces.
        let _ = OsRng;

        Ok(HandshakeConfigSource {
            server_mlkem_pk_bytes,
            server_x25519_pub,
            server_pq_fingerprint,
            client_id_sk,
            user_id,
            pow_difficulty: self.pow_difficulty.unwrap_or(0),
        })
    }
}

/// Precomputed handshake-config source. Built ONCE via
/// [`ClientConfig::build_handshake_config_source`] at startup:
/// reads all 4 key files from disk, decodes base64, validates
/// lengths, derives the Ed25519 signing key. The per-CONNECT
/// path then calls [`Self::alpha`] / [`Self::beta`] which are
/// pure CPU clones — zero disk, zero parsing, zero key
/// derivation.
///
/// ## Why this matters
///
/// Pre-iter-13 every SOCKS5 CONNECT called
/// `build_handshake_config`, which:
///   - opened 4 files (`server_mlkem_pk`, `server_x25519_pk`,
///     `server_pq_fingerprint`, `client_ed25519_sk`)
///   - read them into memory
///   - stripped whitespace + base64-decoded each
///   - validated each length
///   - constructed an `ed25519_dalek::SigningKey` from the raw
///     seed bytes (which runs SHA-512 internally to derive the
///     scalar)
///
/// On a browser navigating a page that opens 50 short-lived
/// HTTP/2 connections, that was 200 disk reads + 50 ed25519
/// derivations per page load before any byte hit the wire.
/// With the cached source it's 0 disk + 0 derivations after
/// the one-time startup cost.
///
/// The clone in [`Self::alpha`] / [`Self::beta`] copies one
/// `Vec<u8>` (the ~1184-byte ML-KEM-768 EK), the `SigningKey` (32
/// bytes), and three small fixed-size arrays. That's ~1.3 KiB of
/// bytes vs the syscall + parsing + key-schedule round-trip the
/// pre-iter-13 path paid.
#[derive(Clone)]
pub struct HandshakeConfigSource {
    server_mlkem_pk_bytes: Vec<u8>,
    server_x25519_pub: [u8; 32],
    server_pq_fingerprint: [u8; 32],
    client_id_sk: ed25519_dalek::SigningKey,
    user_id: [u8; 8],
    pow_difficulty: u8,
}

impl HandshakeConfigSource {
    /// Materialize an α-profile `ClientConfig` from the cached
    /// fields. Pure CPU clone — no disk, no parsing.
    #[must_use]
    pub fn alpha(&self) -> client::ClientConfig {
        client::ClientConfig {
            server_mlkem_pk_bytes: self.server_mlkem_pk_bytes.clone(),
            server_x25519_pub: self.server_x25519_pub,
            server_pq_fingerprint: self.server_pq_fingerprint,
            client_id_sk: self.client_id_sk.clone(),
            user_id: self.user_id,
            pow_difficulty: self.pow_difficulty,
            profile_hint: proteus_transport_alpha::ProfileHint::Alpha,
        }
    }

    /// Materialize a β-profile `ClientConfig` from the cached
    /// fields. Identical to `alpha()` except `profile_hint =
    /// Beta`. The β connector consumes the config by value
    /// (it embeds the cfg into a quinn endpoint state), so
    /// returning an owned clone is the natural API shape.
    #[must_use]
    pub fn beta(&self) -> client::ClientConfig {
        client::ClientConfig {
            server_mlkem_pk_bytes: self.server_mlkem_pk_bytes.clone(),
            server_x25519_pub: self.server_x25519_pub,
            server_pq_fingerprint: self.server_pq_fingerprint,
            client_id_sk: self.client_id_sk.clone(),
            user_id: self.user_id,
            pow_difficulty: self.pow_difficulty,
            profile_hint: proteus_transport_alpha::ProfileHint::Beta,
        }
    }
}

fn encode_user_id(user_id: &str) -> [u8; 8] {
    let mut out = [0u8; 8];
    let bytes = user_id.as_bytes();
    let copy_len = bytes.len().min(8);
    out[..copy_len].copy_from_slice(&bytes[..copy_len]);
    out
}

fn decode_b64_or_raw(input: &[u8]) -> Vec<u8> {
    // Iter-168: scrub the intermediate `trimmed` Vec on drop.
    // When this helper sees the SK b64 file (the client_ed25519_sk
    // load path), `trimmed` is a byte-for-byte copy of the
    // base64-encoded SK seed — directly substitutable for the
    // SK via b64-decode. The public-key load paths also call
    // here; conservatively scrubbing both costs ~one memset
    // per call and avoids baking "is-this-SK" into the helper
    // signature.
    let mut trimmed: Vec<u8> = input
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    let result = if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&trimmed) {
        decoded
    } else {
        input.to_vec()
    };
    trimmed.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn healthz_staleness_secs_parses_when_supplied() {
        let yaml = "\
socks_listen: \"127.0.0.1:1080\"\n\
server_endpoint: \"vps.example.com:8443\"\n\
server_dns_name: \"vps.example.com\"\n\
keys:\n  \
  server_mlkem_pk: /tmp/x\n  \
  server_x25519_pk: /tmp/x\n  \
  server_pq_fingerprint: /tmp/x\n  \
  client_ed25519_sk: /tmp/x\n\
user_id: \"alice001\"\n\
healthz_staleness_secs: 120\n\
";
        let cfg: ClientConfig = serde_yaml::from_str(yaml).expect("parse");
        assert_eq!(cfg.healthz_staleness_secs, Some(120));
    }

    #[test]
    fn healthz_staleness_secs_defaults_to_none_when_omitted() {
        let yaml = "\
socks_listen: \"127.0.0.1:1080\"\n\
server_endpoint: \"vps.example.com:8443\"\n\
server_dns_name: \"vps.example.com\"\n\
keys:\n  \
  server_mlkem_pk: /tmp/x\n  \
  server_x25519_pk: /tmp/x\n  \
  server_pq_fingerprint: /tmp/x\n  \
  client_ed25519_sk: /tmp/x\n\
user_id: \"alice001\"\n\
";
        let cfg: ClientConfig = serde_yaml::from_str(yaml).expect("parse");
        assert_eq!(cfg.healthz_staleness_secs, None);
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ConfigError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("yaml: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("bad key: {0}")]
    BadKey(&'static str),
}
