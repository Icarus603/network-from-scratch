//! Production YAML config for the Proteus α-profile server.
//!
//! ```yaml
//! listen_alpha: "0.0.0.0:8443"
//! keys:
//!   mlkem_pk: ./keys/server_lt.mlkem768.pk
//!   mlkem_sk: ./keys/server_lt.mlkem768.sk
//!   x25519_pk: ./keys/server_lt.x25519.pk
//!   x25519_sk: ./keys/server_lt.x25519.sk
//! client_allowlist:
//!   - user_id: "alice001"
//!     ed25519_pk: ./keys/clients/alice.ed25519.pk
//! ```

use std::path::{Path, PathBuf};

use base64::Engine;
use ml_kem::{kem::DecapsulationKey, EncodedSizeUser, MlKem768Params};
use proteus_crypto::key_schedule;
use proteus_transport_alpha::server::ServerKeys;
use serde::Deserialize;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub listen_alpha: String,
    /// Optional β-profile (QUIC over UDP) listen address. When set,
    /// the binary additionally binds a quinn endpoint and accepts
    /// β-profile sessions in parallel with α. The two carriers share
    /// the same ServerCtx (single allowlist, single rate limiter,
    /// single abuse detector, single access log, single metrics).
    /// Example: `"0.0.0.0:8444"`. Unset = α only.
    #[serde(default)]
    pub listen_beta: Option<String>,
    /// Path to the TLS cert chain to present on β QUIC handshakes.
    /// Required when `listen_beta` is set; defaults to `tls.cert_chain`
    /// if both are configured and this is unset (operators typically
    /// use the same Let's Encrypt cert for both carriers).
    #[serde(default)]
    pub beta_cert_chain: Option<PathBuf>,
    /// Path to the TLS private key. Same fallback behavior as
    /// `beta_cert_chain` — defaults to `tls.private_key` if unset.
    #[serde(default)]
    pub beta_private_key: Option<PathBuf>,
    /// β QUIC `initial_mtu` (bytes). Default 1350 (`PerfProfile::default()`).
    /// Bump to 1452 for max-throughput Ethernet-MTU paths matching
    /// Hy2 / TUIC-v5; lower for VPN/mobile paths with smaller MTUs.
    /// Ignored when `listen_beta` is unset.
    #[serde(default)]
    pub beta_initial_mtu: Option<u16>,
    /// β QUIC: pad every application UDP datagram to current
    /// path-MTU. Defense-in-depth on top of the cell-split AEAD
    /// padding (spec §4.6). **OFF by default** because bandwidth
    /// amplification can ratelimit on macOS loopback (lo0 pacing)
    /// and modestly raises small-write cost. Flip to `true` for
    /// production anti-censorship deployments where bandwidth >>
    /// detectability.
    #[serde(default)]
    pub beta_pad_quic_to_mtu: Option<bool>,
    /// β QUIC: **spin bit** (RFC 9000 §17.4). When `false` (default),
    /// the server emits a random value in the spin-bit position on
    /// every 1-RTT packet — defeats passive on-path RTT inference.
    /// When `true`, quinn's spin-bit logic is active and the bit
    /// toggles in lock-step with RTT (a wire-visible side channel
    /// for any on-path observer including the GFW). Operators
    /// should leave this off; the only reason to set it true is to
    /// debug enterprise SLA dashboards that key on spin-bit RTT.
    #[serde(default)]
    pub beta_allow_spin_bit: Option<bool>,
    /// β QUIC: ACK-frequency reduction (RFC 9802 /
    /// draft-ietf-quic-ack-frequency-04). Asks the peer to bundle up
    /// to N ack-eliciting packets per ACK instead of every other one.
    /// Default 10 — same value Hysteria2 and other quinn-based
    /// stacks tune for bulk throughput. Set 1 to disable (= quinn
    /// default of ACK per 2 packets). Set higher for known long-
    /// fat-pipe paths where you've measured the ACK overhead.
    /// Peers without the extension silently ignore it.
    #[serde(default)]
    pub beta_ack_eliciting_threshold: Option<u32>,
    /// β QUIC: MTU discovery upper bound. quinn searches up to this
    /// value during path-MTU probes. Default 1452 (Ethernet under
    /// IPv6+UDP). Raise to 9000 on known jumbo-frame paths
    /// (intra-DC / IPv6 tunnels) for a real throughput win.
    /// quinn just probes higher and stops when packets drop, so a
    /// too-high value is harmless on non-jumbo paths.
    #[serde(default)]
    pub beta_mtu_upper_bound: Option<u16>,
    pub keys: KeysCfg,
    #[serde(default)]
    pub client_allowlist: Vec<ClientCfg>,
    /// Cover URL to forward to on auth failure (spec §7.5).
    /// e.g. `"www.cloudflare.com:443"`.
    ///
    /// **Single-endpoint mode (default).** Every auth-failed
    /// connection splices to this one URL. Mutually exclusive with
    /// `cover_endpoints`; if both are set, `cover_endpoints` wins.
    #[serde(default)]
    pub cover_endpoint: Option<String>,
    /// Cover endpoint POOL — N URLs the server rotates across with
    /// per-source-IP /24 (v4) or /48 (v6) affinity. Defeats
    /// time-series active probing (2026 threat-intel main line 4):
    /// a single observer probing the same Proteus IP across many
    /// rounds receives the SAME cover URL every round (looks
    /// consistent with a real cover server), while different src IPs
    /// receive different cover URLs.
    ///
    /// Recommended: 3-5 endpoints across distinct popular HTTPS
    /// destinations the operator does NOT control (Cloudflare,
    /// Microsoft, Apple, etc — same picking criteria as the
    /// single-endpoint case, just N of them).
    ///
    /// YAML example:
    /// ```yaml
    /// cover_endpoints:
    ///   - www.cloudflare.com:443
    ///   - www.apple.com:443
    ///   - www.microsoft.com:443
    /// ```
    ///
    /// Single-endpoint `cover_endpoint` shorthand still works for
    /// operators who don't need the pool; in that case this field
    /// stays empty.
    #[serde(default)]
    pub cover_endpoints: Vec<String>,
    /// Probe-anomaly detector: counts cover-forwards per source-IP
    /// /24 (v4) / /48 (v6) prefix and fires a structured WARN log
    /// AND a `proteus_probe_anomalies_fired_total` Prometheus
    /// counter increment whenever any prefix crosses the threshold
    /// within the sliding window.
    ///
    /// Companion defense to `cover_endpoints` (2026 threat-intel
    /// main line 4): the pool defeats the time-series-rotation
    /// signal, this detector defeats the probe-volume signal. See
    /// `proteus_transport_alpha::probe_anomaly` for the rationale.
    ///
    /// Default: disabled (operator opts in by adding the block).
    /// Recommended for any deployment that has the cover-forward
    /// path enabled.
    ///
    /// YAML example (defaults shown):
    /// ```yaml
    /// probe_anomaly:
    ///   window_secs: 300       # 5 min sliding window
    ///   threshold: 8           # 8 cover-forwards per /24 in window
    ///   max_prefixes: 16384    # memory cap on tracked prefixes
    /// ```
    #[serde(default)]
    pub probe_anomaly: Option<ProbeAnomalyCfg>,
    /// Optional Prometheus exposition listener, e.g. `"127.0.0.1:9090"`.
    /// When set, the server exposes `/metrics`, `/healthz`, `/readyz`
    /// over plain HTTP. Bind only to a private address (loopback or
    /// VPN) — only the bearer-token gate below stands between the
    /// listener and the world.
    #[serde(default)]
    pub metrics_listen: Option<String>,

    /// Optional bearer-token file for the `/metrics` endpoint. When
    /// set, every `GET /metrics` request must include the header
    /// `Authorization: Bearer <token>` where `<token>` is the first
    /// line of this file (trailing whitespace stripped).
    ///
    /// `/healthz` and `/readyz` are NEVER gated regardless — k8s /
    /// ECS / GCP load-balancer probes don't carry tokens.
    ///
    /// Strongly recommended when `metrics_listen` is bound to
    /// anything other than 127.0.0.1. Generate a 32-byte token:
    ///   openssl rand -hex 32 > /etc/proteus/metrics.token
    ///   chmod 0600 /etc/proteus/metrics.token
    #[serde(default)]
    pub metrics_token_file: Option<PathBuf>,

    /// Per-source-IP rate limit (handshakes/sec, burst). Production
    /// SHOULD set this; without it a single attacker IP can saturate
    /// the ML-KEM Decap path.
    #[serde(default)]
    pub rate_limit: Option<RateLimitCfg>,

    /// Optional **global** handshake budget — a single shared token
    /// bucket that caps total handshakes/sec across every source.
    /// Independent of `rate_limit` (per-IP) and `max_connections`
    /// (in-flight count); this protects against fleet-wide flooding
    /// where every individual IP stays under its per-IP limit but
    /// the aggregate cost exceeds the server's ML-KEM CPU budget.
    #[serde(default)]
    pub handshake_budget: Option<RateLimitCfg>,

    /// Optional per-user rate limit. Keyed on the matched 8-byte
    /// user_id, so CGNAT'd users each get their own budget. Layered
    /// on top of the per-IP limit. `max_users` caps memory at one
    /// bucket per distinct user (defaults to 64 K).
    #[serde(default)]
    pub user_rate_limit: Option<UserRateLimitCfg>,

    /// Per-handshake wall-clock deadline. Defaults to 15 s.
    #[serde(default)]
    pub handshake_deadline_secs: Option<u64>,

    /// TCP keepalive interval applied to every accepted connection.
    /// Defaults to 30 s.
    #[serde(default)]
    pub tcp_keepalive_secs: Option<u64>,

    /// Outer TLS 1.3 config (spec §4.2). When present the server wraps
    /// every accepted connection in TLS 1.3 BEFORE running the Proteus
    /// handshake — passive DPI sees a standard TLS record stream.
    /// When absent the server falls back to raw TCP (testing / trusted
    /// LAN only).
    #[serde(default)]
    pub tls: Option<TlsCfg>,

    /// Required anti-DoS proof-of-work difficulty (0..=24 leading zero
    /// bits). 0 = disabled. Bump under DoS alert. spec §8.3.
    #[serde(default)]
    pub pow_difficulty: Option<u8>,

    /// SIGTERM/SIGINT drain window in seconds. After receiving the
    /// signal the server stops accepting new connections and waits
    /// this long for in-flight sessions to flush before exiting.
    /// Default 30s; systemd's `TimeoutStopSec` should be ≥ this + 5s.
    #[serde(default)]
    pub drain_secs: Option<u64>,

    /// Optional path to a JSON Lines access log. One record per
    /// completed session is appended; rotate it externally via
    /// `logrotate` (use `copytruncate` since proteus-server keeps
    /// the FD open). Recommended location for a systemd deploy:
    /// `/var/log/proteus/access.log`. The schema is:
    ///     {"ts","user_id","peer","duration_ms","tx_bytes",
    ///      "rx_bytes","close_reason"}
    /// Unset = disabled.
    #[serde(default)]
    pub access_log: Option<PathBuf>,

    /// Outbound destination filter (SSRF defense). When set, every
    /// upstream CONNECT is resolved + checked against this policy
    /// before dialing. When `None`, the binary auto-installs the
    /// production default (ports 80/443, all SSRF CIDRs blocked).
    /// To explicitly disable (testing / trusted-LAN only) set:
    ///   outbound_filter:
    ///     disabled: true
    #[serde(default)]
    pub outbound_filter: Option<OutboundFilterCfg>,

    /// Optional anomaly detector for per-user byte-budget abuse.
    /// When the same `user_id` triggers `close_reason =
    /// "byte_budget_exhausted"` `threshold` times within `window_secs`,
    /// the server logs one WARN and bumps `abuse_alerts_byte_budget_total`.
    /// Fire-once per burst; resets after the window goes empty.
    ///
    /// Sensible production value:
    ///   abuse_detector:
    ///     byte_budget:
    ///       window_secs: 300   # 5-minute sliding window
    ///       threshold: 3       # 3 cap hits → alert
    /// Unset = disabled.
    #[serde(default)]
    pub abuse_detector: Option<AbuseDetectorCfg>,

    /// Optional cap on total bytes (tx + rx plaintext) per session.
    /// When the cumulative byte count crosses this threshold the
    /// session is torn down with close_reason = "byte_budget_exhausted".
    /// Defends against a compromised credential or a single greedy
    /// user saturating upstream egress and starving every other
    /// session sharing the NIC. Sensible production value:
    /// ~50 GiB (53687091200) for streaming-heavy users. Unset = no cap.
    #[serde(default)]
    pub max_session_bytes: Option<u64>,

    /// Per-session idle timeout in seconds. A session that goes this
    /// long without ANY inner traffic (either direction) is closed
    /// and its FD released. Distinct from `handshake_deadline_secs`
    /// which only bounds setup. Default 600s (10 min). Set to 0 to
    /// disable.
    ///
    /// Tune relative to the longest legitimate idle period your
    /// clients expect — too aggressive and you'll churn long-poll
    /// HTTP / WebSocket / SSH sessions; too loose and a malicious
    /// idle holder eats FDs.
    #[serde(default)]
    pub session_idle_secs: Option<u64>,

    /// Data-plane padding quantum (bytes) for the server→client
    /// direction. When non-zero, every outgoing DATA record is
    /// length-prefixed + zero-padded to a multiple of this value
    /// before AEAD seal, so the on-wire ciphertext length leaks only
    /// "which quantum bucket". Spec §4.6 / §22.
    ///
    /// Recommended values:
    /// - 0 / unset: no padding, max throughput, wire lengths leak
    /// - 64: ~1% overhead at 16 KiB records, kills sub-64-byte signal
    /// - 1280: matches β cell size, full sub-cell hiding (~5% overhead)
    ///
    /// The client side has an independent `pad_quantum` knob; setting
    /// only the server side leaves the client→server direction
    /// unpadded.
    #[serde(default)]
    pub pad_quantum: Option<u16>,

    /// CIDR firewall rules. Evaluated before rate-limit / max-connections.
    /// Denied connections are routed to `cover_endpoint` so an attacker
    /// cannot distinguish "you're blocked" from a generic HTTPS proxy.
    /// Example:
    ///   firewall:
    ///     allow:
    ///       - 10.0.0.0/8
    ///       - 198.51.100.0/24
    ///     deny:
    ///       - 192.0.2.42/32       # known abusive client
    ///       - 198.51.100.13/32    # banned for AUP violation
    /// Order: deny wins. Empty allowlist = "no allowlist policy".
    #[serde(default)]
    pub firewall: Option<FirewallCfg>,

    /// Hard cap on the number of *in-flight* accepted connections.
    /// Connections beyond this cap are routed to the cover endpoint
    /// (if configured) or dropped silently. Production deployments
    /// SHOULD set this — without it a sufficiently large SYN flood
    /// that survives the rate limiter can OOM the process by parking
    /// unbounded per-connection ML-KEM scratch space. A reasonable
    /// default for a 1 GiB VPS is `4096`; tune relative to your
    /// `nofile` ulimit (one connection ≈ one FD).
    #[serde(default)]
    pub max_connections: Option<usize>,
}

#[derive(Debug, Deserialize, Default)]
pub struct OutboundFilterCfg {
    /// When true, run the relay with NO outbound filter. Default is
    /// false (filter active). Operators must opt into the unfiltered
    /// path — leaving the field unset means "production defaults".
    #[serde(default)]
    pub disabled: bool,
    /// Replace the default allow-listed ports `[80, 443]`. Empty Vec
    /// means "no port restriction" (still subject to CIDR blocks).
    /// Use `extra_ports` to ADD without replacing the default.
    #[serde(default)]
    pub allowed_ports: Option<Vec<u16>>,
    /// Add ports on top of the default `[80, 443]`. Use this for
    /// extra ports the operator wants to allow (e.g. SMTP 587,
    /// IMAPS 993, DoT 853).
    #[serde(default)]
    pub extra_ports: Vec<u16>,
    /// Append additional CIDRs to the SSRF default blocklist. e.g.
    /// the operator's own VPC range, internal corp networks.
    #[serde(default)]
    pub extra_blocked_cidrs: Vec<String>,
    /// When true, replace the SSRF default blocklist entirely with
    /// `extra_blocked_cidrs`. Default false — operator MUST opt out
    /// of the SSRF defaults explicitly. Don't set this unless you
    /// know what you're doing.
    #[serde(default)]
    pub replace_default_blocklist: bool,
    /// Hostname allowlist patterns. When non-empty, the destination
    /// host MUST match one (`example.com` matches the apex and any
    /// subdomain; `*.example.com` matches strict subdomains only).
    /// Literal-IP destinations skip the hostname gate.
    #[serde(default)]
    pub allowed_hostnames: Vec<String>,
    /// Hostname denylist patterns. Always applied; takes precedence
    /// over the allowlist. Same pattern syntax as `allowed_hostnames`.
    #[serde(default)]
    pub blocked_hostnames: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct AbuseDetectorCfg {
    /// Byte-budget cap-hit detector. See [`AbuseDetectorEntry`].
    #[serde(default)]
    pub byte_budget: Option<AbuseDetectorEntry>,
    /// Per-user rate-limit reject detector. Same shape as
    /// `byte_budget`. Fires once-per-burst when the same `user_id`
    /// trips `user_rate_rejected` `threshold` times within
    /// `window_secs`.
    #[serde(default)]
    pub rate_limit: Option<AbuseDetectorEntry>,
}

#[derive(Debug, Deserialize)]
pub struct AbuseDetectorEntry {
    /// Sliding-window length in seconds. Default 300 (5 min).
    #[serde(default = "default_abuse_window_secs")]
    pub window_secs: u64,
    /// Number of events within the window that constitute "abuse".
    /// Default 3.
    #[serde(default = "default_abuse_threshold")]
    pub threshold: usize,
}

const fn default_abuse_window_secs() -> u64 {
    300
}
const fn default_abuse_threshold() -> usize {
    3
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct FirewallCfg {
    /// CIDR rules — only sources matching one of these are admitted.
    /// Empty = "no allowlist policy" (admit unless denied).
    #[serde(default)]
    pub allow: Vec<String>,
    /// CIDR rules — sources matching any of these are denied.
    /// Empty = "no denylist".
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsCfg {
    /// PEM-encoded full chain (server cert first, then intermediates).
    pub cert_chain: PathBuf,
    /// PEM-encoded PKCS8 / PKCS1 / SEC1 private key.
    pub private_key: PathBuf,
}

#[derive(Debug, Deserialize)]
pub struct RateLimitCfg {
    /// Burst capacity (max tokens per source IP).
    pub burst: f64,
    /// Steady-state refill rate (tokens per second per source IP).
    pub refill_per_sec: f64,
}

/// Configuration for `proteus_transport_alpha::probe_anomaly::ProbeAnomalyDetector`.
/// See the field's docstring on `ServerConfig::probe_anomaly` for
/// the operator-facing description; the type lives here so YAML can
/// deserialize it.
#[derive(Debug, Deserialize)]
pub struct ProbeAnomalyCfg {
    /// Sliding-window length in seconds. Default 300 (5 min).
    #[serde(default = "default_probe_anomaly_window_secs")]
    pub window_secs: u64,
    /// Per-prefix threshold. Default 8 (cover-forwards from one /24
    /// in `window_secs`).
    #[serde(default = "default_probe_anomaly_threshold")]
    pub threshold: usize,
    /// Hard cap on tracked prefixes (memory bound). Default 16384
    /// — about 1 MiB of bookkeeping.
    #[serde(default = "default_probe_anomaly_max_prefixes")]
    pub max_prefixes: usize,
    /// **Auto-deny TTL in minutes.** When > 0, every probe-anomaly
    /// fire inserts the offending /24 (v4) / /48 (v6) into a TTL-
    /// bounded in-memory deny list; `admission_ok` consults it
    /// BEFORE the firewall snapshot so denied prefixes short-circuit
    /// at the cheapest admission point. Entries auto-expire after
    /// the TTL — transient false positives heal automatically
    /// without operator intervention.
    ///
    /// Default 0 (disabled). Recommended starting value 15-60 for
    /// production deploys: long enough that a sustained prober
    /// loses many minutes of probing per fire, short enough that a
    /// mis-trigger on a legitimate client clears within one human
    /// coffee break.
    ///
    /// **The deny list is in-binary**, not pushed to the kernel
    /// firewall — see `auto_deny.rs` for the design rationale
    /// (operator firewall rules + auto-deny entries have different
    /// lifecycles; mixing them in one SIGHUP-reloadable surface is
    /// confusing). Connections that ARE denied by auto-deny still
    /// route to the cover endpoint (same as firewall denies),
    /// preserving the cover-server-pass-through fingerprint.
    #[serde(default = "default_probe_anomaly_autodeny_minutes")]
    pub autodeny_minutes: u64,
    /// Hard cap on the auto-deny map size. Same defense semantics
    /// as `max_prefixes` — when reached, new inserts are refused
    /// (existing entries continue to refresh). Default 4096 entries
    /// (~128 KiB bookkeeping).
    #[serde(default = "default_probe_anomaly_autodeny_max_entries")]
    pub autodeny_max_entries: usize,
}

const fn default_probe_anomaly_window_secs() -> u64 {
    300
}
const fn default_probe_anomaly_threshold() -> usize {
    8
}
const fn default_probe_anomaly_max_prefixes() -> usize {
    16 * 1024
}
const fn default_probe_anomaly_autodeny_minutes() -> u64 {
    // Default DISABLED. Operator opts in by setting > 0 in
    // server.yaml; we never apply a non-zero default because
    // auto-deny is a policy action and policy actions need
    // operator consent (false positives on legitimate clients
    // would be unacceptable surprises).
    0
}
const fn default_probe_anomaly_autodeny_max_entries() -> usize {
    4096
}

#[derive(Debug, Deserialize)]
pub struct UserRateLimitCfg {
    /// Burst capacity per user.
    pub burst: f64,
    /// Steady-state refill per user (tokens/sec).
    pub refill_per_sec: f64,
    /// Cap on distinct users tracked. Defaults to 65 536. Bound your
    /// memory: each bucket is ~64 bytes.
    #[serde(default = "default_max_users")]
    pub max_users: usize,
}

const fn default_max_users() -> usize {
    65_536
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // x25519_pk is round-tripped via x25519_sk → pub
pub struct KeysCfg {
    pub mlkem_pk: PathBuf,
    pub mlkem_sk: PathBuf,
    pub x25519_pk: PathBuf,
    pub x25519_sk: PathBuf,
}

#[derive(Debug, Deserialize)]
pub struct ClientCfg {
    /// Up to 8-byte ASCII user-id (will be truncated/zero-padded).
    pub user_id: String,
    /// Path to Ed25519 verifying-key file.
    pub ed25519_pk: PathBuf,
}

impl ServerConfig {
    pub async fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = tokio::fs::read_to_string(path)
            .await
            .map_err(ConfigError::Io)?;
        let cfg: Self = serde_yaml::from_str(&text).map_err(ConfigError::Yaml)?;
        Ok(cfg)
    }
}

pub fn load_server_keys(cfg: &ServerConfig) -> Result<ServerKeys, ConfigError> {
    {
        let mlkem_pk_bytes = std::fs::read(&cfg.keys.mlkem_pk).map_err(ConfigError::Io)?;
        let mlkem_pk_bytes = decode_b64_or_raw(&mlkem_pk_bytes);

        let mlkem_sk_raw = std::fs::read(&cfg.keys.mlkem_sk).map_err(ConfigError::Io)?;
        let mlkem_sk_bytes = decode_b64_or_raw(&mlkem_sk_raw);

        let x25519_sk_raw = std::fs::read(&cfg.keys.x25519_sk).map_err(ConfigError::Io)?;
        let x25519_sk_bytes = decode_b64_or_raw(&x25519_sk_raw);
        if x25519_sk_bytes.len() != 32 {
            return Err(ConfigError::BadKey("x25519_sk must be 32 bytes"));
        }
        let x25519_sk_arr: [u8; 32] = x25519_sk_bytes.as_slice().try_into().unwrap();
        let x25519_sk = StaticSecret::from(x25519_sk_arr);
        let x25519_pub = XPublicKey::from(&x25519_sk).to_bytes();

        let ek_array = ml_kem::array::Array::<u8, _>::try_from(&mlkem_pk_bytes[..])
            .map_err(|_| ConfigError::BadKey("invalid mlkem_pk length"))?;
        // sanity: round-trip back to bytes to confirm the array shape matches
        // the runtime expectation.
        let _ek_check = ml_kem::kem::EncapsulationKey::<MlKem768Params>::from_bytes(&ek_array);

        let dk_array = ml_kem::array::Array::<u8, _>::try_from(&mlkem_sk_bytes[..])
            .map_err(|_| ConfigError::BadKey("invalid mlkem_sk length"))?;
        let mlkem_sk = DecapsulationKey::<MlKem768Params>::from_bytes(&dk_array);

        let pq_fingerprint = key_schedule::sha256(&mlkem_pk_bytes);

        let mut client_id_aead_key = [0u8; 32];
        proteus_crypto::kdf::expand_label(
            &pq_fingerprint,
            b"proteus-cid-key-v1",
            b"",
            &mut client_id_aead_key,
        )
        .map_err(|_| ConfigError::BadKey("hkdf failed"))?;

        let mut allowlist = Vec::new();
        for client in &cfg.client_allowlist {
            let uid = encode_user_id(&client.user_id);
            let pk_bytes = std::fs::read(&client.ed25519_pk).map_err(ConfigError::Io)?;
            let pk_bytes = decode_b64_or_raw(&pk_bytes);
            if pk_bytes.len() != 32 {
                return Err(ConfigError::BadKey("ed25519_pk must be 32 bytes"));
            }
            let pk_arr: [u8; 32] = pk_bytes.as_slice().try_into().unwrap();
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk_arr)
                .map_err(|_| ConfigError::BadKey("invalid ed25519_pk"))?;
            allowlist.push((uid, vk));
        }

        Ok(ServerKeys {
            mlkem_sk,
            mlkem_pk_bytes,
            pq_fingerprint,
            x25519_sk,
            x25519_pub,
            client_allowlist: allowlist,
            client_id_aead_key,
        })
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
    // Try base64 (line-buffered file with optional trailing newline).
    let trimmed: Vec<u8> = input
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&trimmed) {
        return decoded;
    }
    input.to_vec()
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
