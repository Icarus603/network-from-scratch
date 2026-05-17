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

    /// Optional **per-user sustained bandwidth-rate** abuse detector.
    /// Unlike the event-based [`AbuseDetectorCfg`] above, this fires
    /// on rolling-window throughput: when a `user_id`'s `(tx+rx)`
    /// byte rate averaged over `window_secs` crosses
    /// `threshold_mb_per_sec`, the server logs one WARN line and
    /// bumps `abuse_alerts_per_user_bandwidth_total`. Hysteresis
    /// (re-arm after rate drops below 50% threshold) prevents
    /// flapping at the boundary.
    ///
    /// Designed for the canonical small-VPN operator (personal VPN
    /// for friends on one VPS, no Prometheus stack). The in-process
    /// detector gives them the alert that PromQL `rate(...) > N`
    /// would otherwise provide — without requiring the alerting
    /// infrastructure.
    ///
    /// Sensible production value (a 1 Gbps home uplink, 5-user
    /// personal VPN):
    ///   per_user_bandwidth_rate:
    ///     window_secs: 30
    ///     threshold_mb_per_sec: 100   # 100 MB/s sustained = abuse
    ///     max_users: 4096
    ///
    /// Unset OR `threshold_mb_per_sec=0` = detector silent
    /// (gauges still emitted as 0 so operators can verify the slot
    /// is wired).
    #[serde(default)]
    pub per_user_bandwidth_rate: Option<PerUserBandwidthRateCfg>,

    /// Optional **per-user concurrent-session cap**. Mirrors the
    /// commercial-VPN "N devices per account" model that
    /// VLESS/Hy2/TUIC5 lack at the protocol layer. When a user_id
    /// holds `max_per_user` open sessions, additional sessions are
    /// rejected with `proteus_per_user_conn_limit_rejected_total++`.
    ///
    /// Sensible production values (commercial reference points):
    /// - 4-6 for personal-VPN-for-friends (mostly mobile + laptop)
    /// - 6-10 for small workgroups (NordVPN-grade)
    /// - 0 = limiter wired but disabled (SIGHUP-swap slot)
    ///
    /// Critical defense against stolen credentials: an attacker
    /// with a leaked user_id can open hundreds of small sessions
    /// in parallel (each one stays under per-session byte budget),
    /// exfiltrating GBs aggregated. This cap stops that without
    /// affecting legitimate users who almost never need >5 devices.
    #[serde(default)]
    pub per_user_conn_limit: Option<PerUserConnLimitCfg>,

    /// Optional **auto-quarantine list** — TTL-bounded ban for
    /// user_ids that trip the operator-selected abuse detectors.
    /// Closes the loop from observation (counters + WARN logs +
    /// recent-fires ring) to enforcement (subsequent handshakes
    /// from the banned user_id are rejected at the post-handshake
    /// admission gate). The IP-based `auto_deny` does the same
    /// for source-IP /24 prefixes; this is the per-credential
    /// sibling — the right level for stolen-credential abuse.
    ///
    /// Sensible production values:
    ///
    /// ```yaml
    /// user_quarantine:
    ///   ttl_secs: 600                  # 10-minute ban
    ///   max_entries: 4096              # match other per-user caps
    ///   on_kinds:
    ///     - per_user_bandwidth_rate    # strongest signal — always opt in
    ///     - rate_limit                 # optional — fires on repeated rate hits
    ///     # byte_budget                # noisiest; opt in only if you trust the detector
    /// ```
    ///
    /// Unset = quarantine disabled (the detectors still fire alerts
    ///   + push to the recent-fires ring; just no auto-enforcement).
    ///     `ttl_secs=0` = list wired but disabled (SIGHUP-swap slot).
    #[serde(default)]
    pub user_quarantine: Option<UserQuarantineCfg>,

    /// Optional per-user period-based data quota tracker. Closes
    /// the gap left by the rate / event detectors: a patient
    /// attacker who stays under any single-session cap AND any
    /// sustained-rate threshold can drain TBs over weeks; a hard
    /// monthly cap stops that. Every commercial VPN has this
    /// (Mullvad free tier 5 GB, Cloudflare WARP 1 GB/month,
    /// corporate VPN admins set per-user monthly).
    ///
    /// Example:
    ///
    /// ```yaml
    /// user_quotas:
    ///   period_secs: 2592000              # 30 days
    ///   default_period_bytes: 107374182400 # 100 GB default
    ///   max_entries: 4096
    ///   persistence_path: /var/lib/proteus/user_quotas.jsonl
    ///   overrides:
    ///     - user_id: alice001
    ///       period_bytes: 53687091200     # 50 GB for alice
    ///     - user_id: vip00001
    ///       period_bytes: 0               # unlimited for vip
    /// ```
    ///
    /// Unset = no per-user data caps (the current behavior, full
    /// back-compat). `default_period_bytes=0` = no default cap;
    /// only per-user overrides apply.
    #[serde(default)]
    pub user_quotas: Option<UserQuotasCfg>,

    /// Startup self-test deadline in seconds. The binary runs a
    /// full loopback handshake against the operator's real keys
    /// BEFORE binding the public listener. Catches mismatched
    /// mlkem_pk/sk, broken dep regressions, RNG starvation —
    /// failures the operator would otherwise only learn about
    /// when real users start failing handshakes.
    ///
    /// 0 = self-test disabled (NOT recommended for production —
    /// you give up the deploy-time trip-wire). Default 10s when
    /// unset. Reasonable production value: 10-30 seconds; the
    /// self-test typically takes <1ms on modern hardware, so a
    /// generous deadline costs nothing.
    #[serde(default)]
    pub startup_self_test_timeout_secs: Option<u64>,

    /// Periodic self-test interval in seconds. The binary runs
    /// the same loopback handshake every N seconds in a
    /// background task. On failure, `/healthz` immediately flips
    /// to 503 so load balancers route traffic away from this
    /// (degraded) instance.
    ///
    /// Catches mid-flight crypto-stack degradation: disk full →
    /// AEAD entropy reads failing, accept-loop deadlock, GC
    /// pause that hangs the runtime, clock drift past the replay
    /// window. Without this, /healthz is set-once-at-startup and
    /// returns 200 even if the binary is silently broken.
    ///
    /// 0 (default) = periodic self-test DISABLED (back-compat for
    /// existing deployments). Recommended production value:
    /// 30-300 seconds. The /healthz stale-rule fires when the
    /// last success was more than `3 × interval` ago, so a 60s
    /// interval gives the LB ~3min to route around a hung node.
    #[serde(default)]
    pub periodic_self_test_interval_secs: Option<u64>,

    /// TLS cert file mtime-watch interval in seconds.
    ///
    /// When set (and a `tls:` block is configured), Proteus polls
    /// the cert/key file mtimes every N seconds. If either
    /// changed, the binary auto-reloads the cert chain WITHOUT
    /// requiring a SIGHUP. Closes the "non-Let's-Encrypt operator
    /// forgets to signal after rotation" gap — the operator's
    /// deploy script just needs to atomic-rename the new cert
    /// onto the configured path; Proteus picks it up on the next
    /// poll cycle.
    ///
    /// Counters: `proteus_tls_cert_watcher_*` (mtime changes,
    /// auto-reload attempts/succeeded/failed). Alert on
    /// `auto_reload_failed > 0` to spot a deploy that produced a
    /// malformed PEM (the binary keeps serving the OLD cert
    /// until the operator fixes it).
    ///
    /// 0 (default) = watcher DISABLED. Operators using
    /// Let's-Encrypt + certbot deploy-hook already have SIGHUP
    /// reload wired and don't need this. Recommended for
    /// everyone else: 60 seconds — fast enough to pick up a
    /// fresh cert within a minute, slow enough that `stat()`
    /// cost is negligible.
    #[serde(default)]
    pub tls_cert_watcher_interval_secs: Option<u64>,

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

/// Per-user sustained bandwidth-rate detector knobs (see
/// [`ServerConfig::per_user_bandwidth_rate`] for the operator-facing
/// docstring).
#[derive(Debug, Deserialize)]
pub struct PerUserBandwidthRateCfg {
    /// Sliding-window length in seconds the detector averages over.
    /// Operator default 30s — short enough to catch real abuse fast,
    /// long enough to ignore a single fast-completing session.
    #[serde(default = "default_per_user_bw_window_secs")]
    pub window_secs: u64,
    /// Per-user threshold in **megabytes per second**. A user whose
    /// `(tx+rx)/window_secs` exceeds this fires ONE alert per burst.
    /// 0 = detector wired but silent (gauges still emitted so the
    /// operator can confirm the slot is alive).
    #[serde(default)]
    pub threshold_mb_per_sec: u64,
    /// Cap on distinct user_ids the detector samples. Matches the
    /// per-user bandwidth accumulator's typical default of 4096.
    /// Beyond cap, new users are silently dropped from the detector
    /// (memory bound > alerting perfection).
    #[serde(default = "default_per_user_bw_max_users")]
    pub max_users: usize,
    /// Hysteresis exit factor `[0.0, 1.0]`. Once an alert fires, the
    /// user's rolling-window rate must drop below
    /// `threshold * exit_factor` before another alert can fire.
    /// Default 0.5 — re-arm at half threshold; prevents flapping at
    /// the boundary.
    #[serde(default = "default_per_user_bw_exit_factor")]
    pub exit_factor: f64,
}

const fn default_per_user_bw_window_secs() -> u64 {
    30
}
const fn default_per_user_bw_max_users() -> usize {
    4096
}
#[allow(clippy::excessive_precision)]
fn default_per_user_bw_exit_factor() -> f64 {
    0.5
}

/// Per-user concurrent-session cap config (see
/// [`ServerConfig::per_user_conn_limit`] for the operator-facing
/// docstring).
#[derive(Debug, Deserialize)]
pub struct PerUserConnLimitCfg {
    /// Max simultaneous sessions per user_id. 0 = wired but disabled
    /// (operator gets the gauge surface for SIGHUP-swap workflows
    /// but no session is ever rejected).
    pub max_per_user: usize,
}

/// Auto-quarantine config (see [`ServerConfig::user_quarantine`]
/// for the operator-facing docstring).
#[derive(Debug, Deserialize)]
pub struct UserQuarantineCfg {
    /// TTL applied to each new (or refreshed) quarantine entry.
    /// Operator defaults: 600 (10 min) for personal-VPN, 3600
    /// (1 hour) for stricter deployments. 0 = list wired but
    /// disabled (no insert ever sticks).
    #[serde(default = "default_user_quarantine_ttl_secs")]
    pub ttl_secs: u64,
    /// Hard cap on map size (memory bound). Matches the per-user
    /// bandwidth/conn-limit defaults; raise only if the operator
    /// expects more than 4096 distinct user_ids active in the
    /// quarantine window.
    #[serde(default = "default_user_quarantine_max_entries")]
    pub max_entries: usize,
    /// Abuse-fire kinds eligible for auto-quarantine. Each entry
    /// must be one of `byte_budget`, `rate_limit`,
    /// `per_user_bandwidth_rate`. Unknown labels are silently
    /// stored (forward-compat) but never fire enforcement.
    ///
    /// Empty list = quarantine list installed for observability
    /// only — no detector opted in, nothing ever gets banned.
    #[serde(default)]
    pub on_kinds: Vec<String>,
    /// Optional disk path for persisting quarantine state across
    /// process restarts. When set, every insert (fresh or refresh)
    /// writes the current map to the file atomically (temp + rename),
    /// and the file is loaded at startup to restore prior bans.
    ///
    /// Without this, a stolen credential gets a fresh attack window
    /// of `ttl_secs` every time the process restarts (systemd
    /// restart, OOM kill, binary upgrade). For deployments that
    /// expect long quarantine windows, persistence is mandatory.
    ///
    /// Format: operator-readable JSON Lines with a versioned
    /// header. Safe to hand-edit for emergency unbans (delete the
    /// matching line, SIGHUP to reload... actually no SIGHUP is
    /// needed — the file is only read at startup; future edits
    /// take effect on next restart).
    ///
    /// Recommended path: `/var/lib/proteus/user_quarantine.jsonl`
    /// (same level as systemd's typical `StateDirectory=`).
    #[serde(default)]
    pub persistence_path: Option<std::path::PathBuf>,
}

const fn default_user_quarantine_ttl_secs() -> u64 {
    600
}
const fn default_user_quarantine_max_entries() -> usize {
    4096
}

/// Per-user period-based data quota config (see
/// [`ServerConfig::user_quotas`] for the operator-facing
/// docstring).
#[derive(Debug, Deserialize)]
pub struct UserQuotasCfg {
    /// Period length over which the quota resets. Default
    /// 2_592_000 (30 days). Set to a shorter window for daily
    /// quotas, or longer for quarterly.
    #[serde(default = "default_user_quota_period_secs")]
    pub period_secs: u64,
    /// Default per-period byte cap for any user without an
    /// explicit override. 0 = no default cap (only overrides
    /// apply). Recommended: 100 GiB (107_374_182_400) for
    /// personal-VPN-for-friends.
    #[serde(default)]
    pub default_period_bytes: u64,
    /// Hard cap on the number of distinct user_ids tracked.
    /// Matches the per-user bandwidth/conn-limit defaults.
    #[serde(default = "default_user_quota_max_entries")]
    pub max_entries: usize,
    /// Optional disk persistence path. Same JSONL pattern as
    /// `user_quarantine.persistence_path`. Without this, a
    /// process restart resets every user's bucket → attacker can
    /// exploit by bouncing the binary.
    #[serde(default)]
    pub persistence_path: Option<std::path::PathBuf>,
    /// Per-user cap overrides. Each entry's `period_bytes`
    /// overrides the default for that user_id.
    /// `period_bytes=0` explicitly grants UNLIMITED for that
    /// user (operator's VIP override).
    #[serde(default)]
    pub overrides: Vec<UserQuotaOverride>,
}

#[derive(Debug, Deserialize)]
pub struct UserQuotaOverride {
    /// 8-byte user_id, ASCII or zero-padded.
    pub user_id: String,
    /// Per-period byte cap for this user. 0 = unlimited.
    pub period_bytes: u64,
}

const fn default_user_quota_period_secs() -> u64 {
    2_592_000 // 30 days
}
const fn default_user_quota_max_entries() -> usize {
    4096
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

    /// Snapshot which optional config sections are present.
    ///
    /// Operators read this on `/metrics` + `admin status` to answer
    /// "did my YAML edit even land?" without re-reading the on-disk
    /// file. The presence bits also act as a deployment-shape
    /// indicator visible to Grafana dashboards — e.g. an alert that
    /// fires when `firewall` flips from 1 to 0 unexpectedly catches
    /// the operator who SIGHUPed with the firewall block accidentally
    /// commented out.
    ///
    /// Deliberately exposes ONLY presence bits, never field values —
    /// the metric must be safe to scrape into a shared Prometheus
    /// without leaking allowlist entries / cover URLs / rate-limit
    /// burst values etc.
    #[must_use]
    pub fn presence(&self) -> ConfigPresence {
        ConfigPresence {
            tls: self.tls.is_some(),
            firewall: self.firewall.is_some(),
            rate_limit: self.rate_limit.is_some(),
            user_rate_limit: self.user_rate_limit.is_some(),
            handshake_budget: self.handshake_budget.is_some(),
            probe_anomaly: self.probe_anomaly.is_some(),
            outbound_filter: self.outbound_filter.is_some(),
            cover_endpoint: self.cover_endpoint.is_some(),
            cover_endpoints: !self.cover_endpoints.is_empty(),
            max_connections: self.max_connections.is_some(),
            metrics_listen: self.metrics_listen.is_some(),
            per_user_bandwidth_rate: self.per_user_bandwidth_rate.is_some(),
            per_user_conn_limit: self.per_user_conn_limit.is_some(),
            user_quarantine: self.user_quarantine.is_some(),
            user_quotas: self.user_quotas.is_some(),
            cover_endpoint_count: self.cover_endpoints.len() as u64,
            client_allowlist_count: self.client_allowlist.len() as u64,
        }
    }
}

/// Snapshot of which optional `ServerConfig` sections are present
/// at load time. Returned by [`ServerConfig::presence`] and rendered
/// to Prometheus + admin-status text.
///
/// All fields are public so the renderers don't need a getter
/// boilerplate; the struct is value-only (no methods that mutate
/// state). Safe to clone freely.
#[derive(Debug, Clone, Default)]
pub struct ConfigPresence {
    pub tls: bool,
    pub firewall: bool,
    pub rate_limit: bool,
    pub user_rate_limit: bool,
    pub handshake_budget: bool,
    pub probe_anomaly: bool,
    pub outbound_filter: bool,
    pub cover_endpoint: bool,
    pub cover_endpoints: bool,
    pub max_connections: bool,
    pub metrics_listen: bool,
    /// `per_user_bandwidth_rate:` block — 1 when the detector is
    /// configured (even with threshold=0 — the slot is wired).
    pub per_user_bandwidth_rate: bool,
    /// `per_user_conn_limit:` block — 1 when the cap is configured
    /// (even with max=0 — the slot is wired).
    pub per_user_conn_limit: bool,
    /// `user_quarantine:` block — 1 when the auto-quarantine list
    /// is configured (even with ttl_secs=0 — the slot is wired).
    pub user_quarantine: bool,
    /// `user_quotas:` block — 1 when the per-user period quota
    /// tracker is configured.
    pub user_quotas: bool,
    /// Number of entries in `cover_endpoints:`. Operators read the
    /// SIZE of the pool as a sanity check ("I configured 5 cover
    /// endpoints, why does this show 3?") which a bare presence bit
    /// can't surface.
    pub cover_endpoint_count: u64,
    /// Number of `client_allowlist` entries. Same operator-sanity
    /// rationale as `cover_endpoint_count`.
    pub client_allowlist_count: u64,
}

impl ConfigPresence {
    /// Emit a Prometheus exposition block. Format follows the
    /// existing `proteus_*` series conventions:
    ///   - `proteus_config_section_active{section="firewall"} 0|1`
    ///   - `proteus_config_cover_endpoint_pool_size N`
    ///   - `proteus_config_client_allowlist_size N`
    ///
    /// The `section` label discriminator lets one HELP/TYPE pair
    /// cover all the boolean sections; PromQL `count(proteus_config_section_active{value="1"})`
    /// gives the operator the active-section count.
    #[must_use]
    pub fn prometheus(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(1024);
        let _ = writeln!(
            s,
            "# HELP proteus_config_section_active 1 if the named optional config section is present at load time, 0 otherwise."
        );
        let _ = writeln!(s, "# TYPE proteus_config_section_active gauge");
        for (section, present) in [
            ("tls", self.tls),
            ("firewall", self.firewall),
            ("rate_limit", self.rate_limit),
            ("user_rate_limit", self.user_rate_limit),
            ("handshake_budget", self.handshake_budget),
            ("probe_anomaly", self.probe_anomaly),
            ("outbound_filter", self.outbound_filter),
            ("cover_endpoint", self.cover_endpoint),
            ("cover_endpoints", self.cover_endpoints),
            ("max_connections", self.max_connections),
            ("metrics_listen", self.metrics_listen),
            ("per_user_bandwidth_rate", self.per_user_bandwidth_rate),
            ("per_user_conn_limit", self.per_user_conn_limit),
            ("user_quarantine", self.user_quarantine),
            ("user_quotas", self.user_quotas),
        ] {
            let _ = writeln!(
                s,
                r#"proteus_config_section_active{{section="{section}"}} {}"#,
                u8::from(present)
            );
        }
        let _ = writeln!(
            s,
            "# HELP proteus_config_cover_endpoint_pool_size Number of entries in cover_endpoints:."
        );
        let _ = writeln!(s, "# TYPE proteus_config_cover_endpoint_pool_size gauge");
        let _ = writeln!(
            s,
            "proteus_config_cover_endpoint_pool_size {}",
            self.cover_endpoint_count
        );
        let _ = writeln!(
            s,
            "# HELP proteus_config_client_allowlist_size Number of entries in client_allowlist:."
        );
        let _ = writeln!(s, "# TYPE proteus_config_client_allowlist_size gauge");
        let _ = writeln!(
            s,
            "proteus_config_client_allowlist_size {}",
            self.client_allowlist_count
        );
        s
    }
}

#[cfg(test)]
mod presence_tests {
    use super::*;

    #[test]
    fn presence_all_false_for_minimal_config() {
        let p = ConfigPresence::default();
        let s = p.prometheus();
        // Every section reports 0.
        for sec in [
            "tls",
            "firewall",
            "rate_limit",
            "user_rate_limit",
            "handshake_budget",
            "probe_anomaly",
            "outbound_filter",
            "cover_endpoint",
            "cover_endpoints",
            "max_connections",
            "metrics_listen",
        ] {
            assert!(
                s.contains(&format!(
                    r#"proteus_config_section_active{{section="{sec}"}} 0"#
                )),
                "missing zero-row for {sec}: {s}"
            );
        }
        assert!(
            s.contains("proteus_config_cover_endpoint_pool_size 0"),
            "{s}"
        );
        assert!(s.contains("proteus_config_client_allowlist_size 0"), "{s}");
    }

    #[test]
    fn prometheus_has_one_help_and_type_per_metric_name() {
        let p = ConfigPresence::default();
        let s = p.prometheus();
        let help_section = s.matches("# HELP proteus_config_section_active ").count();
        let type_section = s
            .matches("# TYPE proteus_config_section_active gauge")
            .count();
        assert_eq!(help_section, 1);
        assert_eq!(type_section, 1);
        // pool_size / allowlist_size have their own HELP+TYPE.
        assert_eq!(
            s.matches("# HELP proteus_config_cover_endpoint_pool_size ")
                .count(),
            1
        );
        assert_eq!(
            s.matches("# HELP proteus_config_client_allowlist_size ")
                .count(),
            1
        );
    }

    #[test]
    fn prometheus_reflects_present_sections() {
        let p = ConfigPresence {
            tls: true,
            firewall: true,
            rate_limit: false,
            cover_endpoint_count: 3,
            client_allowlist_count: 5,
            ..ConfigPresence::default()
        };
        let s = p.prometheus();
        assert!(s.contains(r#"proteus_config_section_active{section="tls"} 1"#));
        assert!(s.contains(r#"proteus_config_section_active{section="firewall"} 1"#));
        assert!(s.contains(r#"proteus_config_section_active{section="rate_limit"} 0"#));
        assert!(s.contains("proteus_config_cover_endpoint_pool_size 3"));
        assert!(s.contains("proteus_config_client_allowlist_size 5"));
    }

    #[test]
    fn presence_from_yaml_minimal_reports_all_optional_sections_false() {
        let yaml = "\
listen_alpha: \"127.0.0.1:0\"\n\
keys:\n  \
  mlkem_pk: /tmp/x\n  \
  mlkem_sk: /tmp/x\n  \
  x25519_pk: /tmp/x\n  \
  x25519_sk: /tmp/x\n\
";
        let cfg: ServerConfig = serde_yaml::from_str(yaml).expect("parse");
        let p = cfg.presence();
        assert!(!p.tls);
        assert!(!p.firewall);
        assert!(!p.rate_limit);
        assert!(!p.user_rate_limit);
        assert!(!p.handshake_budget);
        assert!(!p.probe_anomaly);
        assert!(!p.outbound_filter);
        assert!(!p.cover_endpoint);
        assert!(!p.cover_endpoints);
        assert!(!p.max_connections);
        assert!(!p.metrics_listen);
        assert_eq!(p.cover_endpoint_count, 0);
        assert_eq!(p.client_allowlist_count, 0);
    }

    #[test]
    fn presence_from_yaml_with_firewall_and_cover_pool_reports_correctly() {
        let yaml = "\
listen_alpha: \"127.0.0.1:0\"\n\
keys:\n  \
  mlkem_pk: /tmp/x\n  \
  mlkem_sk: /tmp/x\n  \
  x25519_pk: /tmp/x\n  \
  x25519_sk: /tmp/x\n\
firewall:\n  \
  default_action: allow\n  \
  rules: []\n\
cover_endpoints:\n  \
  - example.com:443\n  \
  - other.com:443\n\
client_allowlist:\n  \
  - user_id: alice001\n    \
    ed25519_pk: /tmp/x\n\
";
        let cfg: ServerConfig = serde_yaml::from_str(yaml).expect("parse");
        let p = cfg.presence();
        assert!(p.firewall, "firewall block should be detected");
        assert!(p.cover_endpoints);
        assert_eq!(p.cover_endpoint_count, 2);
        assert_eq!(p.client_allowlist_count, 1);
        // Sections not in the YAML stay false.
        assert!(!p.tls);
        assert!(!p.rate_limit);
        // Specifically not configuring per_user_bandwidth_rate must
        // leave the presence bit at false (back-compat: existing YAML
        // files without the section must not start showing the bit
        // active).
        assert!(!p.per_user_bandwidth_rate);
    }

    #[test]
    fn presence_reports_per_user_bandwidth_rate_when_configured() {
        // YAML roundtrip — proves the section name + every field
        // serde-deserializes against the operator-facing docstring.
        let yaml = "\
listen_alpha: \"127.0.0.1:0\"\n\
keys:\n  \
  mlkem_pk: /tmp/x\n  \
  mlkem_sk: /tmp/x\n  \
  x25519_pk: /tmp/x\n  \
  x25519_sk: /tmp/x\n\
per_user_bandwidth_rate:\n  \
  window_secs: 30\n  \
  threshold_mb_per_sec: 100\n  \
  max_users: 4096\n  \
  exit_factor: 0.5\n\
";
        let cfg: ServerConfig = serde_yaml::from_str(yaml).expect("parse");
        let r = cfg
            .per_user_bandwidth_rate
            .as_ref()
            .expect("must deserialize");
        assert_eq!(r.window_secs, 30);
        assert_eq!(r.threshold_mb_per_sec, 100);
        assert_eq!(r.max_users, 4096);
        assert!((r.exit_factor - 0.5).abs() < 1e-12);
        let p = cfg.presence();
        assert!(
            p.per_user_bandwidth_rate,
            "presence bit must reflect the section being present"
        );
        // Prometheus block includes the new section row.
        let prom = p.prometheus();
        assert!(
            prom.contains(r#"proteus_config_section_active{section="per_user_bandwidth_rate"} 1"#),
            "{prom}"
        );
    }

    #[test]
    fn presence_reports_per_user_conn_limit_when_configured() {
        let yaml = "\
listen_alpha: \"127.0.0.1:0\"\n\
keys:\n  \
  mlkem_pk: /tmp/x\n  \
  mlkem_sk: /tmp/x\n  \
  x25519_pk: /tmp/x\n  \
  x25519_sk: /tmp/x\n\
per_user_conn_limit:\n  \
  max_per_user: 6\n\
";
        let cfg: ServerConfig = serde_yaml::from_str(yaml).expect("parse");
        let l = cfg.per_user_conn_limit.as_ref().expect("must deserialize");
        assert_eq!(l.max_per_user, 6);
        let p = cfg.presence();
        assert!(p.per_user_conn_limit, "presence bit must reflect section");
        let prom = p.prometheus();
        assert!(
            prom.contains(r#"proteus_config_section_active{section="per_user_conn_limit"} 1"#),
            "{prom}"
        );
    }

    #[test]
    fn presence_reports_user_quotas_when_configured() {
        let yaml = "\
listen_alpha: \"127.0.0.1:0\"\n\
keys:\n  \
  mlkem_pk: /tmp/x\n  \
  mlkem_sk: /tmp/x\n  \
  x25519_pk: /tmp/x\n  \
  x25519_sk: /tmp/x\n\
user_quotas:\n  \
  period_secs: 2592000\n  \
  default_period_bytes: 107374182400\n  \
  max_entries: 4096\n  \
  persistence_path: /var/lib/proteus/user_quotas.jsonl\n  \
  overrides:\n    - user_id: alice001\n      period_bytes: 53687091200\n    - user_id: vip00001\n      period_bytes: 0\n\
";
        let cfg: ServerConfig = serde_yaml::from_str(yaml).expect("parse");
        let q = cfg.user_quotas.as_ref().expect("must deserialize");
        assert_eq!(q.period_secs, 2592000);
        assert_eq!(q.default_period_bytes, 107374182400);
        assert_eq!(q.max_entries, 4096);
        assert_eq!(q.overrides.len(), 2);
        assert_eq!(q.overrides[0].user_id, "alice001");
        assert_eq!(q.overrides[0].period_bytes, 53687091200);
        assert_eq!(q.overrides[1].user_id, "vip00001");
        assert_eq!(q.overrides[1].period_bytes, 0);
        let p = cfg.presence();
        assert!(p.user_quotas);
        assert!(p
            .prometheus()
            .contains(r#"proteus_config_section_active{section="user_quotas"} 1"#));
    }

    #[test]
    fn startup_self_test_timeout_parses_when_supplied() {
        let yaml = "\
listen_alpha: \"127.0.0.1:0\"\n\
keys:\n  \
  mlkem_pk: /tmp/x\n  \
  mlkem_sk: /tmp/x\n  \
  x25519_pk: /tmp/x\n  \
  x25519_sk: /tmp/x\n\
startup_self_test_timeout_secs: 30\n\
";
        let cfg: ServerConfig = serde_yaml::from_str(yaml).expect("parse");
        assert_eq!(cfg.startup_self_test_timeout_secs, Some(30));
    }

    #[test]
    fn startup_self_test_timeout_zero_means_disabled() {
        let yaml = "\
listen_alpha: \"127.0.0.1:0\"\n\
keys:\n  \
  mlkem_pk: /tmp/x\n  \
  mlkem_sk: /tmp/x\n  \
  x25519_pk: /tmp/x\n  \
  x25519_sk: /tmp/x\n\
startup_self_test_timeout_secs: 0\n\
";
        let cfg: ServerConfig = serde_yaml::from_str(yaml).expect("parse");
        assert_eq!(cfg.startup_self_test_timeout_secs, Some(0));
    }

    #[test]
    fn periodic_self_test_interval_parses_when_supplied() {
        let yaml = "\
listen_alpha: \"127.0.0.1:0\"\n\
keys:\n  \
  mlkem_pk: /tmp/x\n  \
  mlkem_sk: /tmp/x\n  \
  x25519_pk: /tmp/x\n  \
  x25519_sk: /tmp/x\n\
periodic_self_test_interval_secs: 60\n\
";
        let cfg: ServerConfig = serde_yaml::from_str(yaml).expect("parse");
        assert_eq!(cfg.periodic_self_test_interval_secs, Some(60));
    }

    #[test]
    fn tls_cert_watcher_interval_parses_when_supplied() {
        let yaml = "\
listen_alpha: \"127.0.0.1:0\"\n\
keys:\n  \
  mlkem_pk: /tmp/x\n  \
  mlkem_sk: /tmp/x\n  \
  x25519_pk: /tmp/x\n  \
  x25519_sk: /tmp/x\n\
tls_cert_watcher_interval_secs: 60\n\
";
        let cfg: ServerConfig = serde_yaml::from_str(yaml).expect("parse");
        assert_eq!(cfg.tls_cert_watcher_interval_secs, Some(60));
    }

    #[test]
    fn tls_cert_watcher_interval_defaults_to_none() {
        let yaml = "\
listen_alpha: \"127.0.0.1:0\"\n\
keys:\n  \
  mlkem_pk: /tmp/x\n  \
  mlkem_sk: /tmp/x\n  \
  x25519_pk: /tmp/x\n  \
  x25519_sk: /tmp/x\n\
";
        let cfg: ServerConfig = serde_yaml::from_str(yaml).expect("parse");
        assert_eq!(cfg.tls_cert_watcher_interval_secs, None);
    }

    #[test]
    fn periodic_self_test_interval_defaults_to_none() {
        let yaml = "\
listen_alpha: \"127.0.0.1:0\"\n\
keys:\n  \
  mlkem_pk: /tmp/x\n  \
  mlkem_sk: /tmp/x\n  \
  x25519_pk: /tmp/x\n  \
  x25519_sk: /tmp/x\n\
";
        let cfg: ServerConfig = serde_yaml::from_str(yaml).expect("parse");
        assert_eq!(cfg.periodic_self_test_interval_secs, None);
    }

    #[test]
    fn startup_self_test_timeout_defaults_to_none_when_omitted() {
        let yaml = "\
listen_alpha: \"127.0.0.1:0\"\n\
keys:\n  \
  mlkem_pk: /tmp/x\n  \
  mlkem_sk: /tmp/x\n  \
  x25519_pk: /tmp/x\n  \
  x25519_sk: /tmp/x\n\
";
        let cfg: ServerConfig = serde_yaml::from_str(yaml).expect("parse");
        // None = use default (10s in main.rs).
        assert_eq!(cfg.startup_self_test_timeout_secs, None);
    }

    #[test]
    fn user_quotas_defaults_apply_when_subfields_missing() {
        let yaml = "\
listen_alpha: \"127.0.0.1:0\"\n\
keys:\n  \
  mlkem_pk: /tmp/x\n  \
  mlkem_sk: /tmp/x\n  \
  x25519_pk: /tmp/x\n  \
  x25519_sk: /tmp/x\n\
user_quotas:\n  \
  default_period_bytes: 107374182400\n\
";
        let cfg: ServerConfig = serde_yaml::from_str(yaml).expect("parse");
        let q = cfg.user_quotas.as_ref().unwrap();
        assert_eq!(q.period_secs, 2_592_000); // default
        assert_eq!(q.max_entries, 4096); // default
        assert!(q.overrides.is_empty());
        assert!(q.persistence_path.is_none());
    }

    #[test]
    fn presence_reports_user_quarantine_when_configured() {
        let yaml = "\
listen_alpha: \"127.0.0.1:0\"\n\
keys:\n  \
  mlkem_pk: /tmp/x\n  \
  mlkem_sk: /tmp/x\n  \
  x25519_pk: /tmp/x\n  \
  x25519_sk: /tmp/x\n\
user_quarantine:\n  \
  ttl_secs: 600\n  \
  max_entries: 4096\n  \
  on_kinds:\n    \
    - per_user_bandwidth_rate\n    \
    - rate_limit\n\
";
        let cfg: ServerConfig = serde_yaml::from_str(yaml).expect("parse");
        let q = cfg.user_quarantine.as_ref().expect("must deserialize");
        assert_eq!(q.ttl_secs, 600);
        assert_eq!(q.max_entries, 4096);
        assert_eq!(q.on_kinds, vec!["per_user_bandwidth_rate", "rate_limit"]);
        let p = cfg.presence();
        assert!(p.user_quarantine);
        assert!(p
            .prometheus()
            .contains(r#"proteus_config_section_active{section="user_quarantine"} 1"#),);
    }

    #[test]
    fn user_quarantine_persistence_path_roundtrips_through_yaml() {
        let yaml = "\
listen_alpha: \"127.0.0.1:0\"\n\
keys:\n  \
  mlkem_pk: /tmp/x\n  \
  mlkem_sk: /tmp/x\n  \
  x25519_pk: /tmp/x\n  \
  x25519_sk: /tmp/x\n\
user_quarantine:\n  \
  ttl_secs: 600\n  \
  max_entries: 4096\n  \
  on_kinds:\n    - per_user_bandwidth_rate\n  \
  persistence_path: /var/lib/proteus/user_quarantine.jsonl\n\
";
        let cfg: ServerConfig = serde_yaml::from_str(yaml).expect("parse");
        let q = cfg.user_quarantine.as_ref().unwrap();
        assert_eq!(
            q.persistence_path.as_deref(),
            Some(std::path::Path::new(
                "/var/lib/proteus/user_quarantine.jsonl"
            )),
        );
    }

    #[test]
    fn user_quarantine_defaults_apply_when_subfields_missing() {
        let yaml = "\
listen_alpha: \"127.0.0.1:0\"\n\
keys:\n  \
  mlkem_pk: /tmp/x\n  \
  mlkem_sk: /tmp/x\n  \
  x25519_pk: /tmp/x\n  \
  x25519_sk: /tmp/x\n\
user_quarantine:\n  \
  on_kinds:\n    \
    - per_user_bandwidth_rate\n\
";
        let cfg: ServerConfig = serde_yaml::from_str(yaml).expect("parse");
        let q = cfg.user_quarantine.as_ref().unwrap();
        assert_eq!(q.ttl_secs, 600); // default
        assert_eq!(q.max_entries, 4096); // default
        assert_eq!(q.on_kinds.len(), 1);
    }

    #[test]
    fn per_user_bandwidth_rate_defaults_apply_when_subfields_missing() {
        // Minimal section: only threshold given, rest from defaults.
        let yaml = "\
listen_alpha: \"127.0.0.1:0\"\n\
keys:\n  \
  mlkem_pk: /tmp/x\n  \
  mlkem_sk: /tmp/x\n  \
  x25519_pk: /tmp/x\n  \
  x25519_sk: /tmp/x\n\
per_user_bandwidth_rate:\n  \
  threshold_mb_per_sec: 200\n\
";
        let cfg: ServerConfig = serde_yaml::from_str(yaml).expect("parse");
        let r = cfg.per_user_bandwidth_rate.as_ref().unwrap();
        assert_eq!(r.threshold_mb_per_sec, 200);
        // Defaults pulled from default_per_user_bw_*.
        assert_eq!(r.window_secs, 30);
        assert_eq!(r.max_users, 4096);
        assert!((r.exit_factor - 0.5).abs() < 1e-12);
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
