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
    pub keys: KeysCfg,
    #[serde(default)]
    pub client_allowlist: Vec<ClientCfg>,
    /// Cover URL to forward to on auth failure (spec §7.5).
    /// e.g. `"www.cloudflare.com:443"`.
    #[serde(default)]
    pub cover_endpoint: Option<String>,
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
