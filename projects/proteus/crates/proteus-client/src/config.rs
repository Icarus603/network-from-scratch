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

#[derive(Debug, Deserialize)]
pub struct ClientConfig {
    pub server_endpoint: String,
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

    pub fn build_handshake_config(&self) -> Result<client::ClientConfig, ConfigError> {
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

        let sk_bytes = decode_b64_or_raw(&std::fs::read(&self.keys.client_ed25519_sk)?);
        if sk_bytes.len() != 32 {
            return Err(ConfigError::BadKey(
                "client_ed25519_sk must be 32 bytes (raw seed)",
            ));
        }
        let sk_arr: [u8; 32] = sk_bytes.as_slice().try_into().unwrap();
        let client_id_sk = ed25519_dalek::SigningKey::from_bytes(&sk_arr);

        let user_id = encode_user_id(&self.user_id);

        // RNG seed not needed here; the OS RNG handles per-handshake nonces.
        let _ = OsRng;

        Ok(client::ClientConfig {
            server_mlkem_pk_bytes,
            server_x25519_pub,
            server_pq_fingerprint,
            client_id_sk,
            user_id,
            pow_difficulty: self.pow_difficulty.unwrap_or(0),
            profile_hint: proteus_transport_alpha::ProfileHint::Alpha,
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
