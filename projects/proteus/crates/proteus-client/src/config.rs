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
