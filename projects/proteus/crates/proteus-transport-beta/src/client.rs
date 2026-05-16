//! β-profile QUIC client.
//!
//! Dials the server over QUIC + TLS 1.3 + `proteus-β-v1` ALPN, opens
//! ONE bidirectional stream, and drives the standard Proteus
//! handshake from `proteus-transport-alpha` on it.

use std::net::SocketAddr;
use std::sync::Arc;

use proteus_transport_alpha::client::{handshake_over_split, ClientConfig};
use proteus_transport_alpha::session::AlphaSession;
use proteus_transport_alpha::ProfileHint;
use rustls::pki_types::CertificateDer;
use tracing::info;

use crate::error::BetaError;
use crate::ALPN;

/// Build the rustls client config quinn uses. ALPN pinned to
/// `proteus-β-v1`; TLS 1.3 only.
pub fn make_client_crypto(
    extra_roots: Vec<CertificateDer<'static>>,
) -> Result<Arc<rustls::ClientConfig>, BetaError> {
    install_default_crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    for cert in extra_roots {
        roots.add(cert)?;
    }
    // Always seed with webpki-roots so real-CA-signed certs work.
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut client_cfg =
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(roots)
            .with_no_client_auth();
    client_cfg.alpn_protocols = vec![ALPN.to_vec()];
    Ok(Arc::new(client_cfg))
}

fn install_default_crypto_provider() {
    use std::sync::Once;
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// A live β-profile client connection — holds the quinn endpoint
/// and connection alongside the Proteus session. Caller MUST keep
/// this struct alive for the lifetime of the session; dropping it
/// closes the underlying QUIC connection.
pub struct BetaClientSession {
    /// The Proteus session. Caller drives this for record I/O.
    pub session: AlphaSession<quinn::RecvStream, quinn::SendStream>,
    /// The live QUIC connection. Held for lifetime management; the
    /// caller doesn't usually touch it.
    pub connection: quinn::Connection,
    /// The quinn endpoint. Same — held to keep the UDP socket open.
    pub endpoint: quinn::Endpoint,
}

/// Open a β QUIC connection to `target`, run the Proteus handshake,
/// return a [`BetaClientSession`] wrapper that keeps the endpoint
/// and connection alive alongside the session.
///
/// Equivalent to [`connect_with_timeout`] using the default
/// 60-second idle timeout. Prefer the explicit-timeout variant when
/// the caller wants fast-fail dial semantics (e.g. dual-stack
/// happy-eyeballs).
pub async fn connect(
    server_name: &str,
    server_addr: SocketAddr,
    extra_roots: Vec<CertificateDer<'static>>,
    cfg: ClientConfig,
) -> Result<BetaClientSession, BetaError> {
    connect_with_timeout(
        server_name,
        server_addr,
        extra_roots,
        cfg,
        std::time::Duration::from_secs(60),
    )
    .await
}

/// Like [`connect`] but takes an explicit `connect_timeout` that
/// bounds **both** the QUIC handshake and the post-handshake
/// idle-timeout behavior. This is the right entry point for
/// dual-stack happy-eyeballs:
///
///   - `connect_timeout = 3 s` for a fast-fail try-β dial. If the
///     peer's UDP is firewalled (no ICMP feedback), quinn's
///     handshake aborts within ~2× the configured idle window
///     instead of waiting for the default 60-second timeout.
///   - The outer `tokio::time::timeout` on the caller's side still
///     applies; this just makes quinn give up on its own first.
///
/// `server_name` is the SNI string (must match the server cert's
/// SAN). `cfg` carries the client's Proteus identity; the caller
/// MUST set `cfg.profile_hint = ProfileHint::Beta` (we enforce it
/// here as a fail-fast safeguard).
pub async fn connect_with_timeout(
    server_name: &str,
    server_addr: SocketAddr,
    extra_roots: Vec<CertificateDer<'static>>,
    cfg: ClientConfig,
    connect_timeout: std::time::Duration,
) -> Result<BetaClientSession, BetaError> {
    if !matches!(cfg.profile_hint, ProfileHint::Beta) {
        return Err(BetaError::AlpnMismatch(
            vec![cfg.profile_hint.to_byte()],
            vec![ProfileHint::Beta.to_byte()],
        ));
    }
    let crypto = make_client_crypto(extra_roots)?;
    let crypto = Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto.as_ref().clone())
            .map_err(|_| BetaError::CryptoInstall)?,
    );
    let mut client_cfg = quinn::ClientConfig::new(crypto);
    let mut transport = quinn::TransportConfig::default();
    // The idle timeout doubles as quinn's effective handshake
    // timeout — its internal abort fires when no progress happens
    // for `idle_timeout` and during a stalled handshake there's no
    // progress at all. Clamp to the caller's connect_timeout so a
    // dead UDP peer doesn't hang for the default 60 s.
    transport.max_idle_timeout(Some(connect_timeout.try_into().unwrap_or_else(|_| {
        // Saturate to ~10 min if the caller supplied something insane.
        std::time::Duration::from_secs(600).try_into().unwrap()
    })));
    crate::apply_perf_tuning(&mut transport);
    client_cfg.transport_config(Arc::new(transport));

    // Bind an ephemeral UDP socket and connect outbound.
    let bind: SocketAddr = match server_addr {
        SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
    };
    let mut endpoint = quinn::Endpoint::client(bind)?;
    endpoint.set_default_client_config(client_cfg);

    let conn = endpoint.connect(server_addr, server_name)?.await?;
    info!(remote = %conn.remote_address(), "β QUIC handshake complete");

    let (send, recv) = conn.open_bi().await?;
    let session = handshake_over_split(recv, send, &cfg).await?;
    Ok(BetaClientSession {
        session,
        connection: conn,
        endpoint,
    })
}
