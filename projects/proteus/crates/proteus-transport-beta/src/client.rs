//! β-profile QUIC client.
//!
//! Dials the server over QUIC + TLS 1.3 + `proteus-β-v1` ALPN, opens
//! ONE bidirectional stream, and drives the standard Proteus
//! handshake from `proteus-transport-alpha` on it.

use std::net::SocketAddr;
use std::sync::Arc;

use proteus_transport_alpha::client::{
    handshake_over_split_bound, ClientConfig, CHANNEL_BINDING_LEN, TLS_EXPORTER_LABEL,
};
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

    // Bind a UDP socket — try GFW-evasion source-port choice first.
    //
    // ## GFW 2026 QUIC SNI Inspection evasion (USENIX Security '25)
    //
    // The Great Firewall of China deployed QUIC SNI inspection in
    // early 2026. The "Exposing and Circumventing SNI-based QUIC
    // Censorship" paper (Zohaib et al., USENIX Security 2025)
    // documents a critical optimization in the GFW's QUIC inspector:
    //
    //     "The GFW does not block connections where the source port
    //      number is less than or equal to the destination port
    //      number."
    //
    // This single heuristic filters ~70% of UDP traffic from
    // inspection while still catching >90% of standard QUIC client
    // Initials (which typically use source ports in the 49152-65535
    // ephemeral range, all > common destination ports like 443).
    //
    // We exploit it by binding our client socket to a source port
    // **equal to** the destination port. No privileged port required
    // (we don't go below 1024); just pick the same port number the
    // server listens on, and the GFW's heuristic skips inspection
    // entirely. On port conflict (port already in use) we walk down
    // a small window and finally fall back to ephemeral.
    let bind_attempts: Vec<SocketAddr> = {
        let mut out = Vec::with_capacity(8);
        let dst_port = server_addr.port();
        // Try N candidate source ports in the [max(1024, dst_port-7) ..= dst_port] range.
        // Source ports < 1024 require CAP_NET_BIND_SERVICE / root on
        // Linux + macOS; skip them.
        let lo = dst_port.saturating_sub(7).max(1024);
        for src in (lo..=dst_port).rev() {
            let s: SocketAddr = match server_addr {
                SocketAddr::V4(_) => format!("0.0.0.0:{src}").parse().unwrap(),
                SocketAddr::V6(_) => format!("[::]:{src}").parse().unwrap(),
            };
            out.push(s);
        }
        // Last-resort ephemeral fallback so we don't fail to dial
        // when every low-source-port slot is busy.
        let fallback: SocketAddr = match server_addr {
            SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
            SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
        };
        out.push(fallback);
        out
    };

    // Bind a std::net::UdpSocket ourselves so we can (a) send a
    // prefix-noise datagram before quinn writes its QUIC Initial,
    // and (b) hand the same socket to quinn::Endpoint::new() —
    // which keeps the source port unchanged for the subsequent QUIC
    // handshake.
    let std_socket = {
        let mut last_err: Option<std::io::Error> = None;
        let mut chosen: Option<std::net::UdpSocket> = None;
        for bind in &bind_attempts {
            match std::net::UdpSocket::bind(bind) {
                Ok(s) => {
                    chosen = Some(s);
                    break;
                }
                Err(e) => last_err = Some(e),
            }
        }
        chosen.ok_or_else(|| {
            BetaError::Io(
                last_err
                    .unwrap_or_else(|| std::io::Error::other("no UDP source port could be bound")),
            )
        })?
    };

    // ## GFW-evasion: prefix-noise datagram (USENIX Security '25 #2)
    //
    // The same USENIX 25 paper documents another optimization in the
    // GFW's QUIC inspector: it only inspects the FIRST UDP datagram
    // in a flow (`(src_ip, dst_ip, src_port, dst_port)` 4-tuple, 60-s
    // timeout). By sending one random-payload datagram BEFORE quinn
    // writes the QUIC Initial, the GFW classifies the first datagram
    // as the "QUIC Initial" — finds no QUIC header, gives up — then
    // marks the flow's first-packet quota as consumed. Our actual
    // QUIC Initial arrives as the SECOND datagram on that 4-tuple
    // and never gets inspected.
    //
    // Payload: 16 random bytes (any garbage works — the GFW just
    // fails to parse it as a QUIC Initial header and stops looking).
    // 16 bytes is short enough that the prefix doesn't itself look
    // like meaningful traffic, long enough that any UDP packet under
    // it would be too tiny to be a legitimate protocol (most UDP
    // payloads are ≥20 bytes).
    {
        let mut noise = [0u8; 16];
        use rand_core::RngCore;
        rand_core::OsRng.fill_bytes(&mut noise);
        // Best-effort: if this send fails (e.g. ICMP unreachable on
        // a closed UDP path), we ignore and let quinn do its
        // own retransmit. The evasion is a probabilistic optimization
        // win, not a hard correctness requirement.
        //
        // We send while the socket is still in blocking mode so the
        // datagram lands on the wire BEFORE quinn::Endpoint::new
        // takes ownership and writes its QUIC Initial. The send is
        // a single syscall and won't block in practice (UDP sndbuf
        // accepts it immediately).
        let _ = std_socket.send_to(&noise, server_addr);
    }
    // Tokio's `UdpSocket::from_std` (called by quinn's runtime
    // adapter) requires the underlying std socket to be in
    // non-blocking mode.
    std_socket.set_nonblocking(true)?;

    let runtime = quinn::default_runtime()
        .ok_or_else(|| BetaError::Io(std::io::Error::other("no async runtime found")))?;
    let mut endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None, // client-only, no ServerConfig
        std_socket,
        runtime,
    )?;
    endpoint.set_default_client_config(client_cfg);

    let conn = endpoint.connect(server_addr, server_name)?.await?;
    info!(remote = %conn.remote_address(), "β QUIC handshake complete");

    // ----- TLS channel binding (RFC 5705 / 9266) -----
    // Mirror the α-profile binding (commit 906ab22): extract the QUIC
    // outer-TLS exporter and mix it into the inner Proteus transcript.
    // A MITM bridging two distinct QUIC sessions sees different
    // exporters on each side; the inner Finished MAC cannot be
    // relayed → handshake aborts. quinn-proto uses a different
    // exporter shape than rustls (always passes Some(context)) so
    // α and β bindings are deliberately not interchangeable.
    let mut binding = [0u8; CHANNEL_BINDING_LEN];
    conn.export_keying_material(&mut binding[..], TLS_EXPORTER_LABEL, b"")
        .map_err(|_| {
            BetaError::Io(std::io::Error::other(
                "β: QUIC exporter unavailable post-handshake",
            ))
        })?;

    let (send, recv) = conn.open_bi().await?;
    let session = handshake_over_split_bound(recv, send, &cfg, Some(binding)).await?;
    Ok(BetaClientSession {
        session,
        connection: conn,
        endpoint,
    })
}
