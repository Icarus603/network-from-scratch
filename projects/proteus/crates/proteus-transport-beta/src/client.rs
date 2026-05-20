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
use zeroize::Zeroizing;

use crate::error::BetaError;
use crate::ALPN;

/// Build the rustls client config quinn uses. ALPN pinned to
/// `proteus-β-v1`; TLS 1.3 only.
///
/// Per-call (`extra_roots: Vec<CertificateDer>`) path. Kept for
/// back-compat with tests and one-shot tools. Production SOCKS5
/// traffic should go through [`build_client_crypto_cache`] once
/// at startup and call [`BetaClientCrypto::quic_client_config`]
/// per CONNECT — see that helper's docs for the rationale.
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

/// Pre-built β client crypto, cached at startup so the per-
/// CONNECT path doesn't pay for:
///
///   * webpki-roots `extend` clone (~140 system root certs)
///   * `rustls::ClientConfig::builder()` chain (cipher suite
///     enumeration, sig-alg lineup, TLS 1.3 only enforcement)
///   * ALPN Vec allocation
///   * `QuicClientConfig::try_from(crypto)` conversion
///
/// Iter-22: parallels the iter-11 (α `TlsConnector`) and
/// iter-13 (α `HandshakeConfigSource`) caching pattern, but
/// for the β QUIC carrier.
///
/// ## Why this matters
///
/// Pre-iter-22 every SOCKS5 CONNECT that selected β (when
/// the carrier-health tracker said "try β first" — the
/// default on healthy networks) called `make_client_crypto`
/// plus the `QuicClientConfig::try_from` conversion. On a
/// browser opening a page with 50 short-lived HTTP/2
/// connections through β, that's 50× the avoidable rustls
/// setup work per page load.
///
/// The cache only holds the rustls + quinn-crypto layers.
/// `quinn::ClientConfig` itself (which carries the per-
/// connect `TransportConfig` with `max_idle_timeout` and the
/// `PerfProfile`-derived knobs) is built fresh per CONNECT
/// because those values depend on the operator's per-CONNECT
/// timeout setting.
#[derive(Clone)]
pub struct BetaClientCrypto {
    crypto: Arc<rustls::ClientConfig>,
    quic_crypto: Arc<quinn::crypto::rustls::QuicClientConfig>,
}

impl BetaClientCrypto {
    /// Borrow the wrapped quinn `QuicClientConfig`. The caller
    /// passes this to `quinn::ClientConfig::new(...)` per
    /// CONNECT — the `Arc` clone is essentially free, vs the
    /// expensive `try_from` that the per-call path used to do.
    #[must_use]
    pub fn quic_client_config(&self) -> Arc<quinn::crypto::rustls::QuicClientConfig> {
        Arc::clone(&self.quic_crypto)
    }

    /// Borrow the underlying rustls config — useful for tests
    /// or callers that need to introspect the cipher / alpn /
    /// root-store wiring without going through quinn.
    #[must_use]
    pub fn rustls_client_config(&self) -> Arc<rustls::ClientConfig> {
        Arc::clone(&self.crypto)
    }
}

/// Build a cached β client-crypto bundle once at startup.
/// `extra_roots` should be the operator's pinned-CA chain
/// (typically loaded from `tls.trusted_ca` PEM once at
/// process start) plus an empty fallback when not configured.
///
/// Wrap the result in `Arc<BetaClientCrypto>` and stash on
/// `ClientCtx` (mirroring the iter-11 `tls_connector` and
/// iter-13 `hs_config_source` caches). Per-CONNECT callers
/// borrow via `ctx.beta_crypto.as_ref().map(|c|
/// c.quic_client_config())`.
pub fn build_client_crypto_cache(
    extra_roots: Vec<CertificateDer<'static>>,
) -> Result<BetaClientCrypto, BetaError> {
    let crypto = make_client_crypto(extra_roots)?;
    let quic_crypto = Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto.as_ref().clone())
            .map_err(|_| BetaError::CryptoInstall)?,
    );
    Ok(BetaClientCrypto {
        crypto,
        quic_crypto,
    })
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
    /// Server address — retained so `migrate()` can preserve the
    /// destination port for the source-port-evasion heuristic
    /// (USENIX 25 #1) when picking a new local source port.
    server_addr: SocketAddr,
}

impl BetaClientSession {
    /// Trigger a QUIC connection migration — rebinds the local UDP
    /// socket to a fresh source port and lets quinn negotiate the
    /// new path with the server (RFC 9000 §9). All in-flight records
    /// continue without interruption; the session-layer state is
    /// untouched (same AEAD keys, same Proteus session secrets,
    /// same channel binding).
    ///
    /// ## GFW evasion (USENIX Security '25 #4)
    ///
    /// When the GFW detects a forbidden QUIC connection it triggers
    /// a 180-second 5-tuple drop — every packet on
    /// `(src_ip, dst_ip, src_port, dst_port)` is dropped for 3 min.
    /// QUIC connection migration escapes the drop: pick a new
    /// local source port → new 4-tuple → not in the GFW's drop
    /// table → packets flow again.
    ///
    /// This is **opt-in** for now. Automatic migration on a timer
    /// would itself be a fingerprint (no legitimate QUIC client
    /// rebinds periodically). Operators trigger it via the admin
    /// CLI or on a detected throughput collapse.
    ///
    /// Returns the new local socket address on success.
    pub fn migrate(&mut self) -> std::io::Result<SocketAddr> {
        // Reuse the same source-port evasion logic: walk down from
        // dst_port through the [max(1024, dst-7) ..= dst] window,
        // fall back to ephemeral if all candidates are in use.
        let dst_port = self.server_addr.port();
        let new_socket = {
            let lo = dst_port.saturating_sub(7).max(1024);
            let mut last_err: Option<std::io::Error> = None;
            let mut chosen: Option<std::net::UdpSocket> = None;
            for src in (lo..=dst_port).rev() {
                let bind: SocketAddr = match self.server_addr {
                    SocketAddr::V4(_) => format!("0.0.0.0:{src}").parse().unwrap(),
                    SocketAddr::V6(_) => format!("[::]:{src}").parse().unwrap(),
                };
                match std::net::UdpSocket::bind(bind) {
                    Ok(s) => {
                        chosen = Some(s);
                        break;
                    }
                    Err(e) => last_err = Some(e),
                }
            }
            // Fallback to ephemeral if no low-source-port slot is free.
            // We accept this because the alternative is the migration
            // failing entirely — and even ephemeral migration escapes
            // the 180-second 5-tuple drop. The source-port evasion is
            // a best-effort layered on top.
            if chosen.is_none() {
                let fallback: SocketAddr = match self.server_addr {
                    SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
                    SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
                };
                chosen = Some(std::net::UdpSocket::bind(fallback)?);
            }
            let s = chosen.ok_or_else(|| {
                last_err.unwrap_or_else(|| std::io::Error::other("migrate: no socket bound"))
            })?;
            // Iter-61: bump SO_RCVBUF + SO_SNDBUF on the migration
            // socket too. Without this, every migration would
            // silently collapse throughput back to the OS default.
            // Best-effort; on clamp we log but proceed.
            let _ = crate::apply_udp_socket_buffers(&s, crate::DEFAULT_UDP_SOCKET_BUFFER_BYTES);
            s.set_nonblocking(true)?;
            s
        };
        self.endpoint.rebind(new_socket)?;
        self.endpoint.local_addr()
    }
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
    connect_with_timeout_and_perf(
        server_name,
        server_addr,
        extra_roots,
        cfg,
        connect_timeout,
        crate::PerfProfile::default(),
    )
    .await
}

/// Like `connect_with_timeout` but takes an explicit `PerfProfile`.
/// Use this to flip on UDP-layer padding
/// (`pad_quic_datagrams_to_mtu = true`) for anti-censorship
/// deployments, or to bump `initial_mtu` more aggressively.
pub async fn connect_with_timeout_and_perf(
    server_name: &str,
    server_addr: SocketAddr,
    extra_roots: Vec<CertificateDer<'static>>,
    cfg: ClientConfig,
    connect_timeout: std::time::Duration,
    perf: crate::PerfProfile,
) -> Result<BetaClientSession, BetaError> {
    if !matches!(cfg.profile_hint, ProfileHint::Beta) {
        return Err(BetaError::AlpnMismatch(
            vec![cfg.profile_hint.to_byte()],
            vec![ProfileHint::Beta.to_byte()],
        ));
    }
    // Per-call fallback path. Production SOCKS5 traffic now uses
    // `connect_with_timeout_perf_cached_crypto` so the rustls
    // + quinn-crypto setup runs ONCE at startup, not per CONNECT.
    let crypto = build_client_crypto_cache(extra_roots)?;
    connect_with_timeout_perf_cached_crypto(
        server_name,
        server_addr,
        &crypto,
        cfg,
        connect_timeout,
        perf,
    )
    .await
}

/// Like [`connect_with_timeout_and_perf`] but takes a pre-
/// built [`BetaClientCrypto`] cache (built once at startup via
/// [`build_client_crypto_cache`]) so the per-CONNECT path
/// doesn't pay for the webpki-roots extend + rustls config
/// build + `QuicClientConfig::try_from` conversion on every
/// SOCKS5 CONNECT. Iter-22 production hot path.
pub async fn connect_with_timeout_perf_cached_crypto(
    server_name: &str,
    server_addr: SocketAddr,
    crypto: &BetaClientCrypto,
    cfg: ClientConfig,
    connect_timeout: std::time::Duration,
    perf: crate::PerfProfile,
) -> Result<BetaClientSession, BetaError> {
    if !matches!(cfg.profile_hint, ProfileHint::Beta) {
        return Err(BetaError::AlpnMismatch(
            vec![cfg.profile_hint.to_byte()],
            vec![ProfileHint::Beta.to_byte()],
        ));
    }
    let crypto = crypto.quic_client_config();
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
    crate::apply_perf_tuning_with(&mut transport, perf);
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
    // ### Why the first byte is shaped, not pure random
    //
    // A fully random 16-byte payload has ~50 % chance of setting
    // the long-header bit (`0x80`) — which is the GFW inspector's
    // entry condition. With a non-trivial probability the random
    // bytes that follow happen to encode `(version=0x00000001,
    // dcil≤20, scil≤20)`, at which point the inspector treats the
    // noise itself as a parseable QUIC v1 Initial and *will* try
    // to extract SNI from it. The inspector then fails (random
    // payload doesn't AEAD-decrypt), but the flow has now been
    // FLAGGED, and the inspector's next-packet policy is unclear
    // — at minimum we burn the evasion budget on a payload that
    // wasn't even ours.
    //
    // Defense: force the first byte's long-header bit (0x80) to
    // 0. This makes the byte look like a SHORT-header QUIC packet
    // — and the GFW's Initial-only inspector explicitly skips
    // short-header packets (they cannot carry SNI; SNI lives in
    // the CRYPTO frame inside the Initial).
    //
    // ### Why bytes 0–5 are *printable* ASCII, not random
    //
    // A second, *independent* GFW classifier (Wu et al., USENIX
    // Security 2023, "How the Great Firewall of China Detects and
    // Blocks Fully Encrypted Traffic") flags any connection whose
    // **first 6 bytes** are not "printable ASCII" as a fully-
    // encrypted-traffic suspect — and the proxy-block heuristic
    // additionally fires when ≥70 % of bytes are non-printable.
    // The rule is a whitelist exception: if the first 6 bytes are
    // all printable (letters / digits / spaces / common punctuation,
    // ASCII 0x20–0x7E), the connection is exempt regardless of
    // entropy elsewhere. This is documented at GFW.report
    // (`/blog/ss_advise/en/`) and Geneva
    // (`geneva.cs.umd.edu/posts/fully-encrypted-traffic/`).
    //
    // 16 fully random bytes hit ~94 % non-printable density and
    // trip both heuristics. We therefore split the 16-byte noise:
    //   - bytes 0–5:  printable ASCII (random within 0x20–0x7E,
    //                 with byte 0 ALSO satisfying the short-header
    //                 constraint via the 0x20–0x7E range which has
    //                 bit 0x80 already cleared — every printable
    //                 ASCII byte is by definition < 0x80)
    //   - bytes 6–15: fully random (10 bytes; well under the 70 %
    //                 non-printable threshold for the 16-byte total
    //                 — even worst-case all-10-non-printable gives
    //                 10/16 = 62.5 %, under the 70 % wall)
    //
    // This single change satisfies USENIX 25 #2 (prefix-noise
    // before QUIC Initial, byte 0 cleared) AND USENIX 23 rules
    // 1 + 3 (printable-byte heuristic) simultaneously. See
    // `qa/2026-05-17-gfw-2026-q1q2-threat-intel.md` main line 7.
    //
    // Payload: 16 bytes total. Bytes 0–5 in 0x20..=0x7E (printable
    // ASCII); bytes 6–15 fully random.
    {
        let mut noise = [0u8; 16];
        use rand_core::RngCore;
        rand_core::OsRng.fill_bytes(&mut noise);
        // Shape bytes 0–5 to printable ASCII (0x20–0x7E). Mapping
        // a random byte into 95 codepoints biases (256 mod 95 = 66
        // codepoints get one extra) but the bias is well below any
        // meaningful adversary distinguisher and is irrelevant for
        // GFW heuristics that only care about printable vs. not.
        // The short-header-bit constraint (byte 0 & 0x80 == 0) is
        // automatically satisfied because 0x20..=0x7E ⊂ [0, 0x7F].
        for byte in noise.iter_mut().take(6) {
            *byte = 0x20 + (*byte % 95); // 0x20..=0x7E
        }
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
    // Iter-61: bump SO_RCVBUF + SO_SNDBUF before quinn takes
    // ownership. Symmetric with the server-side change in
    // server.rs. The OS default (Linux ~212 KiB) caps single-
    // stream throughput on long-fat-pipe paths well below
    // Hy2 / TUIC5; 7 MiB sustains 1 Gbit/s at ~500 ms RTT.
    let buf_outcome =
        crate::apply_udp_socket_buffers(&std_socket, crate::DEFAULT_UDP_SOCKET_BUFFER_BYTES)?;
    if !buf_outcome.met_target {
        tracing::warn!(
            requested_bytes = buf_outcome.requested,
            achieved_recv_bytes = buf_outcome.achieved_recv,
            achieved_send_bytes = buf_outcome.achieved_send,
            "β client UDP socket buffers were clamped by the kernel — \
             single-stream throughput on long-fat-pipe paths may be capped \
             below 1 Gbit/s. Raise `sysctl -w net.core.rmem_max=8388608 net.core.wmem_max=8388608` \
             on Linux, or `sysctl -w kern.ipc.maxsockbuf=16777216` on macOS."
        );
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
    // Iter-174: wrap the QUIC exporter output in Zeroizing —
    // same defense as the α-profile fix in the matching iteration.
    // The QUIC TLS exporter is the channel-binding tag the inner
    // Proteus handshake commits to via its Finished MAC chain;
    // recovery via stack-image grab → MITM-binding bypass.
    let mut binding = Zeroizing::new([0u8; CHANNEL_BINDING_LEN]);
    conn.export_keying_material(&mut binding[..], TLS_EXPORTER_LABEL, b"")
        .map_err(|_| {
            BetaError::Io(std::io::Error::other(
                "β: QUIC exporter unavailable post-handshake",
            ))
        })?;

    let (send, recv) = conn.open_bi().await?;
    let session = handshake_over_split_bound(recv, send, &cfg, Some(*binding)).await?;
    Ok(BetaClientSession {
        session,
        connection: conn,
        endpoint,
        server_addr,
    })
}
