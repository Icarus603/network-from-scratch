//! β-profile QUIC server.
//!
//! Listens on UDP, runs QUIC + TLS 1.3 + `proteus-β-v1` ALPN, then
//! for each incoming bidirectional stream invokes the standard
//! Proteus handshake from `proteus-transport-alpha`.

use std::net::SocketAddr;
use std::sync::Arc;

use proteus_transport_alpha::client::{CHANNEL_BINDING_LEN, TLS_EXPORTER_LABEL};
use proteus_transport_alpha::server::{
    admission_ok, handshake_over_split_bound, user_admission_ok, ConnGate, ServerCtx,
};
use proteus_transport_alpha::session::AlphaSession;

/// Record one β-profile "would have cover-forwarded" event in the
/// probe-anomaly detector (if installed). The β carrier has no raw
/// cover-forward stream (QUIC handshake already completed by the
/// time we discover the auth failure — there's no plaintext TCP
/// byte stream below it to splice), so the "close + drop" branches
/// are the β-side equivalent of α's cover-forward triggers. From
/// the operator's POV the operational signal is the same: this
/// /24 keeps hitting the failure path, ALERT.
///
/// On the call that crosses the per-/24 threshold, emits a
/// structured WARN log + bumps `probe_anomalies_fired`. Pure CPU.
fn record_probe_anomaly(ctx: &Arc<ServerCtx>, peer: &SocketAddr) {
    let Some(detector) = ctx.probe_anomaly() else {
        return;
    };
    let now = std::time::Instant::now();
    if detector.record_at(peer.ip(), now).is_some() {
        tracing::warn!(
            peer = %peer,
            carrier = "β",
            prefix = match peer.ip() {
                std::net::IpAddr::V4(_) => "/24",
                std::net::IpAddr::V6(_) => "/48",
            },
            "probe-anomaly: source-IP prefix repeatedly tripping β failure path — \
             likely active probing (threat-intel main line 4)"
        );
        if let Some(m) = ctx.metrics() {
            m.probe_anomalies_fired
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        // Auto-deny: same policy as α. The list silently no-ops
        // when not configured. Subsequent QUIC connections from
        // this /24 short-circuit at `admission_ok` (which the β
        // accept loop calls 1:1 with α).
        if let Some(auto_deny) = ctx.auto_deny() {
            if auto_deny.insert(peer.ip(), now) {
                tracing::warn!(
                    peer = %peer,
                    carrier = "β",
                    ttl_secs = auto_deny.ttl().as_secs(),
                    "auto-deny: prefix added to TTL-bounded deny list"
                );
            }
        }
    }
}
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

use crate::error::BetaError;
use crate::ALPN;

/// Build the rustls server config we hand to quinn. Pins TLS 1.3,
/// ALPN = `proteus-β-v1`, no client auth.
fn make_server_crypto(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<rustls::ServerConfig>, BetaError> {
    install_default_crypto_provider()?;
    let mut server_cfg =
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)?;
    server_cfg.alpn_protocols = vec![ALPN.to_vec()];
    Ok(Arc::new(server_cfg))
}

fn install_default_crypto_provider() -> Result<(), BetaError> {
    // quinn doesn't auto-install; the first install wins, subsequent
    // attempts return an error we silently absorb.
    use std::sync::Once;
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
    Ok(())
}

/// Build a quinn server endpoint bound to `addr` with the bundled
/// rustls/TLS 1.3 config. Production deploys should reuse an
/// already-bound UDP socket via [`Endpoint::new`] for SO_REUSEPORT.
pub fn make_endpoint(
    addr: SocketAddr,
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<quinn::Endpoint, BetaError> {
    make_endpoint_with_perf(addr, cert_chain, key, crate::PerfProfile::default())
}

/// Like `make_endpoint` but takes an explicit `PerfProfile`.
///
/// Use this when the operator wants to flip on UDP-layer padding
/// (`pad_quic_datagrams_to_mtu = true`) for anti-censorship deployments,
/// or to bump `initial_mtu` more aggressively on paths known to
/// support Ethernet MTU. The default profile matches what
/// `make_endpoint` ships.
pub fn make_endpoint_with_perf(
    addr: SocketAddr,
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    perf: crate::PerfProfile,
) -> Result<quinn::Endpoint, BetaError> {
    let crypto = make_server_crypto(cert_chain, key)?;
    let crypto = Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(crypto.as_ref().clone())
            .map_err(|_| BetaError::CryptoInstall)?,
    );
    let mut server_cfg = quinn::ServerConfig::with_crypto(crypto);
    // A warm carrier may serve concurrent SOCKS CONNECTs. The
    // process-wide β-session semaphore in ServerCtx is the hard
    // memory bound; this transport parameter is the independent
    // per-carrier fan-out bound.
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(quinn::VarInt::from_u32(64))
        // 60s idle is the spec default; operators override via
        // server.yaml.
        .max_idle_timeout(Some(std::time::Duration::from_secs(60).try_into().unwrap()));
    crate::apply_perf_tuning_with(&mut transport, perf);
    server_cfg.transport_config(Arc::new(transport));

    // Iter-61: bind UDP ourselves so we can tune SO_RCVBUF +
    // SO_SNDBUF BEFORE quinn takes ownership. Pre-iter-61 we
    // called quinn::Endpoint::server(cfg, addr) which used the
    // OS default (~212 KiB on Linux) — caps single-stream
    // throughput on long-fat-pipe paths well below Hy2 / TUIC5.
    let std_sock = std::net::UdpSocket::bind(addr)?;
    let buf_outcome =
        crate::apply_udp_socket_buffers(&std_sock, crate::DEFAULT_UDP_SOCKET_BUFFER_BYTES)?;
    if !buf_outcome.met_target {
        tracing::warn!(
            requested_bytes = buf_outcome.requested,
            achieved_recv_bytes = buf_outcome.achieved_recv,
            achieved_send_bytes = buf_outcome.achieved_send,
            "β server UDP socket buffers were clamped by the kernel — \
             single-stream throughput on long-fat-pipe paths may be capped \
             below 1 Gbit/s. Raise `sysctl -w net.core.rmem_max=8388608 net.core.wmem_max=8388608` \
             on Linux, or `sysctl -w kern.ipc.maxsockbuf=16777216` on macOS."
        );
    }
    let runtime = quinn::default_runtime()
        .ok_or_else(|| BetaError::Io(std::io::Error::other("no async runtime found")))?;
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_cfg),
        std_sock,
        runtime,
    )?;
    Ok(endpoint)
}

/// Accept loop. Each QUIC carrier can host multiple independently
/// authenticated Proteus sessions. Every accepted stream passes the
/// canonical admission pipeline, a distinct global β-session cap,
/// a stream-specific TLS-exporter binding, and the full inner
/// handshake before reaching `handler`.
pub async fn serve<F, Fut>(
    endpoint: quinn::Endpoint,
    ctx: Arc<ServerCtx>,
    handler: F,
) -> Result<(), BetaError>
where
    F: Fn(AlphaSession<quinn::RecvStream, quinn::SendStream>) -> Fut
        + Send
        + Sync
        + Clone
        + 'static,
    Fut: std::future::Future<Output = ()> + Send,
{
    info!(local = ?endpoint.local_addr().ok(), "β-profile listener bound");
    while let Some(incoming) = endpoint.accept().await {
        // ---- Pre-QUIC-handshake auto-deny short-circuit ----
        //
        // The accept() future resolves to a `quinn::Incoming` BEFORE
        // the QUIC handshake completes. `Incoming::remote_address()`
        // is available immediately (the UDP datagram source). When
        // the operator has opted into the auto-deny loop AND this
        // /24 is currently on the list, drop the incoming via
        // `Incoming::ignore()` — quinn sends NO response packet at
        // all, so the prober's wire view looks like the server
        // never existed (no QUIC Initial reply, no CONNECTION_CLOSE,
        // no nothing). Saves the full TLS+QUIC handshake CPU cost
        // on every probe attempt from a known-bad prefix.
        //
        // We DO NOT call full `admission_ok` here — that gate
        // includes the per-IP rate limiter, which we want to fire
        // against the post-QUIC-handshake stage so its metrics
        // accurately reflect "QUIC handshake completed but admission
        // rejected" vs "QUIC packet dropped pre-handshake". Same
        // discipline as the firewall: only the auto-deny path is
        // cheap enough to be worth running pre-handshake.
        let remote_pre = incoming.remote_address();
        if let Some(auto_deny) = ctx.auto_deny() {
            if auto_deny.is_denied(remote_pre.ip(), std::time::Instant::now()) {
                tracing::debug!(
                    peer = %remote_pre,
                    carrier = "β",
                    "auto-deny hit pre-QUIC-handshake; ignoring incoming (no wire response)"
                );
                if let Some(m) = ctx.metrics() {
                    m.firewall_denied
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                incoming.ignore();
                continue;
            }
        }

        let ctx = Arc::clone(&ctx);
        let handler = handler.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    let remote = conn.remote_address();
                    debug!(remote = %remote, "β QUIC connection accepted");

                    // The outer max_connections semaphore limits live
                    // QUIC carriers, including authenticated peers that
                    // never open a stream. A separate equal-capacity
                    // semaphore below limits live inner sessions.
                    let _carrier_permit = match ctx.try_acquire_connection() {
                        ConnGate::Unbounded => None,
                        ConnGate::Allowed(p) => Some(p),
                        ConnGate::Rejected => {
                            tracing::warn!(
                                peer = %remote,
                                "β: max_connections cap reached; closing"
                            );
                            if let Some(m) = ctx.metrics() {
                                m.firewall_denied
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                            record_probe_anomaly(&ctx, &remote);
                            conn.close(0u32.into(), b"");
                            return;
                        }
                    };

                    // ALPN sanity (rustls already enforced it, but
                    // confirm for log clarity).
                    if let Some(p) = conn.handshake_data().and_then(|d| {
                        d.downcast::<quinn::crypto::rustls::HandshakeData>()
                            .ok()
                            .and_then(|h| h.protocol)
                    }) {
                        if p != ALPN {
                            warn!(alpn = ?p, "β: unexpected ALPN; closing");
                            record_probe_anomaly(&ctx, &remote);
                            conn.close(0u32.into(), b"");
                            return;
                        }
                    }

                    // A carrier earns warm-idle privileges only after
                    // one complete, admitted inner handshake. Before
                    // that point, opening QUIC and sending no stream is
                    // still a slowloris/probe event bounded by the
                    // configured handshake deadline.
                    let authenticated = Arc::new(std::sync::atomic::AtomicBool::new(false));
                    let authenticated_notify = Arc::new(tokio::sync::Notify::new());

                    // A reusable carrier waits on accept_bi until its
                    // QUIC idle timeout or peer close. Applying the
                    // short handshake deadline to this wait would kill
                    // healthy warm carriers between user requests.
                    loop {
                        let accepted = if authenticated.load(std::sync::atomic::Ordering::Acquire) {
                            conn.accept_bi().await
                        } else {
                            let notified = authenticated_notify.notified();
                            tokio::pin!(notified);
                            if authenticated.load(std::sync::atomic::Ordering::Acquire) {
                                continue;
                            }
                            tokio::select! {
                                result = conn.accept_bi() => result,
                                () = &mut notified => continue,
                                () = tokio::time::sleep(ctx.handshake_deadline()) => {
                                    if authenticated.load(std::sync::atomic::Ordering::Acquire) {
                                        continue;
                                    }
                                    warn!(
                                        remote = %remote,
                                        "β: unauthenticated carrier opened no stream before deadline"
                                    );
                                    if let Some(m) = ctx.metrics() {
                                        m.handshake_timeouts.fetch_add(
                                            1,
                                            std::sync::atomic::Ordering::Relaxed,
                                        );
                                    }
                                    record_probe_anomaly(&ctx, &remote);
                                    conn.close(0u32.into(), b"");
                                    return;
                                }
                            }
                        };
                        let (send, recv) = match accepted {
                            Ok(pair) => pair,
                            Err(quinn::ConnectionError::LocallyClosed) => return,
                            Err(e) => {
                                warn!(
                                    remote = %remote,
                                    error = %e,
                                    error_debug = ?e,
                                    "β carrier closed"
                                );
                                return;
                            }
                        };
                        debug_assert_eq!(send.id(), recv.id());
                        let stream_id = send.id();

                        // Admission is per inner handshake, not merely
                        // per carrier. Otherwise an authenticated QUIC
                        // peer could open streams indefinitely and drain
                        // ML-KEM work after paying one rate-limit token.
                        if !admission_ok(&ctx, &remote) {
                            record_probe_anomaly(&ctx, &remote);
                            conn.close(0u32.into(), b"");
                            return;
                        }

                        let session_permit = match ctx.try_acquire_beta_session() {
                            ConnGate::Unbounded => None,
                            ConnGate::Allowed(p) => Some(p),
                            ConnGate::Rejected => {
                                warn!(
                                    peer = %remote,
                                    "β: global inner-session cap reached; closing carrier"
                                );
                                if let Some(m) = ctx.metrics() {
                                    m.firewall_denied
                                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                }
                                conn.close(0u32.into(), b"");
                                return;
                            }
                        };

                        let stream_ctx = Arc::clone(&ctx);
                        let stream_handler = handler.clone();
                        let stream_conn = conn.clone();
                        let stream_authenticated = Arc::clone(&authenticated);
                        let stream_authenticated_notify = Arc::clone(&authenticated_notify);
                        tokio::spawn(async move {
                            // Hold through handshake + relay handler.
                            let _session_permit = session_permit;

                            let context = crate::stream_exporter_context(stream_id);
                            let mut binding = Zeroizing::new([0u8; CHANNEL_BINDING_LEN]);
                            if stream_conn
                                .export_keying_material(
                                    &mut binding[..],
                                    TLS_EXPORTER_LABEL,
                                    &context,
                                )
                                .is_err()
                            {
                                warn!(
                                    remote = %remote,
                                    stream = %stream_id,
                                    "β: TLS exporter unavailable for stream; closing"
                                );
                                record_probe_anomaly(&stream_ctx, &remote);
                                stream_conn.close(0u32.into(), b"");
                                return;
                            }

                            let hs_start = std::time::Instant::now();
                            let hs_fut =
                                handshake_over_split_bound(recv, send, &stream_ctx, Some(*binding));
                            let session =
                                match tokio::time::timeout(stream_ctx.handshake_deadline(), hs_fut)
                                    .await
                                {
                                    Ok(Ok(s)) => s
                                        .with_peer_addr(remote)
                                        .with_handshake_duration(hs_start.elapsed()),
                                    Ok(Err(e)) => {
                                        warn!(
                                            remote = %remote,
                                            stream = %stream_id,
                                            error = %e,
                                            "β: Proteus stream handshake failed"
                                        );
                                        record_probe_anomaly(&stream_ctx, &remote);
                                        stream_conn.close(0u32.into(), b"");
                                        return;
                                    }
                                    Err(_) => {
                                        warn!(
                                            remote = %remote,
                                            stream = %stream_id,
                                            "β: Proteus stream handshake exceeded deadline"
                                        );
                                        if let Some(m) = stream_ctx.metrics() {
                                            m.handshake_timeouts
                                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                        }
                                        record_probe_anomaly(&stream_ctx, &remote);
                                        stream_conn.close(0u32.into(), b"");
                                        return;
                                    }
                                };

                            if !user_admission_ok(&stream_ctx, &session) {
                                stream_conn.close(0u32.into(), b"");
                                return;
                            }

                            stream_authenticated.store(true, std::sync::atomic::Ordering::Release);
                            stream_authenticated_notify.notify_waiters();
                            stream_handler(session).await;
                        });
                    }
                }
                Err(e) => warn!(error = %e, "β QUIC connecting failed"),
            }
        });
    }
    Ok(())
}

// Compile-time assert that the quinn IO halves satisfy the alpha
// handshake's bounds. If quinn ever changes its types this will
// break in a useful place.
const _: () = {
    fn assert_async_read<T: AsyncRead>() {}
    fn assert_async_write<T: AsyncWrite>() {}
    let _ = assert_async_read::<quinn::RecvStream>;
    let _ = assert_async_write::<quinn::SendStream>;
};
