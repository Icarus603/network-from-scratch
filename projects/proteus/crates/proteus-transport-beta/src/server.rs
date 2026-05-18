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
    // Single inner stream per connection for M2 — spec §10.3 calls
    // for one Proteus session per QUIC connection in profile β.
    // Multipath / multi-stream is M3+.
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(quinn::VarInt::from_u32(4))
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
    let buf_outcome = crate::apply_udp_socket_buffers(
        &std_sock,
        crate::DEFAULT_UDP_SOCKET_BUFFER_BYTES,
    )?;
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

/// Accept loop. For each incoming QUIC connection: complete TLS+QUIC,
/// accept ONE bidirectional stream, run the Proteus handshake, hand
/// the resulting [`AlphaSession`] to `handler`.
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

                    // ----- Admission gates (firewall + global handshake
                    // budget + per-IP rate limit). These MUST mirror α
                    // 1:1 — without them an attacker that speaks UDP to
                    // the server can drain ML-KEM cycles unmetered.
                    //
                    // β has no cover-forward path (the QUIC handshake
                    // already completed; we don't have a raw TLS byte
                    // stream below it). Rejection mode is therefore a
                    // clean QUIC close. From the peer's perspective the
                    // close is indistinguishable from "server decided
                    // to terminate" — same fingerprint as a normal
                    // server-initiated close.
                    //
                    // ## Indistinguishability discipline (USENIX 25 ++)
                    //
                    // Every close MUST be NO_ERROR (0x00) with an empty
                    // reason phrase. Earlier revisions surfaced reasons
                    // like "admission-denied" / "max-connections" /
                    // "alpn-mismatch" / "bi-stream-timeout" /
                    // "no-exporter" with distinct error codes (1, 2, 0,
                    // 3, 4). An active GFW prober that retries the
                    // handshake under different invariants — fresh IP
                    // vs. blocked IP, fresh user_id vs. unknown
                    // user_id, varied ALPN — can read the reason phrase
                    // out of the CONNECTION_CLOSE frame (it's
                    // unencrypted at the QUIC transport level, RFC
                    // 9000 §19.19) and CLASSIFY the server's policy.
                    // That distinguishes Proteus from generic QUIC
                    // services that close with NO_ERROR + empty
                    // reason. The diagnostic content stays in the
                    // operator's tracing logs + Prometheus metrics —
                    // never on the wire.
                    if !admission_ok(&ctx, &remote) {
                        record_probe_anomaly(&ctx, &remote);
                        conn.close(0u32.into(), b"");
                        return;
                    }

                    // ----- max_connections semaphore (same as α).
                    let _permit = match ctx.try_acquire_connection() {
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

                    // Accept exactly one bidi stream, bounded by the
                    // configured per-handshake wall-clock deadline so
                    // a peer that opens a QUIC connection then refuses
                    // to send the inner stream cannot park resources
                    // indefinitely (slowloris-over-QUIC).
                    let bi_fut = conn.accept_bi();
                    let (send, recv) =
                        match tokio::time::timeout(ctx.handshake_deadline(), bi_fut).await {
                            Ok(Ok(pair)) => pair,
                            Ok(Err(e)) => {
                                warn!(error = %e, "β: accept_bi failed");
                                return;
                            }
                            Err(_) => {
                                warn!(
                                    remote = %remote,
                                    "β: peer never opened bidi stream within handshake_deadline"
                                );
                                if let Some(m) = ctx.metrics() {
                                    m.handshake_timeouts
                                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                }
                                record_probe_anomaly(&ctx, &remote);
                                // Indistinguishability: NO_ERROR + empty
                                // reason. Same discipline as the
                                // admission/cap branches above. Reason
                                // visible only in operator metrics.
                                conn.close(0u32.into(), b"");
                                return;
                            }
                        };

                    // ----- TLS channel binding (RFC 5705 / 9266) -----
                    // Extract the QUIC outer-TLS exporter and feed it into
                    // the inner Proteus handshake transcript so a MITM
                    // bridging two distinct QUIC sessions (rogue cert,
                    // SSL-bumping middlebox of the QUIC variety) cannot
                    // relay the inner Finished MAC chain. Same threat
                    // model + same defense as the α-profile path —
                    // identical to commit 906ab22 but using quinn's
                    // `export_keying_material` instead of rustls's.
                    //
                    // The two carriers use DIFFERENT binding bytes (rustls
                    // exporter for α; quinn-proto exporter for β), and
                    // they are not interchangeable. That's a feature: a
                    // β-rogue cannot replay an α capture and vice versa.
                    let mut binding = [0u8; CHANNEL_BINDING_LEN];
                    if conn
                        .export_keying_material(&mut binding[..], TLS_EXPORTER_LABEL, b"")
                        .is_err()
                    {
                        warn!(
                            remote = %remote,
                            "β: TLS exporter unavailable post-handshake; closing"
                        );
                        record_probe_anomaly(&ctx, &remote);
                        // Indistinguishability: NO_ERROR + empty
                        // reason. Diagnostic stays in the tracing log
                        // above.
                        conn.close(0u32.into(), b"");
                        return;
                    }

                    // Run the Proteus handshake, also bounded by the
                    // wall-clock deadline. Same semantics as α.
                    // Measure handshake wall-clock so the on_session
                    // handler can feed it into the latency histogram.
                    let hs_start = std::time::Instant::now();
                    let hs_fut = handshake_over_split_bound(recv, send, &ctx, Some(binding));
                    let session = match tokio::time::timeout(ctx.handshake_deadline(), hs_fut).await
                    {
                        Ok(Ok(s)) => {
                            let elapsed = hs_start.elapsed();
                            s.with_peer_addr(remote).with_handshake_duration(elapsed)
                        }
                        Ok(Err(e)) => {
                            warn!(remote = %remote, error = %e, "β: Proteus handshake failed");
                            record_probe_anomaly(&ctx, &remote);
                            return;
                        }
                        Err(_) => {
                            warn!(
                                remote = %remote,
                                "β: Proteus handshake exceeded handshake_deadline"
                            );
                            if let Some(m) = ctx.metrics() {
                                m.handshake_timeouts
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                            record_probe_anomaly(&ctx, &remote);
                            return;
                        }
                    };

                    // Post-handshake per-user limit. Mirrors α.
                    if !user_admission_ok(&ctx, &session) {
                        // user_admission_ok already logged + bumped the
                        // rate-limit counter. Drop the session — the
                        // QUIC connection close on scope exit is the
                        // peer-visible signal.
                        return;
                    }

                    handler(session).await;
                    // After the handler returns, wait for the peer
                    // to close the QUIC connection. This lets the
                    // peer's read side drain any FIN'd stream bytes
                    // we sent before we drop `conn` (which would
                    // otherwise abort the connection with ApplicationClose).
                    //
                    // Bounded grace period — if the peer is gone for
                    // > 10 s we drop unilaterally.
                    let _ = tokio::time::timeout(std::time::Duration::from_secs(10), conn.closed())
                        .await;
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
