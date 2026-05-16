//! β-profile QUIC server.
//!
//! Listens on UDP, runs QUIC + TLS 1.3 + `proteus-β-v1` ALPN, then
//! for each incoming bidirectional stream invokes the standard
//! Proteus handshake from `proteus-transport-alpha`.

use std::net::SocketAddr;
use std::sync::Arc;

use proteus_transport_alpha::server::{
    admission_ok, handshake_over_split, user_admission_ok, ConnGate, ServerCtx,
};
use proteus_transport_alpha::session::AlphaSession;
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
    crate::apply_perf_tuning(&mut transport);
    server_cfg.transport_config(Arc::new(transport));
    let endpoint = quinn::Endpoint::server(server_cfg, addr)?;
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
    while let Some(connecting) = endpoint.accept().await {
        let ctx = Arc::clone(&ctx);
        let handler = handler.clone();
        tokio::spawn(async move {
            match connecting.await {
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
                    if !admission_ok(&ctx, &remote) {
                        conn.close(1u32.into(), b"admission-denied");
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
                            conn.close(2u32.into(), b"max-connections");
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
                            conn.close(0u32.into(), b"alpn-mismatch");
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
                                conn.close(3u32.into(), b"bi-stream-timeout");
                                return;
                            }
                        };

                    // Run the Proteus handshake, also bounded by the
                    // wall-clock deadline. Same semantics as α.
                    let hs_fut = handshake_over_split(recv, send, &ctx);
                    let session = match tokio::time::timeout(ctx.handshake_deadline(), hs_fut).await
                    {
                        Ok(Ok(s)) => s.with_peer_addr(remote),
                        Ok(Err(e)) => {
                            warn!(remote = %remote, error = %e, "β: Proteus handshake failed");
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
