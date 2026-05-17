//! Minimal SOCKS5 inbound (RFC 1928) → Proteus α outbound.
//!
//! Supported: TCP CONNECT, no auth (`0x00`). UDP-ASSOCIATE / BIND not
//! implemented (Proteus α is TCP-only; UDP is a γ/β profile concern).

use std::sync::Arc;

use proteus_transport_alpha::client as p_client;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::bootstrap::{resolve_for_client, BootstrapError, Resolved, ResolvedVia};
use crate::carrier_health::{BetaDecision, CarrierHealth};
use crate::config::ClientConfig;

#[derive(thiserror::Error, Debug)]
pub enum SocksError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("config: {0}")]
    Config(#[from] crate::config::ConfigError),

    #[error("alpha: {0}")]
    Alpha(#[from] proteus_transport_alpha::error::AlphaError),

    #[error("socks5: {0}")]
    Socks(&'static str),

    #[error("bootstrap-dns: {0}")]
    Bootstrap(#[from] BootstrapError),
}

/// Log the bootstrap-DNS resolution path taken for an endpoint dial.
///
/// Levels:
/// - `IpLiteralInEndpoint` / `PinnedDirectIp` → `debug` (the
///   anti-censorship path; quiet when working)
/// - `SystemResolver` → `info` (deserves operator attention because
///   it's the path that's vulnerable to the 2026 GFW DoH
///   identification; logging it makes the misconfiguration
///   visible without spamming the log when the operator picked
///   the safe path)
fn log_bootstrap_route(
    carrier: &str,
    endpoint: &str,
    addr: std::net::SocketAddr,
    via: ResolvedVia,
) {
    match via {
        ResolvedVia::IpLiteralInEndpoint => tracing::debug!(
            carrier = carrier,
            endpoint = endpoint,
            addr = %addr,
            via = "ip-literal",
            "bootstrap: endpoint is already an IP literal — DNS skipped"
        ),
        ResolvedVia::PinnedDirectIp => tracing::debug!(
            carrier = carrier,
            endpoint = endpoint,
            addr = %addr,
            via = "pinned-direct-ip",
            "bootstrap: using bootstrap_dns.direct_ip — DNS skipped"
        ),
        ResolvedVia::SystemResolver => tracing::info!(
            carrier = carrier,
            endpoint = endpoint,
            addr = %addr,
            via = "system-resolver",
            "bootstrap: resolved via OS resolver (consider setting `bootstrap_dns: \
             direct_ip: <ip>` to defeat 2026 GFW DoH identification)"
        ),
    }
}

pub async fn handle_socks5(sock: TcpStream, cfg: &Arc<ClientConfig>) -> Result<(), SocksError> {
    // Back-compat shim: when the caller didn't supply a CarrierHealth
    // (legacy call sites + many integration tests), give them a
    // fresh per-call tracker — same behavior as the pre-back-off
    // dispatcher (try β always, fall back to α on per-CONNECT
    // failure with no memory). New code should call
    // `handle_socks5_with_health` so the back-off / probe logic
    // actually has somewhere to accumulate state.
    let health = Arc::new(CarrierHealth::new());
    handle_socks5_with_health(sock, cfg, &health).await
}

/// Health-aware dispatch — the entry point the production binary
/// uses so the back-off + recovery-probe state survives across
/// CONNECTs from the same client.
pub async fn handle_socks5_with_health(
    mut sock: TcpStream,
    cfg: &Arc<ClientConfig>,
    health: &Arc<CarrierHealth>,
) -> Result<(), SocksError> {
    sock.set_nodelay(true).ok();

    // ----- SOCKS5 greeting -----
    let mut hdr = [0u8; 2];
    sock.read_exact(&mut hdr).await?;
    if hdr[0] != 0x05 {
        return Err(SocksError::Socks("not SOCKS5"));
    }
    let nmethods = hdr[1] as usize;
    let mut methods = vec![0u8; nmethods];
    sock.read_exact(&mut methods).await?;
    if !methods.contains(&0x00) {
        sock.write_all(&[0x05, 0xff]).await?;
        return Err(SocksError::Socks("no acceptable auth method"));
    }
    sock.write_all(&[0x05, 0x00]).await?;

    // ----- SOCKS5 request -----
    let mut req = [0u8; 4];
    sock.read_exact(&mut req).await?;
    if req[0] != 0x05 || req[1] != 0x01 {
        // CMD must be CONNECT (0x01).
        sock.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        return Err(SocksError::Socks("unsupported SOCKS5 cmd"));
    }
    let (host, port) = match req[3] {
        0x01 => {
            // IPv4
            let mut buf = [0u8; 6];
            sock.read_exact(&mut buf).await?;
            (
                format!("{}.{}.{}.{}", buf[0], buf[1], buf[2], buf[3]),
                u16::from_be_bytes([buf[4], buf[5]]),
            )
        }
        0x03 => {
            // domain name
            let mut len = [0u8; 1];
            sock.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            sock.read_exact(&mut name).await?;
            let mut port_b = [0u8; 2];
            sock.read_exact(&mut port_b).await?;
            (
                std::str::from_utf8(&name)
                    .map_err(|_| SocksError::Socks("invalid hostname"))?
                    .to_string(),
                u16::from_be_bytes(port_b),
            )
        }
        0x04 => {
            // IPv6
            let mut buf = [0u8; 18];
            sock.read_exact(&mut buf).await?;
            let segs: Vec<String> = buf[..16]
                .chunks(2)
                .map(|c| format!("{:x}", u16::from_be_bytes([c[0], c[1]])))
                .collect();
            (segs.join(":"), u16::from_be_bytes([buf[16], buf[17]]))
        }
        _ => {
            sock.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            return Err(SocksError::Socks("unsupported ATYP"));
        }
    };

    // ----- Open Proteus session (β-first dual-stack, fallback to α) -----
    let target_bytes = {
        let mut v = Vec::with_capacity(1 + host.len() + 2);
        v.push(host.len() as u8);
        v.extend_from_slice(host.as_bytes());
        v.extend_from_slice(&port.to_be_bytes());
        v
    };

    // Consult the carrier-health tracker: under sustained β
    // failures (e.g. UDP egress blocked by the network or
    // throttled by the GFW per threat-intel main line 5), we
    // suppress β attempts for a back-off window so each CONNECT
    // doesn't pay `beta_first_timeout_secs` of pointless waiting.
    // Suppression auto-recovers via periodic probes — see
    // `carrier_health.rs` for the policy.
    let beta_decision = health.decide_beta(
        cfg.server_endpoint_beta.is_some(),
        std::time::Instant::now(),
    );
    let try_beta_now = matches!(beta_decision, BetaDecision::TryBeta | BetaDecision::Probe);
    if try_beta_now {
        if matches!(beta_decision, BetaDecision::Probe) {
            tracing::debug!(
                "β suppressed; running recovery probe (streak={})",
                health.failure_streak(),
            );
        }
        match try_beta(cfg, &target_bytes, &mut sock).await {
            Ok(()) => {
                health.record_beta_success();
                return Ok(());
            }
            Err(e) => {
                health.record_beta_failure(std::time::Instant::now());
                tracing::warn!(
                    error = %e,
                    streak = health.failure_streak(),
                    "β dial failed — falling back to α (TCP/TLS)"
                );
                // Fall through to α path below.
            }
        }
    } else if matches!(beta_decision, BetaDecision::SkipSuppressed) {
        tracing::debug!(
            streak = health.failure_streak(),
            "β suppressed; skipping straight to α"
        );
    }

    try_alpha(cfg, &target_bytes, &mut sock).await
}

/// Attempt a β-profile (QUIC) handshake to `cfg.server_endpoint_beta`,
/// send the CONNECT target, and pump bytes. Returns Ok(()) on a
/// fully-completed session, Err(_) on any failure that justifies
/// falling back to α.
async fn try_beta(
    cfg: &Arc<ClientConfig>,
    target_bytes: &[u8],
    sock: &mut TcpStream,
) -> Result<(), SocksError> {
    let beta_endpoint = cfg
        .server_endpoint_beta
        .as_ref()
        .ok_or(SocksError::Socks("server_endpoint_beta unset"))?;
    let server_name = cfg
        .beta_server_name
        .as_deref()
        .or_else(|| cfg.tls.as_ref().map(|t| t.server_name.as_str()))
        .ok_or(SocksError::Socks(
            "β requires beta_server_name or tls.server_name",
        ))?;
    let timeout = std::time::Duration::from_secs(cfg.beta_first_timeout_secs.unwrap_or(3));

    // Resolve `host:port` to a concrete SocketAddr under the
    // configured bootstrap-DNS policy. See `bootstrap.rs` —
    // operators can pin a literal IP (production anti-censorship
    // recommendation) to skip the OS resolver entirely and defeat
    // the 2026 GFW DoH-identification + DNS-hijack attack surface.
    let Resolved {
        addr: server_addr,
        via,
    } = resolve_for_client(beta_endpoint.as_str(), cfg).await?;
    log_bootstrap_route("β", beta_endpoint.as_str(), server_addr, via);

    // Build a β-flavored ClientConfig (profile_hint = Beta).
    let mut hs_cfg = cfg.build_handshake_config()?;
    hs_cfg.profile_hint = proteus_transport_alpha::ProfileHint::Beta;

    // Optional extra-trust CA from the α TLS block (β reuses the
    // same chain in the recommended deployment).
    let extra_roots = match cfg.tls.as_ref().and_then(|t| t.trusted_ca.as_ref()) {
        Some(ca) => proteus_transport_alpha::tls::load_cert_chain(ca)
            .map_err(|e| SocksError::Io(std::io::Error::other(e.to_string())))?,
        None => Vec::new(),
    };

    // Use connect_with_timeout so quinn's internal idle-timeout
    // also clamps to `timeout`; this guarantees fast-fail when the
    // peer's UDP is firewalled (no ICMP feedback). Without this,
    // quinn would happily wait its default 60-second idle window
    // even though our outer tokio::time::timeout is 3 seconds —
    // and quinn's connect future doesn't cancel cleanly mid-
    // handshake on every platform (notably macOS loopback).
    // Use connect_with_timeout so quinn's internal idle-timeout
    // also clamps; the outer tokio::time::timeout serves as a
    // belt-and-suspenders bound.
    // Build the PerfProfile from client.yaml β tunables. Defaults
    // match `PerfProfile::default()` — operators flip on
    // `beta_pad_quic_to_mtu: true` and/or bump `beta_initial_mtu`
    // in production deployments.
    let mut perf = proteus_transport_beta::PerfProfile::default();
    if let Some(v) = cfg.beta_initial_mtu {
        perf.initial_mtu = v;
    }
    if let Some(v) = cfg.beta_pad_quic_to_mtu {
        perf.pad_quic_datagrams_to_mtu = v;
    }
    if let Some(v) = cfg.beta_allow_spin_bit {
        perf.allow_spin_bit = v;
    }
    if let Some(v) = cfg.beta_ack_eliciting_threshold {
        perf.ack_eliciting_threshold = v;
    }
    if let Some(v) = cfg.beta_mtu_upper_bound {
        perf.mtu_upper_bound = v;
    }
    let connect_fut = proteus_transport_beta::client::connect_with_timeout_and_perf(
        server_name,
        server_addr,
        extra_roots,
        hs_cfg,
        timeout,
        perf,
    );
    let beta_client =
        tokio::time::timeout(timeout + std::time::Duration::from_secs(1), connect_fut)
            .await
            .map_err(|_| SocksError::Socks("β handshake timed out"))?
            .map_err(|e| SocksError::Io(std::io::Error::other(e.to_string())))?;

    let proteus_transport_alpha::session::AlphaSession {
        mut sender,
        mut receiver,
        ..
    } = beta_client.session;
    if let Some(q) = cfg.pad_quantum {
        if q > 0 {
            sender.set_pad_quantum(q);
        }
    }
    sender.send_record(target_bytes).await?;
    sender.flush().await?;
    sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    pump(sock, &mut sender, &mut receiver).await;

    // Keep the endpoint + connection alive across the pump (they
    // were moved into beta_client). Drop happens here when scope
    // ends — at this point the session has finished and the close
    // notification has already gone out via shutdown semantics.
    drop(beta_client.connection);
    drop(beta_client.endpoint);
    Ok(())
}

/// Attempt the α-profile (TCP / TCP+TLS) path. Same logic as the
/// pre-dual-stack version, factored out so try_beta's fall-back
/// path can call it.
async fn try_alpha(
    cfg: &Arc<ClientConfig>,
    target_bytes: &[u8],
    sock: &mut TcpStream,
) -> Result<(), SocksError> {
    let hs_cfg = cfg.build_handshake_config()?;

    // Resolve under the configured bootstrap-DNS policy (same path
    // as β — see `bootstrap.rs`). The same `Resolved` discriminator
    // gets logged so operators can audit "am I actually skipping DNS?"
    // by tailing the client logs.
    let Resolved {
        addr: server_addr,
        via,
    } = resolve_for_client(cfg.server_endpoint.as_str(), cfg).await?;
    log_bootstrap_route("α", cfg.server_endpoint.as_str(), server_addr, via);

    if let Some(tls_cfg) = cfg.tls.as_ref() {
        let connector = match tls_cfg.trusted_ca.as_ref() {
            Some(ca) => proteus_transport_alpha::tls::build_connector_with_ca(ca)
                .map_err(|e| SocksError::Io(std::io::Error::other(e.to_string())))?,
            None => proteus_transport_alpha::tls::build_connector_webpki_roots()
                .map_err(|e| SocksError::Io(std::io::Error::other(e.to_string())))?,
        };
        // Dial the IP literal we just resolved. The TLS SNI continues
        // to be `tls_cfg.server_name` (hostname) so cert verification
        // still works against the operator's Let's Encrypt cert.
        let tcp = tokio::net::TcpStream::connect(server_addr).await?;
        let session =
            p_client::handshake_over_tls(tcp, &connector, &tls_cfg.server_name, &hs_cfg).await?;
        let proteus_transport_alpha::session::AlphaSession {
            mut sender,
            mut receiver,
            ..
        } = session;
        if let Some(q) = cfg.pad_quantum {
            if q > 0 {
                sender.set_pad_quantum(q);
            }
        }
        sender.send_record(target_bytes).await?;
        sender.flush().await?;
        sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        pump(sock, &mut sender, &mut receiver).await;
        return Ok(());
    }

    // No TLS configured (test/dev mode). Dial the resolved IP directly.
    let tcp = tokio::net::TcpStream::connect(server_addr).await?;
    let session = p_client::handshake_over_tcp(tcp, &hs_cfg).await?;
    let proteus_transport_alpha::session::AlphaSession {
        mut sender,
        mut receiver,
        ..
    } = session;
    if let Some(q) = cfg.pad_quantum {
        if q > 0 {
            sender.set_pad_quantum(q);
        }
    }
    sender.send_record(target_bytes).await?;
    sender.flush().await?;
    sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    pump(sock, &mut sender, &mut receiver).await;
    Ok(())
}

/// Bidirectional pump between SOCKS5 inbound and Proteus session.
/// Bidirectional pump with **EOF propagation in both directions** —
/// this is the production fix for the broken session-teardown that
/// shipped in 58b56d8.
///
/// Previously: when the SOCKS5 client closed its socket, the
/// `client_to_server` half exited but the `server_to_client` half
/// kept blocking on `receiver.recv_record()` forever (the proteus
/// server was still happily relaying). The `tokio::join!` waited
/// on both halves → session leaked → semaphore permit never
/// released → `max_inflight_sessions` effectively == 0.
///
/// Fix: use `tokio::select!` so either half exiting fires the
/// teardown. On `client_to_server` EOF, send a CLOSE record to the
/// proteus server so it drops its relay and propagates to upstream.
/// On `server_to_client` EOF, shut down the SOCKS5 socket so the
/// client's read returns EOF.
async fn pump<R, W>(
    sock: &mut TcpStream,
    sender: &mut proteus_transport_alpha::session::AlphaSender<W>,
    receiver: &mut proteus_transport_alpha::session::AlphaReceiver<R>,
) where
    R: tokio::io::AsyncRead + Unpin + Send,
    W: tokio::io::AsyncWrite + Unpin + Send,
{
    let (mut sock_r, mut sock_w) = tokio::io::split(sock);
    let client_to_server = async {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match sock_r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if sender.send_record(&buf[..n]).await.is_err() {
                        break;
                    }
                    if sender.flush().await.is_err() {
                        break;
                    }
                }
            }
        }
    };
    let server_to_client = async {
        loop {
            match receiver.recv_record().await {
                Ok(Some(buf)) if !buf.is_empty() => {
                    if sock_w.write_all(&buf).await.is_err() {
                        break;
                    }
                }
                Ok(Some(_)) => {} // keepalive
                Ok(None) | Err(_) => break,
            }
        }
    };
    // Either half exiting triggers a clean teardown of both.
    //
    // - If client→server hit EOF first: SOCKS5 client closed. Send
    //   a Proteus CLOSE record so the server drops the relay (and
    //   propagates upstream-side EOF), then drop the socket.
    // - If server→client hit EOF first: the upstream / Proteus
    //   session is gone. Shut down the SOCKS5 write side so the
    //   local app sees EOF and stops sending; this also wakes the
    //   client→server half if it's blocked on read.
    tokio::select! {
        _ = client_to_server => {
            // CLOSE error code 0x00 = clean close (spec §26.1).
            let _ = sender.send_close(0x00, b"socks5-eof").await;
            let _ = sock_w.shutdown().await;
        }
        _ = server_to_client => {
            let _ = sock_w.shutdown().await;
        }
    }
}
