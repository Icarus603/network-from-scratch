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
use crate::endpoint_pool::{EndpointDecision, EndpointPool};
use proteus_transport_alpha::log_throttle::{AcquireResult, Throttle};

// ----- iter-23: per-process throttles for high-spam failure paths -----
//
// Pre-iter-23 a sustained upstream-VPS-down failure produced
// one log line per CONNECT (β-dial-fail, α-fallback, pool-entry-
// fail, etc.). A browser opening 50 parallel HTTP/2 connections
// while the VPS was unreachable swamped operator logs with
// hundreds of redundant lines per second — the actual
// diagnostic signal (carrier_health state transition, pool
// suppression engagement) was buried in noise.
//
// Each throttle below uses `burst=3, refill=0.2/sec` — first
// three failures fire normally so the operator sees the
// transition cleanly, then we throttle to one line every ~5 s
// of sustained failure. Matches the iter-18/iter-20 server-side
// pattern (`accept_error_throttle`, `cover_forward_throttle`).
//
// State-transition logs (carrier_health flipping, pool entry
// engaging suppression, primary-probe forcing) are NOT
// throttled — those fire once per transition and the
// operator wants every one of them.

fn beta_dial_fail_throttle() -> &'static Throttle {
    static T: std::sync::OnceLock<Throttle> = std::sync::OnceLock::new();
    T.get_or_init(|| Throttle::new(3, 0.2))
}

fn pool_entry_fail_throttle() -> &'static Throttle {
    static T: std::sync::OnceLock<Throttle> = std::sync::OnceLock::new();
    T.get_or_init(|| Throttle::new(3, 0.2))
}

fn pool_entry_beta_fail_throttle() -> &'static Throttle {
    static T: std::sync::OnceLock<Throttle> = std::sync::OnceLock::new();
    T.get_or_init(|| Throttle::new(3, 0.2))
}

fn beta_session_stats_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("PROTEUS_BETA_SESSION_STATS")
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false)
    })
}

fn log_beta_session_stats(
    before: proteus_transport_beta::client::BetaConnectionStats,
    after: proteus_transport_beta::client::BetaConnectionStats,
    carrier_id: usize,
) {
    let tx_datagrams = after.tx_datagrams.saturating_sub(before.tx_datagrams);
    let tx_bytes = after.tx_bytes.saturating_sub(before.tx_bytes);
    let rx_datagrams = after.rx_datagrams.saturating_sub(before.rx_datagrams);
    let rx_bytes = after.rx_bytes.saturating_sub(before.rx_bytes);
    let sent_packets = after.sent_packets.saturating_sub(before.sent_packets);
    let lost_packets = after.lost_packets.saturating_sub(before.lost_packets);
    let lost_bytes = after.lost_bytes.saturating_sub(before.lost_bytes);
    let packet_threshold_lost_packets = after
        .packet_threshold_lost_packets
        .saturating_sub(before.packet_threshold_lost_packets);
    let time_threshold_lost_packets = after
        .time_threshold_lost_packets
        .saturating_sub(before.time_threshold_lost_packets);
    let spurious_lost_packets = after
        .spurious_lost_packets
        .saturating_sub(before.spurious_lost_packets);
    let spurious_packet_threshold_lost_packets = after
        .spurious_packet_threshold_lost_packets
        .saturating_sub(before.spurious_packet_threshold_lost_packets);
    let spurious_time_threshold_lost_packets = after
        .spurious_time_threshold_lost_packets
        .saturating_sub(before.spurious_time_threshold_lost_packets);
    let adaptive_packet_threshold_updates = after
        .adaptive_packet_threshold_updates
        .saturating_sub(before.adaptive_packet_threshold_updates);
    let adaptive_time_threshold_updates = after
        .adaptive_time_threshold_updates
        .saturating_sub(before.adaptive_time_threshold_updates);
    let congestion_events = after
        .congestion_events
        .saturating_sub(before.congestion_events);
    let stream_data_blocked = after
        .stream_data_blocked
        .saturating_sub(before.stream_data_blocked);
    let data_blocked = after.data_blocked.saturating_sub(before.data_blocked);

    tracing::info!(
        carrier_id,
        tx_datagrams,
        tx_bytes,
        rx_datagrams,
        rx_bytes,
        sent_packets,
        lost_packets,
        lost_bytes,
        packet_threshold_lost_packets,
        time_threshold_lost_packets,
        spurious_lost_packets,
        spurious_packet_threshold_lost_packets,
        spurious_time_threshold_lost_packets,
        current_packet_threshold = after.current_packet_threshold,
        adaptive_packet_threshold_updates,
        max_spurious_packet_reordering = after.max_spurious_packet_reordering,
        current_time_threshold = after.current_time_threshold,
        adaptive_time_threshold_updates,
        max_spurious_time_ratio = after.max_spurious_time_ratio,
        congestion_events,
        stream_data_blocked,
        data_blocked,
        rtt_ms = after.rtt.as_secs_f64() * 1000.0,
        cwnd_bytes = after.cwnd_bytes,
        mtu = after.mtu,
        "β session QUIC delta (client path)"
    );
}

/// Iter-27: drain + reset the per-call-site suppression counts
/// for the iter-23 client-side throttles. Returns a `(site,
/// suppressed_in_window)` list with only the non-zero entries.
///
/// Mirrors the server-side `rejection_log_throttle_drain_rollups()`
/// (proteus-transport-alpha/src/server.rs). Called from a 60s
/// periodic task in main.rs so a long-running upstream-down
/// outage produces an operator-friendly summary line each
/// window instead of a sparse trickle of throttled WARNs
/// scattered over hours.
///
/// Each `roll_up()` call ATOMICALLY swaps the throttle's
/// "since last rollup" counter to zero, so calling this
/// periodically doesn't double-count.
#[must_use]
pub fn drain_failure_log_rollups() -> Vec<(&'static str, u64)> {
    let mut out = Vec::new();
    for (site, t) in [
        ("beta_dial_fail", beta_dial_fail_throttle()),
        ("pool_entry_fail", pool_entry_fail_throttle()),
        ("pool_entry_beta_fail", pool_entry_beta_fail_throttle()),
    ] {
        let n = t.roll_up();
        if n > 0 {
            out.push((site, n));
        }
    }
    out
}

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
    handle_socks5_with_health_and_pool(sock, cfg, &health, None).await
}

/// Health-aware dispatch — the entry point the production binary
/// uses so the back-off + recovery-probe state survives across
/// CONNECTs from the same client.
pub async fn handle_socks5_with_health(
    sock: TcpStream,
    cfg: &Arc<ClientConfig>,
    health: &Arc<CarrierHealth>,
) -> Result<(), SocksError> {
    handle_socks5_with_health_and_pool(sock, cfg, health, None).await
}

/// Full-featured dispatch via the shared `ClientCtx`. Same per-CONNECT
/// behavior as `handle_socks5_with_health_and_pool`, but additionally
/// bumps the dial counters (attempted / succeeded / failed) so the
/// admin `/status` endpoint can surface cumulative dial activity.
///
/// New entry point added 2026-05-18 — the older
/// `handle_socks5_with_health_and_pool` remains as a back-compat
/// wrapper for integration tests that build their own `CarrierHealth`
/// + `EndpointPool` directly.
pub async fn handle_socks5_with_ctx(
    sock: TcpStream,
    cfg: &Arc<ClientConfig>,
    ctx: &Arc<crate::ctx::ClientCtx>,
) -> Result<(), SocksError> {
    ctx.record_dial_attempt();
    // Snapshot the current pool ONCE at CONNECT entry so the
    // dispatch path sees a consistent view across all per-entry
    // tries. A SIGHUP between this line and the dispatch loop's
    // last iteration still works — the new pool will pick up on
    // the NEXT CONNECT — but mid-CONNECT consistency means the
    // dispatch loop doesn't accidentally walk a partially-replaced
    // entry list.
    let pool_snapshot = ctx.pool();
    // Hand the dispatch path a cheap-to-clone view onto the
    // bootstrap-DNS counter atomics so `try_alpha` / `try_beta` can
    // bump the right counter without holding a full ctx reference.
    let bootstrap = Some(ctx.bootstrap_counter_handles());
    // Cached TLS connector (built once at startup, free to clone
    // since `TlsConnector` is `Arc<ClientConfig>` internally).
    // When `None` (no tls: config or running in dev mode without
    // TLS), `try_alpha` falls through to the legacy
    // build-connector-per-request path.
    let connector = ctx.tls_connector.clone();
    // Cached handshake-config source (iter 13). Same caching
    // pattern as the connector — built once at startup, cloned
    // cheaply per CONNECT. When None, try_alpha/try_beta fall
    // back to calling cfg.build_handshake_config() per request.
    let hs_source = ctx.hs_config_source.clone();
    // Iter-22: cached β client crypto. Same shape as the
    // connector + hs_source caches — built once at startup,
    // cloned cheaply per CONNECT. When None (β not configured
    // or build failed at startup), try_beta falls back to the
    // legacy uncached path.
    let beta_crypto = ctx.beta_crypto.clone();
    let beta_connections = Some(Arc::clone(&ctx.beta_connections));
    let res = handle_socks5_with_health_and_pool_and_bootstrap_counters(
        sock,
        cfg,
        &ctx.carrier,
        pool_snapshot.as_ref(),
        bootstrap,
        connector,
        hs_source,
        beta_crypto,
        beta_connections,
    )
    .await;
    match &res {
        Ok(()) => {
            ctx.record_dial_success();
        }
        Err(_) => {
            ctx.record_dial_failure();
        }
    }
    res
}

/// Full-featured dispatch: optionally consults a multi-VPS
/// `EndpointPool` for primary-then-fallback routing. When `pool`
/// is `None`, falls back to the single-endpoint behavior using
/// `cfg.server_endpoint` (and optionally `cfg.server_endpoint_beta`).
/// When `pool` is `Some(_)`, every CONNECT walks the pool in
/// operator-specified order with per-endpoint health tracking.
pub async fn handle_socks5_with_health_and_pool(
    sock: TcpStream,
    cfg: &Arc<ClientConfig>,
    health: &Arc<CarrierHealth>,
    pool: Option<&Arc<EndpointPool>>,
) -> Result<(), SocksError> {
    // Back-compat shim — tests + non-ctx callers get None for the
    // bootstrap counters so resolution paths aren't bumped against
    // any handles (counters stay at their default zero). Same for
    // the cached TLS connector and handshake-config source — when
    // None, `try_alpha` / `try_beta` fall through to building
    // them inline per request.
    handle_socks5_with_health_and_pool_and_bootstrap_counters(
        sock, cfg, health, pool, None, None, None, None, None,
    )
    .await
}

/// Full-fidelity dispatch entry point. `bootstrap` is the
/// bootstrap-DNS counter handle from `ClientCtx`; pass `None` to
/// skip counter bumps (tests / integration callers that don't have
/// a ctx wired).
#[allow(clippy::too_many_arguments)]
pub async fn handle_socks5_with_health_and_pool_and_bootstrap_counters(
    mut sock: TcpStream,
    cfg: &Arc<ClientConfig>,
    health: &Arc<CarrierHealth>,
    pool: Option<&Arc<EndpointPool>>,
    bootstrap: Option<crate::ctx::BootstrapCounterHandles>,
    connector: Option<Arc<proteus_transport_alpha::tls::TlsConnector>>,
    hs_source: Option<Arc<crate::config::HandshakeConfigSource>>,
    beta_crypto: Option<Arc<proteus_transport_beta::client::BetaClientCrypto>>,
    beta_connections: Option<Arc<crate::beta_pool::BetaConnectionPool>>,
) -> Result<(), SocksError> {
    sock.set_nodelay(true).ok();

    // Iter-15: bound the SOCKS5 pre-CONNECT phase (greeting +
    // method-select + request parse) so a slow-loris local app
    // cannot occupy a `max_inflight_sessions` slot indefinitely.
    // Pre-iter-15 each `read_exact` was unbounded; a stalled or
    // malicious downstream could exhaust the semaphore by
    // opening N=max_inflight TCP connections and never writing.
    // 10 s default — real apps send their greeting within µs.
    let socks_req_timeout =
        std::time::Duration::from_secs(cfg.socks_request_timeout_secs.unwrap_or(10));
    let parse_fut = async {
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
                // Iter-198: use std `Ipv4Addr` for consistency with
                // the iter-170 IPv6 canonicalization. The IPv4
                // canonical form happens to match the hand-format
                // (`"a.b.c.d"`) so the wire-side host string is
                // identical, but routing through `Ipv4Addr` makes
                // the parse-then-stringify discipline uniform with
                // the ATYP=0x04 branch — easier to audit + immune
                // to future format-string changes that might
                // diverge from canonical form.
                let ipv4_bytes: [u8; 4] = buf[..4].try_into().expect("4 bytes");
                let host = std::net::Ipv4Addr::from(ipv4_bytes).to_string();
                (host, u16::from_be_bytes([buf[4], buf[5]]))
            }
            0x03 => {
                // domain name
                let mut len = [0u8; 1];
                sock.read_exact(&mut len).await?;
                // Iter-151: reject zero-length domain at the SOCKS5
                // boundary. A misbehaving app sending ATYP=0x03 +
                // length=0 + 2 port bytes parses to ("", port),
                // which later wastes a DNS bound-timeout on the
                // empty hostname (symmetric with the iter-146
                // server-side gate, but caught one hop earlier so
                // the user sees a meaningful SOCKS5 error instead
                // of a Proteus tunnel failure).
                if len[0] == 0 {
                    sock.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await?;
                    return Err(SocksError::Socks("empty SOCKS5 domain name"));
                }
                let mut name = vec![0u8; len[0] as usize];
                sock.read_exact(&mut name).await?;
                let mut port_b = [0u8; 2];
                sock.read_exact(&mut port_b).await?;
                let host = std::str::from_utf8(&name)
                    .map_err(|_| SocksError::Socks("invalid hostname"))?
                    .to_string();
                // Iter-151: reject control bytes in the domain name.
                // Symmetric with the iter-146 server-side
                // parse_connect gate. A malicious downstream app
                // (or a misconfigured one) embedding \0 / \r / \n /
                // \t in the SOCKS5 ATYP=0x03 hostname would smuggle
                // those bytes through to the server's CONNECT path.
                // Server-side iter-146 already rejects them, but
                // catching at the SOCKS5 boundary avoids the
                // pointless wire round-trip + surfaces a
                // SOCKS5-protocol error code to the downstream app.
                if host
                    .bytes()
                    .any(|b| b == 0 || b == b'\r' || b == b'\n' || b == b'\t')
                {
                    sock.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await?;
                    return Err(SocksError::Socks(
                        "SOCKS5 domain name contains forbidden control byte",
                    ));
                }
                (host, u16::from_be_bytes(port_b))
            }
            0x04 => {
                // IPv6
                let mut buf = [0u8; 18];
                sock.read_exact(&mut buf).await?;
                // Iter-170: use the std `Ipv6Addr::to_string` which
                // produces RFC 5952 canonical form. Pre-iter-170 we
                // hand-formatted via `format!("{:x}", segs).join(":")`,
                // which produced `2001:db8:0:0:0:0:0:1` for what
                // should canonicalize to `2001:db8::1`. The downstream
                // server's `parse_connect`-then-`lookup_host` parser
                // accepted both shapes (libc's getaddrinfo handles
                // either), but the access-log line and any operator
                // grep against the upstream-dial host string saw
                // the non-canonical form, complicating forensics +
                // making it harder to match against IP-reputation
                // / outbound-filter rules that expect canonical
                // RFC 5952 representations.
                let ipv6_bytes: [u8; 16] = buf[..16].try_into().expect("16 bytes");
                let host = std::net::Ipv6Addr::from(ipv6_bytes).to_string();
                (host, u16::from_be_bytes([buf[16], buf[17]]))
            }
            _ => {
                sock.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await?;
                return Err(SocksError::Socks("unsupported ATYP"));
            }
        };
        Ok::<_, SocksError>((host, port))
    };
    let (host, port) = match tokio::time::timeout(socks_req_timeout, parse_fut).await {
        Ok(Ok(hp)) => hp,
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            // Slow-loris on the SOCKS5 port. Don't try to write a
            // SOCKS5 error reply — we don't know how far through
            // the protocol negotiation the downstream got, so the
            // safe choice is "close TCP".
            tracing::warn!(
                timeout_secs = socks_req_timeout.as_secs(),
                "SOCKS5 greeting/request timed out — downstream app didn't send anything"
            );
            return Err(SocksError::Socks("socks5 greeting/request timeout"));
        }
    };
    // Iter-151: port == 0 is not a valid TCP destination. Reject at
    // the SOCKS5 boundary (symmetric with iter-146 server-side
    // gate). A SOCKS5 connect to port 0 then over the Proteus
    // tunnel would fail at the relay's TcpStream::connect with a
    // confusing OS error; surfacing 0x08 (Address type not
    // supported / general failure) here gives the downstream app
    // a clear "this isn't a valid destination" signal.
    if port == 0 {
        // Best-effort reply — even if the write fails, the err
        // surfaces upstream cleanly.
        let _ = sock
            .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await;
        return Err(SocksError::Socks(
            "SOCKS5 destination port == 0 (not a valid TCP destination)",
        ));
    }

    // ----- Open Proteus session (β-first dual-stack, fallback to α) -----
    let target_bytes = {
        let mut v = Vec::with_capacity(1 + host.len() + 2);
        v.push(host.len() as u8);
        v.extend_from_slice(host.as_bytes());
        v.extend_from_slice(&port.to_be_bytes());
        v
    };

    // Multi-VPS HA dispatch path: when `pool` is wired, walk pool
    // entries in operator order using each entry's EndpointHealth
    // to skip recently-failed endpoints. Within each chosen entry,
    // the existing CarrierHealth still decides β-vs-α.
    //
    // Iter-29: capture the dispatch result rather than returning it
    // directly so we can emit a proper SOCKS5 error reply on
    // failure. Pre-iter-29 we just dropped TCP, which made every
    // upstream-dial failure look like "could not connect to proxy"
    // to the downstream browser/cURL — wrong diagnostic. With the
    // mapping, the downstream sees the correct SOCKS5 reply code
    // (0x03 network unreachable / 0x04 host unreachable / 0x05
    // connection refused / 0x06 TTL expired / 0x01 generic) and
    // surfaces an actionable error to the user.
    let dispatch_result = if let Some(p) = pool {
        dispatch_via_pool(
            cfg,
            health,
            p,
            target_bytes,
            &mut sock,
            bootstrap.as_ref(),
            connector.as_ref(),
            hs_source.as_ref(),
            beta_crypto.as_ref(),
            beta_connections.as_ref(),
        )
        .await
    } else {
        // Single-endpoint path (legacy / pool not configured).
        // Behavior is identical to the pre-pool dispatcher.
        single_endpoint_dispatch(
            cfg,
            health,
            &target_bytes,
            &mut sock,
            bootstrap.as_ref(),
            connector.as_ref(),
            hs_source.as_ref(),
            beta_crypto.as_ref(),
            beta_connections.as_ref(),
        )
        .await
    };

    // Iter-29: best-effort SOCKS5 error reply on dispatch failure.
    // The successful dispatch paths (single_endpoint_dispatch /
    // dispatch_via_pool → try_alpha → ... → pump) already wrote
    // the `0x05 0x00` success reply BEFORE entering the pump
    // loop. If we got Err here, that means NO reply was sent and
    // the downstream is waiting on a SOCKS5 reply that will never
    // come — so we send one with the right code.
    if let Err(e) = &dispatch_result {
        let code = socks5_error_code_for(e);
        // 10-byte SOCKS5 reply: VER=5, REP=<code>, RSV=0, ATYP=1
        // (IPv4), BND.ADDR=0.0.0.0, BND.PORT=0. The BND fields
        // are operator-irrelevant on error replies (RFC 1928
        // §6); zero them.
        let reply = [0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        let _ = sock.write_all(&reply).await;
        // Best-effort flush before drop — downstream cURL needs
        // the reply BEFORE the TCP close to surface the right
        // diagnostic.
        let _ = sock.flush().await;
    }
    dispatch_result
}

/// Iter-29: map a [`SocksError`] to the matching SOCKS5 REP
/// code (RFC 1928 §6). Returns the catch-all 0x01 "general
/// SOCKS server failure" for cases we don't have a specific
/// code for — that's still better than dropping TCP without a
/// reply because downstream clients (cURL, browsers,
/// proxychains) at least know "the proxy itself responded; the
/// upstream dial failed" instead of "the proxy is unreachable".
///
/// Iter-30 widens the mapping: timeout-class `SocksError::Socks`
/// messages (β / α handshake timed out, α TCP connect timed
/// out) now map to 0x06 (TTL expired) instead of the
/// catch-all 0x01. The message strings are `&'static str`
/// compile-time literals so matching them is reliable; if a
/// future refactor renames a message, the iter-30 unit tests
/// catch the regression at compile-time-of-test.
#[must_use]
pub(crate) fn socks5_error_code_for(e: &SocksError) -> u8 {
    use std::io::ErrorKind;
    match e {
        SocksError::Io(io) => match io.kind() {
            ErrorKind::ConnectionRefused => 0x05, // refused
            ErrorKind::TimedOut => 0x06,          // TTL expired
            ErrorKind::NetworkUnreachable => 0x03,
            ErrorKind::HostUnreachable => 0x04,
            _ => 0x01, // general SOCKS server failure
        },
        SocksError::Socks(msg) => {
            // Iter-30: the dispatch path's timeout-class
            // `&'static str` messages map to 0x06 TTL expired
            // — that's the RFC 1928 §6 code for "request took
            // too long." Downstream cURL / browsers surface
            // this as "the proxy connection timed out" which
            // is exactly the right user-visible diagnostic.
            if msg.contains("timed out") || msg.contains("timeout") {
                0x06
            } else {
                // Other Socks(...) cases are pre-dispatch-time
                // protocol errors (e.g. "no acceptable auth
                // method", "unsupported SOCKS5 cmd",
                // "unsupported ATYP") — the early-return paths
                // handle those with their own writes BEFORE
                // dispatch starts, so anything that reaches
                // here is genuinely a generic dispatch-side
                // failure.
                0x01
            }
        }
        SocksError::Alpha(_) => 0x01,
        SocksError::Config(_) => 0x01,
        SocksError::Bootstrap(_) => 0x03, // network unreachable
    }
}

// Iter-30 unit tests moved to the END of the file (post-
// pump-fn definition) so `clippy::items_after_test_module`
// stays satisfied. See `mod socks5_error_code_tests` at the
// bottom of this file.

/// Pre-pool single-endpoint dispatcher. Kept as a separate function
/// so the pool path can reuse it per-entry without code duplication.
#[allow(clippy::too_many_arguments)]
async fn single_endpoint_dispatch(
    cfg: &Arc<ClientConfig>,
    health: &Arc<CarrierHealth>,
    target_bytes: &[u8],
    sock: &mut TcpStream,
    bootstrap: Option<&crate::ctx::BootstrapCounterHandles>,
    connector: Option<&Arc<proteus_transport_alpha::tls::TlsConnector>>,
    hs_source: Option<&Arc<crate::config::HandshakeConfigSource>>,
    beta_crypto: Option<&Arc<proteus_transport_beta::client::BetaClientCrypto>>,
    beta_connections: Option<&Arc<crate::beta_pool::BetaConnectionPool>>,
) -> Result<(), SocksError> {
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
        match try_beta(
            cfg,
            target_bytes,
            sock,
            None,
            bootstrap,
            hs_source,
            beta_crypto,
            beta_connections,
        )
        .await
        {
            Ok(()) => {
                health.record_beta_success();
                return Ok(());
            }
            Err(e) => {
                health.record_beta_failure(std::time::Instant::now());
                // iter-23: throttle the per-CONNECT
                // β-fail log so a sustained VPS-down event
                // doesn't flood operator logs.
                if matches!(
                    beta_dial_fail_throttle().try_acquire(),
                    AcquireResult::Allowed
                ) {
                    tracing::warn!(
                        error = %e,
                        streak = health.failure_streak(),
                        suppressed = beta_dial_fail_throttle().total_suppressed(),
                        "β dial failed — falling back to α (TCP/TLS)"
                    );
                }
                // Fall through to α path below.
            }
        }
    } else if matches!(beta_decision, BetaDecision::SkipSuppressed) {
        tracing::debug!(
            streak = health.failure_streak(),
            "β suppressed; skipping straight to α"
        );
    }

    try_alpha(
        cfg,
        target_bytes,
        sock,
        None,
        bootstrap,
        connector,
        hs_source,
    )
    .await
}

/// Multi-VPS dispatcher. Walks `pool` in operator-specified order,
/// using each entry's `EndpointHealth` to skip recently-failed
/// endpoints. For each chosen entry, runs the β-then-α
/// CarrierHealth-aware logic with the entry's address as the
/// endpoint override.
///
/// Returns the result of the FIRST successful CONNECT; on a
/// per-entry failure (network refused, handshake timed out, etc.)
/// records the failure against that entry's health AND continues
/// to the next entry. Returns the LAST entry's error when every
/// pool member failed; that mirrors single-endpoint behavior from
/// the user's POV (one error per SOCKS5 CONNECT).
///
/// Internal dispatch fan-out — the per-CONNECT cached state
/// (bootstrap counters, TLS connector, handshake-config source)
/// is naturally a bag of optional refs, not a struct, so the
/// "too many arguments" lint is suppressed here.
#[allow(clippy::too_many_arguments)]
async fn dispatch_via_pool(
    cfg: &Arc<ClientConfig>,
    health: &Arc<CarrierHealth>,
    pool: &Arc<EndpointPool>,
    target_bytes: Vec<u8>,
    sock: &mut TcpStream,
    bootstrap: Option<&crate::ctx::BootstrapCounterHandles>,
    connector: Option<&Arc<proteus_transport_alpha::tls::TlsConnector>>,
    hs_source: Option<&Arc<crate::config::HandshakeConfigSource>>,
    beta_crypto: Option<&Arc<proteus_transport_beta::client::BetaClientCrypto>>,
    beta_connections: Option<&Arc<crate::beta_pool::BetaConnectionPool>>,
) -> Result<(), SocksError> {
    let mut last_err: Option<SocksError> = None;
    let mut any_endpoint_attempted = false;
    let now = std::time::Instant::now();

    for entry in 0..pool.len() {
        let snap = pool.diagnostic_snapshot(now);
        let (addr_owned, _streak, _suppressed) = snap[entry].clone();
        let decision = pool.endpoint_health(entry).map(|h| h.decide(now));
        let Some(decision) = decision else { continue };
        if matches!(decision, EndpointDecision::SkipSuppressed) {
            tracing::debug!(endpoint = %addr_owned, "pool: skipping suppressed entry");
            continue;
        }
        if matches!(decision, EndpointDecision::Probe) {
            tracing::debug!(endpoint = %addr_owned, "pool: recovery probe");
        }
        any_endpoint_attempted = true;
        let endpoint_health = pool.endpoint_health(entry).unwrap();
        // Cumulative per-endpoint attempt counter — bumped BEFORE the
        // dial so a panicking attempt still counts as one try (the
        // matching outcome counter just won't bump in that case, and
        // the operator sees `attempts - successes - failures > 0`
        // as the "something crashed mid-dial" signal). The dispatch
        // path is what knows the operator's per-VPS routing intent,
        // so the counter is bumped here rather than inside
        // EndpointHealth's decide() — keeps the health state machine
        // a pure policy primitive and the counter pure observability.
        endpoint_health.record_attempt();

        // Per-entry attempt: same β-first → α-fallback as
        // single_endpoint_dispatch, but with endpoint_override.
        // Note: the β endpoint override mirrors the α one — operators
        // who run α and β on the same host:port (the
        // recommended deployment) get one address per pool entry
        // covering both carriers.
        let result = attempt_one_pool_entry(
            cfg,
            health,
            &addr_owned,
            &target_bytes,
            sock,
            bootstrap,
            connector,
            hs_source,
            beta_crypto,
            beta_connections,
        )
        .await;
        match result {
            Ok(()) => {
                // record_success returns true IFF this transitioned
                // the entry OUT of an active suppression window. The
                // operator wants exactly one INFO line per recovery,
                // not one per CONNECT.
                if endpoint_health.record_success() {
                    tracing::info!(
                        endpoint = %addr_owned,
                        "endpoint RECOVERED — suppression cleared by successful CONNECT"
                    );
                }
                return Ok(());
            }
            Err(e) => {
                // record_failure returns Some(window_secs) IFF this
                // newly engaged suppression. Use that to escalate the
                // log: warn! on the engagement (a real signal to
                // investigate) vs the existing per-attempt warn!.
                let engaged = endpoint_health.record_failure(std::time::Instant::now());
                if let Some(window_secs) = engaged {
                    tracing::warn!(
                        endpoint = %addr_owned,
                        error = %e,
                        streak = endpoint_health.failure_streak(),
                        window_secs,
                        "endpoint SUPPRESSED — consecutive failures hit threshold; \
                         dispatcher will skip this entry until window expires"
                    );
                } else if matches!(
                    pool_entry_fail_throttle().try_acquire(),
                    AcquireResult::Allowed
                ) {
                    // iter-23: throttle the per-CONNECT × per-entry
                    // fail spam. The SUPPRESSED log above ALWAYS
                    // fires on state transition; this one is the
                    // routine "trying next" line that floods under
                    // sustained pool-wide failure.
                    tracing::warn!(
                        endpoint = %addr_owned,
                        error = %e,
                        streak = endpoint_health.failure_streak(),
                        suppressed = pool_entry_fail_throttle().total_suppressed(),
                        "pool entry failed — trying next"
                    );
                }
                last_err = Some(e);
            }
        }
    }

    if !any_endpoint_attempted {
        // All entries were suppressed (no probe slot landed); force
        // a primary probe so we never end up in a "did nothing"
        // state. Matches `EndpointPool::dispatch_with` fallback.
        tracing::warn!("pool: every entry suppressed; forcing primary probe");
        let primary = pool.diagnostic_snapshot(now)[0].0.clone();
        // Forced-probe still counts as an attempt against the
        // primary's cumulative counter — the operator's view of
        // "VPS-A handled N CONNECTs" must include the times we
        // dialed it from desperation, not just the policy-driven
        // tries above.
        let primary_health = pool
            .endpoint_health(0)
            .expect("pool has at least one entry");
        primary_health.record_attempt();
        let result = attempt_one_pool_entry(
            cfg,
            health,
            &primary,
            &target_bytes,
            sock,
            bootstrap,
            connector,
            hs_source,
            beta_crypto,
            beta_connections,
        )
        .await;
        match &result {
            Ok(()) => {
                primary_health.record_success();
            }
            Err(_) => {
                primary_health.record_failure(std::time::Instant::now());
            }
        }
        result?;
        return Ok(());
    }
    Err(last_err.unwrap_or(SocksError::Socks("pool dispatch produced no result")))
}

/// One pool entry's β-then-α attempt. Factored out so
/// `dispatch_via_pool` can reuse it for both the regular and
/// "all suppressed → force primary probe" paths.
///
/// Same "bag of optional cached state" pattern as
/// `dispatch_via_pool` — clippy lint suppressed for the same
/// reason.
#[allow(clippy::too_many_arguments)]
async fn attempt_one_pool_entry(
    cfg: &Arc<ClientConfig>,
    health: &Arc<CarrierHealth>,
    endpoint: &str,
    target_bytes: &[u8],
    sock: &mut TcpStream,
    bootstrap: Option<&crate::ctx::BootstrapCounterHandles>,
    connector: Option<&Arc<proteus_transport_alpha::tls::TlsConnector>>,
    hs_source: Option<&Arc<crate::config::HandshakeConfigSource>>,
    beta_crypto: Option<&Arc<proteus_transport_beta::client::BetaClientCrypto>>,
    beta_connections: Option<&Arc<crate::beta_pool::BetaConnectionPool>>,
) -> Result<(), SocksError> {
    let beta_configured = cfg.server_endpoint_beta.is_some();
    let beta_decision = health.decide_beta(beta_configured, std::time::Instant::now());
    let try_beta_now = matches!(beta_decision, BetaDecision::TryBeta | BetaDecision::Probe);
    if try_beta_now {
        match try_beta(
            cfg,
            target_bytes,
            sock,
            Some(endpoint),
            bootstrap,
            hs_source,
            beta_crypto,
            beta_connections,
        )
        .await
        {
            Ok(()) => {
                health.record_beta_success();
                return Ok(());
            }
            Err(e) => {
                health.record_beta_failure(std::time::Instant::now());
                // iter-23: throttled — fires per CONNECT × per
                // pool entry under sustained β-down conditions.
                if matches!(
                    pool_entry_beta_fail_throttle().try_acquire(),
                    AcquireResult::Allowed
                ) {
                    tracing::warn!(
                        endpoint = %endpoint,
                        error = %e,
                        suppressed = pool_entry_beta_fail_throttle().total_suppressed(),
                        "pool entry: β dial failed; falling to α on this same entry"
                    );
                }
            }
        }
    }
    try_alpha(
        cfg,
        target_bytes,
        sock,
        Some(endpoint),
        bootstrap,
        connector,
        hs_source,
    )
    .await
}

/// Attempt a β-profile (QUIC) handshake.
///
/// `endpoint_override` lets the multi-VPS HA dispatcher (`dispatch_via_pool`)
/// substitute the per-pool-entry address for the cfg's primary
/// `server_endpoint_beta`. When `None`, falls back to the cfg
/// value — preserving the pre-pool single-endpoint behavior for
/// callers that haven't migrated to the pool yet.
#[allow(clippy::too_many_arguments)]
async fn try_beta(
    cfg: &Arc<ClientConfig>,
    target_bytes: &[u8],
    sock: &mut TcpStream,
    endpoint_override: Option<&str>,
    bootstrap: Option<&crate::ctx::BootstrapCounterHandles>,
    cached_hs_source: Option<&Arc<crate::config::HandshakeConfigSource>>,
    cached_beta_crypto: Option<&Arc<proteus_transport_beta::client::BetaClientCrypto>>,
    beta_connections: Option<&Arc<crate::beta_pool::BetaConnectionPool>>,
) -> Result<(), SocksError> {
    let beta_endpoint: &str = match endpoint_override {
        Some(e) => e,
        None => cfg
            .server_endpoint_beta
            .as_deref()
            .ok_or(SocksError::Socks("server_endpoint_beta unset"))?,
    };
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
    } = resolve_for_client(beta_endpoint, cfg).await?;
    log_bootstrap_route("β", beta_endpoint, server_addr, via);
    if let Some(b) = bootstrap {
        b.record(via);
    }

    // Build a β-flavored ClientConfig (profile_hint = Beta).
    // Prefer the cached source — `source.beta()` returns an owned
    // ClientConfig with profile_hint already set, no disk hit.
    // Falls back to the legacy builder + mutation when ctx didn't
    // attach a cached source.
    let make_hs_cfg = || -> Result<_, SocksError> {
        Ok(match cached_hs_source {
            Some(source) => source.beta(),
            None => {
                let mut c = cfg.build_handshake_config()?;
                c.profile_hint = proteus_transport_alpha::ProfileHint::Beta;
                c
            }
        })
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
    if let Some(v) = cfg.beta_minimum_mtu {
        perf.minimum_mtu = v;
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
    if let Some(v) = cfg.beta_packet_threshold {
        perf.packet_threshold = v;
    }
    if let Some(v) = cfg.beta_time_threshold {
        perf.time_threshold = v;
    }
    if let Some(v) = cfg.beta_mtu_upper_bound {
        perf.mtu_upper_bound = v;
    }
    if let Some(v) = cfg.beta_stream_receive_window_mib {
        perf.stream_receive_window_override = Some(v.saturating_mul(1024 * 1024));
    }
    if let Some(v) = cfg.beta_connection_receive_window_mib {
        perf.connection_receive_window_override = Some(v.saturating_mul(1024 * 1024));
    }
    if let Some(v) = cfg.beta_send_window_mib {
        perf.send_window_override = Some(u64::from(v) * 1024 * 1024);
    }
    if cfg.beta_congestion.as_deref() == Some("brutal") {
        perf.congestion = proteus_transport_beta::CongestionKind::Brutal;
        perf.brutal_target_bps = cfg
            .beta_brutal_target_mbps
            .expect("validated: brutal target is required")
            .saturating_mul(1_000_000);
    }
    // Iter-22: prefer the cached β crypto path when ctx
    // attached one (production hot path — skips rustls config
    // build + QuicClientConfig::try_from + the per-CONNECT
    // PEM-parse of trusted_ca). Fall back to the legacy
    // per-call builder when ctx didn't attach a cache
    // (back-compat entry points / tests / β-crypto-cache-build
    // failed at startup).
    let mut one_shot_carrier = None;
    let mut pooled_carrier = None;
    let beta_session = if let (Some(crypto), Some(connection_pool)) =
        (cached_beta_crypto, beta_connections)
    {
        let key = crate::beta_pool::BetaPoolKey::new(server_addr, server_name);
        let mut completed = None;
        let mut last_error = None;

        // One retry is reserved for a carrier that died between
        // cache lookup and open_bi. Authentication failures on a
        // still-live carrier are never retried: that would create
        // a credential oracle and waste ML-KEM work.
        for attempt in 0..2 {
            let carrier_fut = connection_pool.get_or_try_init(key.clone(), || {
                proteus_transport_beta::client::connect_carrier_with_timeout_perf_cached_crypto(
                    server_name,
                    server_addr,
                    crypto,
                    timeout,
                    perf,
                )
            });
            let carrier =
                tokio::time::timeout(timeout + std::time::Duration::from_secs(1), carrier_fut)
                    .await
                    .map_err(|_| SocksError::Socks("β carrier handshake timed out"))?
                    .map_err(|e| SocksError::Io(std::io::Error::other(e.to_string())))?;

            match carrier.open_session(make_hs_cfg()?, timeout).await {
                Ok(session) => {
                    // Lease the endpoint for the full relay
                    // lifetime even if SIGHUP invalidates the
                    // process cache while this session is active.
                    pooled_carrier = Some(carrier);
                    completed = Some(session);
                    break;
                }
                Err(error) => {
                    let carrier_dead = !carrier.is_usable();
                    if carrier_dead {
                        connection_pool.evict_if_current(&key, &carrier).await;
                    }
                    last_error = Some(error);
                    if !carrier_dead || attempt == 1 {
                        break;
                    }
                    tracing::debug!(
                        endpoint = %server_addr,
                        "β cached carrier closed during stream open; reconnecting once"
                    );
                }
            }
        }

        completed.ok_or_else(|| {
            let error = last_error
                .map(|e| e.to_string())
                .unwrap_or_else(|| "β pooled session failed without an error".to_string());
            SocksError::Io(std::io::Error::other(error))
        })?
    } else if let Some(crypto) = cached_beta_crypto {
        let connect_fut = proteus_transport_beta::client::connect_with_timeout_perf_cached_crypto(
            server_name,
            server_addr,
            crypto,
            make_hs_cfg()?,
            timeout,
            perf,
        );
        let client = tokio::time::timeout(timeout + std::time::Duration::from_secs(1), connect_fut)
            .await
            .map_err(|_| SocksError::Socks("β handshake timed out"))?
            .map_err(|e| SocksError::Io(std::io::Error::other(e.to_string())))?;
        let (session, carrier) = client.into_session_and_carrier();
        one_shot_carrier = Some(carrier);
        session
    } else {
        // Optional extra-trust CA from the α TLS block (β reuses the
        // same chain in the recommended deployment). The production
        // cached path loaded this once at startup.
        let extra_roots = match cfg.tls.as_ref().and_then(|t| t.trusted_ca.as_ref()) {
            Some(ca) => proteus_transport_alpha::tls::load_cert_chain(ca)
                .map_err(|e| SocksError::Io(std::io::Error::other(e.to_string())))?,
            None => Vec::new(),
        };
        let connect_fut = proteus_transport_beta::client::connect_with_timeout_and_perf(
            server_name,
            server_addr,
            extra_roots,
            make_hs_cfg()?,
            timeout,
            perf,
        );
        let client = tokio::time::timeout(timeout + std::time::Duration::from_secs(1), connect_fut)
            .await
            .map_err(|_| SocksError::Socks("β handshake timed out"))?
            .map_err(|e| SocksError::Io(std::io::Error::other(e.to_string())))?;
        let (session, carrier) = client.into_session_and_carrier();
        one_shot_carrier = Some(carrier);
        session
    };

    let proteus_transport_alpha::session::AlphaSession {
        mut sender,
        mut receiver,
        ..
    } = beta_session;
    let stats_carrier = pooled_carrier.as_ref().or(one_shot_carrier.as_ref());
    let stats_before = if beta_session_stats_enabled() {
        stats_carrier.map(|carrier| (carrier.stable_id(), carrier.stats()))
    } else {
        None
    };
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
    if let (Some((carrier_id, before)), Some(carrier)) = (stats_before, stats_carrier) {
        log_beta_session_stats(before, carrier.stats(), carrier_id);
    }
    drop(pooled_carrier);
    drop(one_shot_carrier);

    Ok(())
}

/// Attempt the α-profile (TCP / TCP+TLS) path. Same logic as the
/// pre-dual-stack version, factored out so try_beta's fall-back
/// path can call it.
///
/// `endpoint_override`: see `try_beta`'s same-named param. When
/// `None`, dials `cfg.server_endpoint`; when `Some`, dials the
/// supplied per-pool-entry address.
async fn try_alpha(
    cfg: &Arc<ClientConfig>,
    target_bytes: &[u8],
    sock: &mut TcpStream,
    endpoint_override: Option<&str>,
    bootstrap: Option<&crate::ctx::BootstrapCounterHandles>,
    cached_connector: Option<&Arc<proteus_transport_alpha::tls::TlsConnector>>,
    cached_hs_source: Option<&Arc<crate::config::HandshakeConfigSource>>,
) -> Result<(), SocksError> {
    // Prefer the cached source (built ONCE at startup) so we
    // don't pay for 4 disk reads + base64 decode + Ed25519
    // derivation per CONNECT. Falls back to the legacy per-request
    // builder when the source wasn't attached (back-compat entry
    // points / tests).
    let hs_cfg = match cached_hs_source {
        Some(source) => source.alpha(),
        None => cfg.build_handshake_config()?,
    };
    let alpha_endpoint: &str = endpoint_override.unwrap_or(cfg.server_endpoint.as_str());

    // Resolve under the configured bootstrap-DNS policy (same path
    // as β — see `bootstrap.rs`). The same `Resolved` discriminator
    // gets logged so operators can audit "am I actually skipping DNS?"
    // by tailing the client logs.
    let Resolved {
        addr: server_addr,
        via,
    } = resolve_for_client(alpha_endpoint, cfg).await?;
    log_bootstrap_route("α", alpha_endpoint, server_addr, via);
    if let Some(b) = bootstrap {
        b.record(via);
    }

    if let Some(tls_cfg) = cfg.tls.as_ref() {
        let alpha_timeout =
            std::time::Duration::from_secs(cfg.alpha_dial_timeout_secs.unwrap_or(10));

        #[cfg(unix)]
        if let Some(socket_path) = tls_cfg.utls_bridge_socket.as_ref() {
            let bridge_target = server_addr.to_string();
            let session = tokio::time::timeout(
                alpha_timeout,
                crate::utls_bridge::handshake(
                    socket_path,
                    &bridge_target,
                    &tls_cfg.server_name,
                    &hs_cfg,
                ),
            )
            .await
            .map_err(|_| SocksError::Socks("α uTLS bridge + Proteus handshake timed out"))?
            .map_err(|e| SocksError::Io(std::io::Error::other(e.to_string())))?;
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

        // Prefer the ctx-cached connector (built ONCE at startup) so
        // we don't pay for `build_connector_*` per request. Falls back
        // to per-request construction when ctx didn't attach one
        // (legacy entry points, integration tests that bypass ctx).
        let owned_connector;
        let connector: &proteus_transport_alpha::tls::TlsConnector = match cached_connector {
            Some(c) => c.as_ref(),
            None => {
                owned_connector = match tls_cfg.trusted_ca.as_ref() {
                    Some(ca) => proteus_transport_alpha::tls::build_connector_with_ca(ca)
                        .map_err(|e| SocksError::Io(std::io::Error::other(e.to_string())))?,
                    None => proteus_transport_alpha::tls::build_connector_webpki_roots()
                        .map_err(|e| SocksError::Io(std::io::Error::other(e.to_string())))?,
                };
                &owned_connector
            }
        };
        // Iter-15: bound the entire α dial (TCP connect + TLS
        // handshake + Proteus auth-exchange) under
        // `alpha_dial_timeout_secs`. Pre-iter-15 each operation
        // was unbounded — a misbehaving server that accepted TCP
        // then sat silent on TLS would wedge the SOCKS5 CONNECT
        // indefinitely (until the downstream browser/app fired
        // its own 30-60 s timeout). β had this; α didn't.
        // Dial the IP literal we just resolved. The TLS SNI continues
        // to be `tls_cfg.server_name` (hostname) so cert verification
        // still works against the operator's Let's Encrypt cert.
        let tcp = tokio::time::timeout(alpha_timeout, tokio::net::TcpStream::connect(server_addr))
            .await
            .map_err(|_| SocksError::Socks("α TCP connect timed out"))??;
        // Iter-14: apply nodelay + TCP keepalive on the outbound
        // socket so long-idle Proteus sessions survive NAT
        // idle-timer reaping and small writes don't wait on
        // Nagle when the path is high-RTT. Iter-28: ALSO apply
        // TCP_USER_TIMEOUT (Linux-only) so an actively-sending
        // session whose VPS goes silent mid-stream gets
        // terminated within ~120s instead of holding the FD
        // for the kernel's ~15-minute retransmit deadline.
        // Both are best-effort.
        let keepalive_secs = cfg.tcp_keepalive_secs.unwrap_or(30);
        let dial_opts =
            proteus_transport_alpha::socket_opts::apply_dial_socket_opts_with_user_timeout(
                &tcp,
                keepalive_secs,
                keepalive_secs.saturating_mul(4),
            );
        if let Some(e) = dial_opts.nodelay_err {
            tracing::warn!(error = %e, "client→server TCP_NODELAY failed (proceeding)");
        }
        if let Some(e) = dial_opts.keepalive_err {
            tracing::warn!(
                error = %e,
                "client→server TCP keepalive failed (proceeding — session may silently die in NAT idle)"
            );
        }
        if let Some(e) = dial_opts.user_timeout_err {
            tracing::warn!(
                error = %e,
                "client→server TCP_USER_TIMEOUT failed (proceeding — actively-sending session may hold FD for ~15min if VPS goes silent mid-stream)"
            );
        }
        // Bound the TLS+Proteus handshake under the same outer
        // budget. A rogue server that accepts but doesn't speak
        // TLS gets dropped within `alpha_timeout` rather than
        // hanging the CONNECT.
        let session = tokio::time::timeout(
            alpha_timeout,
            p_client::handshake_over_tls(tcp, connector, &tls_cfg.server_name, &hs_cfg),
        )
        .await
        .map_err(|_| SocksError::Socks("α TLS+Proteus handshake timed out"))??;
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
    // Same iter-15 bounded-dial pattern as the TLS branch above —
    // even dev mode should fast-fail on a broken endpoint.
    let alpha_timeout = std::time::Duration::from_secs(cfg.alpha_dial_timeout_secs.unwrap_or(10));
    let tcp = tokio::time::timeout(alpha_timeout, tokio::net::TcpStream::connect(server_addr))
        .await
        .map_err(|_| SocksError::Socks("α TCP connect (plaintext) timed out"))??;
    // Same iter-14 + iter-28 socket-opts pattern as the TLS branch above.
    let keepalive_secs = cfg.tcp_keepalive_secs.unwrap_or(30);
    let dial_opts = proteus_transport_alpha::socket_opts::apply_dial_socket_opts_with_user_timeout(
        &tcp,
        keepalive_secs,
        keepalive_secs.saturating_mul(4),
    );
    if let Some(e) = dial_opts.nodelay_err {
        tracing::warn!(error = %e, "client→server (plaintext) TCP_NODELAY failed (proceeding)");
    }
    if let Some(e) = dial_opts.keepalive_err {
        tracing::warn!(
            error = %e,
            "client→server (plaintext) TCP keepalive failed (proceeding)"
        );
    }
    if let Some(e) = dial_opts.user_timeout_err {
        tracing::warn!(
            error = %e,
            "client→server (plaintext) TCP_USER_TIMEOUT failed (proceeding)"
        );
    }
    let session = tokio::time::timeout(alpha_timeout, p_client::handshake_over_tcp(tcp, &hs_cfg))
        .await
        .map_err(|_| SocksError::Socks("α Proteus handshake (plaintext) timed out"))??;
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
///
/// ## Bounded flush (correctness after iter 12)
///
/// Pre-iter-12 this function flushed after every `send_record`,
/// which defeated the 64 KiB `BufWriter` inside `AlphaSender`. On
/// bulk uploads (file transfer, screen share, anything streaming
/// past 16 KiB) that turned one logical 1 MiB write into ~64
/// individual TLS records each followed by its own kernel write.
/// The result was wasted syscalls, fragmented TCP segments, and
/// throughput much lower than the underlying carrier could carry.
///
/// The original adaptive version skipped flush when a read filled
/// the buffer exactly. That creates a liveness hole: an application
/// may pause on the 64 KiB boundary while waiting for its echoed
/// response, leaving both peers waiting until QUIC's idle timeout.
/// We now flush after every 64 KiB application record. The sender's
/// internal buffer still coalesces each record's header and body,
/// while a completed logical record is never retained indefinitely.
///
/// The receiver side is unchanged — `recv_record` already wakes
/// per logical record; we simply forward each one to the SOCKS5
/// socket as it arrives.
async fn pump<R, W>(
    sock: &mut TcpStream,
    sender: &mut proteus_transport_alpha::session::AlphaSender<W>,
    receiver: &mut proteus_transport_alpha::session::AlphaReceiver<R>,
) where
    R: tokio::io::AsyncRead + Unpin + Send,
    W: tokio::io::AsyncWrite + Unpin + Send,
{
    let (mut sock_r, sock_w_raw) = tokio::io::split(sock);
    // Iter-63: wrap the SOCKS5 outbound writer in a 64 KiB
    // BufWriter to coalesce small Proteus inbound records into
    // single TCP write syscalls to the downstream local app.
    //
    // Pre-iter-63 every `receiver.recv_record()` result became
    // its own `sock_w.write_all(&buf)` syscall. The same Hy2 /
    // TUIC5 speed gap iter-62 fixed on the server-upstream side
    // applies here on the client-downstream side: small Proteus
    // records (HTTP/2 control frames at ~9 bytes, MQTT keepalives,
    // SSH keystrokes) each spent a full TCP write syscall +
    // kernel TX path traversal.
    //
    // 64 KiB matches AlphaSender::TX_BUF_CAPACITY (the inbound-
    // side coalescing budget on the OTHER direction). Symmetric
    // budgets on both legs.
    let mut sock_w = tokio::io::BufWriter::with_capacity(64 * 1024, sock_w_raw);
    let client_to_server = async {
        // 64 KiB matches AlphaSender::TX_BUF_CAPACITY so a single
        // read can fill the BufWriter, and consecutive full reads
        // coalesce cleanly without exceeding it.
        //
        // Iter-184: scope-exit scrub via ScrubOnDrop. Same
        // residue defect as iter-183 (server-side relay):
        // `sock_r.read(&mut buf)` only overwrites `buf[..n]`,
        // leaving prior reads' tail residue accumulating at
        // the high-water mark. The SOCKS5 inbound is APPLICATION
        // PLAINTEXT (the user's HTTP request lines, the user's
        // TCP-tunneled bytes) — exactly what Proteus promises
        // never to leak.
        struct ScrubOnDrop(Vec<u8>);
        impl Drop for ScrubOnDrop {
            fn drop(&mut self) {
                use zeroize::Zeroize as _;
                self.0.zeroize();
            }
        }
        impl std::ops::Deref for ScrubOnDrop {
            type Target = Vec<u8>;
            fn deref(&self) -> &Vec<u8> {
                &self.0
            }
        }
        impl std::ops::DerefMut for ScrubOnDrop {
            fn deref_mut(&mut self) -> &mut Vec<u8> {
                &mut self.0
            }
        }
        let mut buf = ScrubOnDrop(vec![0u8; 64 * 1024]);
        loop {
            match sock_r.read(&mut buf).await {
                Ok(0) => {
                    // Best-effort drain of anything still buffered
                    // before signaling EOF — the select! arm below
                    // will then send CLOSE + shut down the socket.
                    let _ = sender.flush().await;
                    break;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "SOCKS5 client read failed during pump");
                    let _ = sender.flush().await;
                    break;
                }
                Ok(n) => {
                    if let Err(e) = sender.send_record(&buf[..n]).await {
                        tracing::warn!(error = %e, "β client→server record send failed");
                        break;
                    }
                    // Never retain a complete application record
                    // merely because it landed exactly on the 64 KiB
                    // read boundary. The peer may be waiting for this
                    // response before producing another byte.
                    if let Err(e) = sender.flush().await {
                        tracing::warn!(error = %e, "β client→server flush failed");
                        break;
                    }
                }
            }
        }
    };
    let server_to_client = async {
        // Iter-200: reuse a single plaintext scratch across
        // recv_record_into() calls so the bulk-download hot loop
        // stops paying one Vec allocation per record. ScrubOnDrop
        // mirrors the iter-184 zeroize policy: when this future
        // gets dropped (select! teardown, panic, normal exit) the
        // last record's plaintext gets scrubbed exactly once,
        // regardless of path.
        struct ScrubOnDrop(Vec<u8>);
        impl Drop for ScrubOnDrop {
            fn drop(&mut self) {
                use zeroize::Zeroize as _;
                self.0.zeroize();
            }
        }
        impl std::ops::Deref for ScrubOnDrop {
            type Target = Vec<u8>;
            fn deref(&self) -> &Vec<u8> {
                &self.0
            }
        }
        impl std::ops::DerefMut for ScrubOnDrop {
            fn deref_mut(&mut self) -> &mut Vec<u8> {
                &mut self.0
            }
        }
        let mut plaintext = ScrubOnDrop(Vec::with_capacity(16 * 1024));
        loop {
            match receiver.recv_record_into(&mut plaintext.0).await {
                Ok(Some(())) if !plaintext.is_empty() => {
                    let buf = &mut *plaintext;
                    let write_result = sock_w.write_all(buf).await;
                    // Iter-184: scrub the decrypted-plaintext Vec
                    // immediately after the downstream-socket
                    // write completes (success OR error). The
                    // bytes are application plaintext returned
                    // from the upstream — HTTP response headers,
                    // file-download payloads, TCP-tunnel bytes.
                    // Same scrub policy as iter-183's relay.rs
                    // direction-1 fix, applied here on the
                    // client side.
                    use zeroize::Zeroize as _;
                    buf.zeroize();
                    if let Err(e) = write_result {
                        tracing::warn!(error = %e, "SOCKS5 downstream write failed");
                        break;
                    }
                    // A full-capacity record can be the final record
                    // in an application request/response phase.
                    // Flush it instead of waiting for a byte that the
                    // downstream peer will only send after receipt.
                    if let Err(e) = sock_w.flush().await {
                        tracing::warn!(error = %e, "SOCKS5 downstream flush failed");
                        break;
                    }
                }
                Ok(Some(())) => {} // keepalive (plaintext empty)
                Ok(None) => break,
                Err(e) => {
                    tracing::warn!(error = %e, "β server→client record receive failed");
                    break;
                }
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

#[cfg(test)]
mod socks5_error_code_tests {
    //! Iter-30: unit tests for the error-class → REP-code
    //! mapping. Placed at the end of the file so
    //! `clippy::items_after_test_module` stays satisfied.

    use super::{socks5_error_code_for, SocksError};
    use std::io::{Error, ErrorKind};

    #[test]
    fn io_connection_refused_maps_to_0x05() {
        let e = SocksError::Io(Error::from(ErrorKind::ConnectionRefused));
        assert_eq!(socks5_error_code_for(&e), 0x05);
    }

    #[test]
    fn io_timed_out_maps_to_0x06() {
        let e = SocksError::Io(Error::from(ErrorKind::TimedOut));
        assert_eq!(socks5_error_code_for(&e), 0x06);
    }

    /// Iter-30: the dispatch-path `α TCP connect timed out`
    /// and `α TLS+Proteus handshake timed out` and `β
    /// handshake timed out` messages MUST map to 0x06 (TTL
    /// expired), not the catch-all 0x01. If a future
    /// refactor renames any of these messages without
    /// updating the matcher, the user sees a generic
    /// "SOCKS5 failure" instead of "request timed out" —
    /// silent diagnostic regression.
    #[test]
    fn socks_static_timeout_messages_map_to_0x06() {
        for msg in [
            "α TCP connect timed out",
            "α TCP connect (plaintext) timed out",
            "α TLS+Proteus handshake timed out",
            "α Proteus handshake (plaintext) timed out",
            "β handshake timed out",
            "socks5 greeting/request timeout",
        ] {
            let e = SocksError::Socks(msg);
            assert_eq!(
                socks5_error_code_for(&e),
                0x06,
                "iter-30 timeout-message mapping regressed for {msg:?}"
            );
        }
    }

    /// Iter-170: the SOCKS5 ATYP=0x04 path used to format IPv6
    /// segments via `format!("{:x}", u16)`, producing
    /// `2001:db8:0:0:0:0:0:1` for what should canonicalize to
    /// `2001:db8::1`. Iter-170 switches to `Ipv6Addr::to_string()`
    /// which produces RFC 5952 canonical form. This test pins
    /// the std library's behavior: the standard
    /// `Ipv6Addr::from(&[u8; 16])` + `.to_string()` round-trip
    /// MUST produce the canonical compressed form.
    ///
    /// Pre-iter-170 the hand-formatted output of the equivalent
    /// `chunks(2).map(format!("{:x}", ...)).join(":")` would have
    /// produced the LONG (non-compressed) form for any input with
    /// runs of zero segments, so the same `[2001:db8::1]` address
    /// would have shown up in access logs and operator greps as
    /// `2001:db8:0:0:0:0:0:1` — confusing and missable.
    #[test]
    fn iter170_ipv6_canonicalization_matches_rfc_5952() {
        // Sanity: confirm the pre-iter-170 hand-format produced
        // the NON-canonical long form for at least one input that
        // we now canonicalize. This pins the regression evidence:
        // if a future refactor goes back to the hand-format, the
        // test below this one (the canonical form check) fails.
        let bytes: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let segs: Vec<String> = bytes
            .chunks(2)
            .map(|c| format!("{:x}", u16::from_be_bytes([c[0], c[1]])))
            .collect();
        let pre_iter170 = segs.join(":");
        assert_eq!(
            pre_iter170, "2001:db8:0:0:0:0:0:1",
            "pre-iter-170 hand-format reference: long form expected"
        );
        let post_iter170 = std::net::Ipv6Addr::from(bytes).to_string();
        assert_ne!(
            post_iter170, pre_iter170,
            "iter-170: canonical form must differ from the broken long form"
        );
        assert_eq!(post_iter170, "2001:db8::1");
    }

    /// Iter-170: the broader canonicalization matrix. Walks the
    /// standard RFC 5952 examples through `Ipv6Addr::to_string()`.
    #[test]
    fn iter170_ipv6_canonicalization_matrix() {
        for (bytes, expected) in [
            (
                [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                "2001:db8::1",
            ),
            ([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], "::1"),
            (
                [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                "fe80::",
            ),
            (
                [
                    0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0, 0, 0, 0, 0x8a, 0x2e, 0x03, 0x70, 0x73,
                    0x34,
                ],
                "2001:db8:85a3::8a2e:370:7334",
            ),
        ] {
            let s = std::net::Ipv6Addr::from(bytes).to_string();
            assert_eq!(
                s, expected,
                "iter-170: Ipv6Addr::to_string() must canonicalize per RFC 5952; \
                 got {s:?} for {bytes:?}"
            );
        }
    }

    /// Pre-dispatch protocol errors → 0x01. (They're handled
    /// by the early-return paths in practice, but if any ever
    /// reach the dispatch wrapper, generic-failure is the
    /// honest answer.)
    #[test]
    fn non_timeout_socks_messages_map_to_0x01() {
        for msg in [
            "not SOCKS5",
            "no acceptable auth method",
            "unsupported SOCKS5 cmd",
            "unsupported ATYP",
            "invalid hostname",
            "server_endpoint_beta unset",
            "β requires beta_server_name or tls.server_name",
        ] {
            let e = SocksError::Socks(msg);
            assert_eq!(
                socks5_error_code_for(&e),
                0x01,
                "non-timeout Socks message should map to generic 0x01 for {msg:?}"
            );
        }
    }
}
