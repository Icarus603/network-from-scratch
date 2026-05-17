//! Server-side relay logic.
//!
//! After the Proteus handshake completes, the first record from the client
//! is interpreted as a CONNECT-style target spec:
//!
//! ```text
//! struct ConnectRequest {
//!     uint8 host_len;
//!     opaque host[host_len];          // domain name or IP literal
//!     uint16 port;                     // big-endian
//! }
//! ```
//!
//! The server opens a TCP connection to `(host, port)` and pipes the inner
//! stream bidirectionally. Subsequent client records are forwarded to the
//! upstream; upstream replies are wrapped in records back to the client.

use std::sync::Arc;
use std::time::{Duration, Instant};

use proteus_transport_alpha::abuse_detector::AbuseDetector;
use proteus_transport_alpha::access_log::{AccessLogHandle, AccessLogRecord};
use proteus_transport_alpha::metrics::ServerMetrics;
use proteus_transport_alpha::outbound_filter::{Decision, OutboundPolicy};
use proteus_transport_alpha::session::AlphaSession;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

/// Hold the per-session knobs the relay needs from the binary.
#[derive(Clone, Default)]
pub struct RelayConfig {
    /// Per-direction idle timeout. `None` = no timeout (default).
    /// When set, a session that goes this long without any record
    /// arriving on a given direction is terminated and its FD
    /// released.
    pub idle_timeout: Option<Duration>,
    /// Optional server-wide metrics handle so the relay can increment
    /// `session_idle_reaped` when the timeout fires. The binary wires
    /// this in; standalone tests may leave it as None.
    pub metrics: Option<Arc<ServerMetrics>>,
    /// Optional structured access log. One JSON Lines record emitted
    /// per completed session via [`AccessLogHandle::log`]. The handle
    /// itself is cheap to clone (Arc<dyn LogSink>); we capture it
    /// once at session entry and emit at session exit.
    pub access_log: Option<AccessLogHandle>,
    /// Optional cap on total bytes (tx + rx, plaintext) per session.
    /// Once the cap is reached, the relay shuts the session down
    /// with `close_reason = "byte_budget_exhausted"`. Without this,
    /// one authenticated user (possibly with a compromised credential)
    /// can saturate the server's upstream egress and starve every
    /// other session sharing the NIC.
    ///
    /// Set to `None` (default) for unlimited; sensible production
    /// value is "expected max per-session transfer × 2" — e.g.
    /// 50 GiB for streaming-heavy users.
    pub max_session_bytes: Option<u64>,
    /// Optional per-user abuse detector — sliding-window counter
    /// over the byte-budget cap hits. When the same `user_id` trips
    /// the cap `threshold` times within `window`, the detector
    /// fires ONCE (per burst), emitting a structured `WARN` log
    /// and bumping `abuse_alerts_byte_budget`.
    pub abuse_detector_byte_budget: Option<Arc<AbuseDetector>>,
    /// Outbound destination filter (SSRF defense). When set, every
    /// upstream-dial request is resolved + checked against this
    /// policy before the TCP connect. Strongly recommended for any
    /// deployment where the server can route to private networks
    /// (cloud VPCs, datacenter LANs). Default in production:
    /// `OutboundPolicy::default()` (ports 80/443 only, all
    /// SSRF-relevant CIDRs blocked).
    pub outbound_filter: Option<Arc<OutboundPolicy>>,
    /// Optional DNS resolver stats sink. When set, every
    /// upstream-dial DNS lookup (via the outbound_filter path)
    /// bumps the appropriate counter (`ok` / `failed` / `timeout`).
    /// Surfaced via /metrics as
    /// `proteus_dns_lookups_total{outcome="..."}` so operators can
    /// spot a wedged recursive resolver: alert on
    /// `rate(proteus_dns_lookups_total{outcome="timeout"}[5m]) > 0`.
    pub dns_resolver_stats: Option<Arc<proteus_transport_alpha::outbound_filter::DnsResolverStats>>,
    /// Optional recent-abuse-fires ring buffer. When the byte-budget
    /// detector fires (above), a record is also pushed here so
    /// operators see WHICH user_id fired in `/diagnose` and
    /// `admin abuse-fires` — not just the aggregate counter. Mirrors
    /// the per-user bandwidth-rate path's automatic ring push.
    pub abuse_fires: Option<Arc<proteus_transport_alpha::abuse_fires::AbuseFireBuffer>>,
    /// Optional auto-quarantine list. When wired AND the operator
    /// has opted `byte_budget` into `quarantine_on_kinds`, every
    /// byte-budget detector fire ALSO inserts the offending
    /// user_id with the configured TTL. Subsequent handshakes from
    /// that user_id are rejected at the post-handshake admission
    /// gate.
    ///
    /// When wired, the relay ALSO registers this session's
    /// cancellation notify with the list at session start — so
    /// if the user_id is quarantined while this session is
    /// in-flight, the session's main `tokio::select!` immediately
    /// fires the cancel branch and tears down. Closes the gap
    /// where a mid-burst exfiltrator's session kept running until
    /// idle timeout.
    pub user_quarantine: Option<Arc<proteus_transport_alpha::user_quarantine::UserQuarantineList>>,
    /// Whether `byte_budget` fires should trigger an auto-
    /// quarantine insert. Operator-set; matches the bool
    /// returned by `ctx.should_quarantine_on("byte_budget")` (held
    /// here as a flat bool to avoid wiring a full ServerCtx
    /// reference through RelayConfig).
    pub quarantine_on_byte_budget: bool,
    /// Data-plane padding quantum for the server→client direction.
    /// When non-zero, every outgoing AEAD record's plaintext is
    /// length-prefixed and zero-padded to a multiple of this value
    /// before encryption, so a passive observer on the wire learns
    /// only "which quantum bucket" — sub-quantum length signal is
    /// destroyed. Spec §4.6 / §22.
    ///
    /// Independent of the client's outgoing padding choice; each
    /// direction picks its own quantum. Operators concerned about
    /// traffic-analysis MUST set this on the server side too, or
    /// the response direction leaks unpadded lengths.
    pub pad_quantum: Option<u16>,
    /// TCP keepalive interval (seconds) applied to the UPSTREAM
    /// socket the relay dials toward the SOCKS5 target. `None` =
    /// 30 seconds (the same default the server accept-loop uses
    /// for client-facing sockets via `ServerCtx::tcp_keepalive_secs`).
    ///
    /// Why this matters: long-lived upstream connections
    /// (persistent SSH tunnels, HTTP/2 long-poll, WebSocket idle)
    /// traverse the operator's outbound NAT path. CGNAT / cloud-
    /// provider NAT typically reaps idle bindings after 2-30 min,
    /// causing the upstream socket to silently go half-open.
    /// Without TCP keepalive the kernel doesn't notice until the
    /// next outbound write returns EPIPE — by which time the
    /// session looks "broken" to the user. With keepalive on,
    /// the kernel keeps the binding warm OR fast-detects the
    /// dead peer.
    ///
    /// Iter-14 added this knob; pre-iter-14 the upstream socket
    /// only had `set_nodelay(true)` and no keepalive at all.
    pub tcp_keepalive_secs: Option<u64>,
}

impl std::fmt::Debug for RelayConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayConfig")
            .field("idle_timeout", &self.idle_timeout)
            .field("metrics", &self.metrics.is_some())
            .field("access_log", &self.access_log.is_some())
            .field("max_session_bytes", &self.max_session_bytes)
            .field(
                "abuse_detector_byte_budget",
                &self.abuse_detector_byte_budget.is_some(),
            )
            .field("outbound_filter", &self.outbound_filter.is_some())
            .field("abuse_fires", &self.abuse_fires.is_some())
            .field("user_quarantine", &self.user_quarantine.is_some())
            .field("quarantine_on_byte_budget", &self.quarantine_on_byte_budget)
            .field("pad_quantum", &self.pad_quantum)
            .finish()
    }
}

pub async fn handle_session<R, W>(
    session: AlphaSession<R, W>,
    cfg: RelayConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    // Pull the access-log axes off the session *before* the destructure
    // so they survive the move into AlphaSender/AlphaReceiver.
    let user_id = session.user_id;
    let peer_addr = session.peer_addr;
    let shape_seed = session.shape_seed;
    let cover_profile_id = session.cover_profile_id;
    let session_metrics = std::sync::Arc::clone(&session.metrics);
    let access_log = cfg.access_log.clone();
    let metrics_for_alerts = cfg.metrics.clone();
    let abuse_detector = cfg.abuse_detector_byte_budget.clone();
    let abuse_fires = cfg.abuse_fires.clone();
    let user_quarantine = cfg.user_quarantine.clone();
    let quarantine_on_byte_budget = cfg.quarantine_on_byte_budget;
    let started = Instant::now();

    // Register this session with the auto-quarantine list (when
    // both wired AND the session has an authenticated user_id) so
    // a fresh quarantine insert can `notify_waiters()` and tear
    // the session down mid-burst. The notify Arc lives here in
    // the outer scope, so it stays alive for the entire session
    // and drops only when handle_session returns. The list holds
    // a Weak<Notify> internally, so this drop drives the list's
    // vacuum.
    let session_cancel = match (user_quarantine.as_ref(), user_id) {
        (Some(qlist), Some(uid)) => Some(qlist.register_session(uid)),
        _ => None,
    };

    let outcome = handle_session_inner(session, cfg, session_cancel.clone()).await;

    let close_reason: Option<&'static str> = match &outcome {
        Ok(reason) => Some(*reason),
        Err(_) => Some("relay_error"),
    };

    // Anomaly detection: a session that ended on the byte-budget
    // cap for a KNOWN user is a credential-abuse signal when it
    // happens repeatedly. Sliding-window counter; fires once per
    // burst.
    if close_reason == Some("byte_budget_exhausted") {
        if let (Some(uid), Some(detector)) = (user_id, abuse_detector.as_ref()) {
            if detector.record(uid) {
                tracing::warn!(
                    user_id = ?uid,
                    peer = ?peer_addr,
                    "abuse: user repeatedly exhausting per-session byte budget — \
                     possible stolen credential being used to exfiltrate"
                );
                if let Some(m) = metrics_for_alerts.as_ref() {
                    m.abuse_alerts_byte_budget
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                // Recent-fires ring: WHO fired, not just THAT
                // someone fired. Operators query via `/diagnose` /
                // `admin abuse-fires` to find the offending user_id
                // without grepping journald.
                if let Some(buf) = abuse_fires.as_ref() {
                    buf.push(
                        proteus_transport_alpha::abuse_fires::AbuseFireKind::ByteBudget,
                        uid,
                        0,
                    );
                }
                // Auto-quarantine when the operator has opted this
                // kind in. The byte_budget detector fires once-per-
                // burst on its own sliding-window threshold, so a
                // single fire already represents "repeated cap
                // hits" and is enough signal to ban for TTL.
                if quarantine_on_byte_budget {
                    if let Some(qlist) = user_quarantine.as_ref() {
                        if qlist.insert(
                            uid,
                            proteus_transport_alpha::abuse_fires::AbuseFireKind::ByteBudget
                                .as_label(),
                        ) {
                            tracing::warn!(
                                user_id = ?uid,
                                ttl_secs = qlist.ttl().as_secs(),
                                "auto-quarantine: user_id banned for TTL on byte_budget abuse fire"
                            );
                        }
                    }
                }
            }
        }
    }

    // Emit one access-log line for the completed session, regardless
    // of whether the inner body returned Ok / Err / through a panic
    // (the binary wraps the spawn in an InFlightGuard that catches
    // panics, but the log path is the same).
    if let Some(logger) = access_log {
        let snap = session_metrics.snapshot();
        logger.log(AccessLogRecord {
            user_id,
            peer: peer_addr,
            duration_ms: Some(started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64),
            tx_bytes: Some(snap.tx_bytes),
            rx_bytes: Some(snap.rx_bytes),
            close_reason,
            shape_seed,
            cover_profile_id,
        });
    }
    outcome.map(|_| ())
}

async fn handle_session_inner<R, W>(
    session: AlphaSession<R, W>,
    cfg: RelayConfig,
    session_cancel: Option<Arc<tokio::sync::Notify>>,
) -> Result<&'static str, Box<dyn std::error::Error + Send + Sync>>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let metrics = cfg.metrics.clone();
    let pad_quantum = cfg.pad_quantum.unwrap_or(0);
    let AlphaSession {
        mut sender,
        mut receiver,
        ..
    } = session;

    // Apply server→client padding before any record is emitted on this
    // direction. Spec §4.6 — when the operator configured `pad_quantum`
    // on the server, EVERY outgoing record (including the very first
    // upstream reply) is length-hidden.
    if pad_quantum > 0 {
        sender.set_pad_quantum(pad_quantum);
    }

    // First record = connect request. Push it out immediately so the
    // server can dial upstream without waiting for buffering.
    let req = match receiver.recv_record().await? {
        Some(b) => b,
        None => {
            warn!("client closed before sending connect target");
            return Ok("client_no_connect");
        }
    };
    let target = parse_connect(&req)?;
    info!(host = %target.0, port = target.1, "dialing upstream");

    // Outbound destination filter (SSRF defense). Resolve the host
    // ourselves and pass the chosen IP literal to TcpStream::connect
    // so a malicious resolver can't swap it for an internal IP
    // between our policy check and the dial.
    let dial_addr: std::net::SocketAddr = if let Some(filter) = cfg.outbound_filter.as_ref() {
        // Resolve via the bounded helper so a wedged recursive
        // resolver can't pin this relay task. The stats counter
        // is opt-in (only set when the metrics layer wired one
        // in); when None we still get the timeout but the counter
        // increments are silent.
        let resolved = if let Some(stats) = cfg.dns_resolver_stats.as_ref() {
            proteus_transport_alpha::outbound_filter::resolve_host_with_timeout(
                target.0.as_str(),
                target.1,
                std::time::Duration::from_secs(
                    proteus_transport_alpha::outbound_filter::DEFAULT_DNS_LOOKUP_TIMEOUT_SECS,
                ),
                stats,
            )
            .await
        } else {
            proteus_transport_alpha::outbound_filter::resolve_host(target.0.as_str(), target.1)
                .await
        };
        match filter.check(target.0.as_str(), target.1, &resolved) {
            Decision::Allow(ip) => std::net::SocketAddr::new(ip, target.1),
            other => {
                warn!(
                    host = %target.0,
                    port = target.1,
                    decision = ?other,
                    "outbound dial blocked by destination filter"
                );
                if let Some(m) = cfg.metrics.as_ref() {
                    m.outbound_blocked
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                let _ = sender.send_record(&[]).await;
                let _ = sender.flush().await;
                return Ok("outbound_blocked");
            }
        }
    } else {
        // No filter configured — fall back to the legacy "let the
        // OS resolver pick" behavior. ONLY safe for trusted-LAN /
        // testing deployments. Bounded by the same default 5s
        // timeout the outbound_filter path uses, so a wedged
        // recursive resolver can't pin the relay task here either.
        // The legacy path doesn't carry a DnsResolverStats counter
        // (the operator didn't opt into outbound_filter so they
        // implicitly didn't ask for SSRF-grade observability)
        // but we still emit a warn-level tracing event on timeout.
        let lookup_fut = tokio::net::lookup_host((target.0.as_str(), target.1));
        match tokio::time::timeout(
            std::time::Duration::from_secs(
                proteus_transport_alpha::outbound_filter::DEFAULT_DNS_LOOKUP_TIMEOUT_SECS,
            ),
            lookup_fut,
        )
        .await
        {
            Ok(Ok(mut addrs)) => match addrs.next() {
                Some(sa) => sa,
                None => {
                    warn!(host = %target.0, "upstream lookup_host returned no addrs");
                    let _ = sender.send_record(&[]).await;
                    let _ = sender.flush().await;
                    return Ok("upstream_dial_fail");
                }
            },
            Ok(Err(e)) => {
                warn!(host = %target.0, error = %e, "upstream lookup_host failed");
                let _ = sender.send_record(&[]).await;
                let _ = sender.flush().await;
                return Ok("upstream_dial_fail");
            }
            Err(_) => {
                warn!(
                    host = %target.0,
                    "upstream lookup_host timed out — recursive resolver may be wedged"
                );
                let _ = sender.send_record(&[]).await;
                let _ = sender.flush().await;
                return Ok("upstream_dial_timeout");
            }
        }
    };

    // Bound the upstream dial — DNS hangs or unreachable targets must
    // not block the relay task indefinitely.
    let dial = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        TcpStream::connect(dial_addr),
    )
    .await;
    let upstream = match dial {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            warn!(error = %e, host = %target.0, "upstream dial failed");
            let _ = sender.send_record(&[]).await;
            let _ = sender.flush().await;
            return Ok("upstream_dial_fail");
        }
        Err(_) => {
            warn!(host = %target.0, "upstream dial timed out");
            let _ = sender.send_record(&[]).await;
            let _ = sender.flush().await;
            return Ok("upstream_dial_timeout");
        }
    };
    // Apply nodelay + TCP keepalive on the upstream socket so:
    //   * small writes (HTTP/2 control frames, SSH echo) don't
    //     wait on Nagle when crossing a high-RTT path
    //   * long-idle relays (persistent SSH tunnel, HTTP/2
    //     long-poll, websocket idle) survive NAT idle-timer
    //     reaping — without keepalive the upstream socket
    //     silently goes half-open after typically 2-30 minutes
    //     of inactivity and the next write fails with EPIPE.
    //
    // Iter-14: both options applied via the shared
    // `socket_opts::apply_dial_socket_opts` helper; pre-iter-14
    // we only set nodelay and left keepalive disabled, leading
    // to the silent-half-open class of bugs.
    let dial_opts = proteus_transport_alpha::socket_opts::apply_dial_socket_opts(
        &upstream,
        cfg.tcp_keepalive_secs.unwrap_or(30),
    );
    if let Some(e) = dial_opts.nodelay_err {
        warn!(error = %e, host = %target.0, "upstream TCP_NODELAY failed (proceeding)");
    }
    if let Some(e) = dial_opts.keepalive_err {
        warn!(
            error = %e,
            host = %target.0,
            "upstream TCP keepalive failed (proceeding — connection may silently die in NAT idle)"
        );
    }
    let (mut up_r, mut up_w) = upstream.into_split();

    // Bidirectional pump. Each direction is independently bounded by
    // `cfg.idle_timeout`: a direction that goes idle longer than this
    // window shuts itself down (which causes the joined task to
    // finish, releasing the session's FDs and crypto state).
    //
    // Both halves write a close-reason into `reason_cell` on exit;
    // first writer wins. The outer body returns whichever reason
    // landed there (or "session_closed" as a default).
    let idle = cfg.idle_timeout;
    let reason_cell: std::sync::Arc<std::sync::Mutex<Option<&'static str>>> =
        std::sync::Arc::new(std::sync::Mutex::new(None));
    fn set_reason(cell: &std::sync::Mutex<Option<&'static str>>, r: &'static str) {
        if let Ok(mut g) = cell.lock() {
            if g.is_none() {
                *g = Some(r);
            }
        }
    }

    // Per-session byte budget. `bytes_used` is the cumulative
    // plaintext byte count across BOTH directions; reaching `cap`
    // tears down the whole session. Defaults to no limit.
    let byte_cap = cfg.max_session_bytes;
    let bytes_used: std::sync::Arc<std::sync::atomic::AtomicU64> =
        std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));

    let metrics_c2u = metrics.clone();
    let reason_c2u = std::sync::Arc::clone(&reason_cell);
    let bytes_c2u = std::sync::Arc::clone(&bytes_used);
    let client_to_upstream = async move {
        loop {
            let recv = receiver.recv_record();
            let next = match idle {
                Some(d) => match tokio::time::timeout(d, recv).await {
                    Ok(r) => r,
                    Err(_) => {
                        warn!(idle_secs = d.as_secs(), "client→upstream idle timeout");
                        if let Some(m) = metrics_c2u.as_ref() {
                            m.session_idle_reaped
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        set_reason(&reason_c2u, "idle_timeout");
                        break;
                    }
                },
                None => recv.await,
            };
            match next {
                Ok(Some(buf)) if !buf.is_empty() => {
                    // Bump-then-check: even if the cap is exceeded
                    // mid-write, we still finish this one buffer so the
                    // upstream sees a consistent stream boundary, but
                    // the next iteration tears down.
                    let new_total = bytes_c2u
                        .fetch_add(buf.len() as u64, std::sync::atomic::Ordering::Relaxed)
                        + buf.len() as u64;
                    if up_w.write_all(&buf).await.is_err() {
                        set_reason(&reason_c2u, "upstream_write_fail");
                        break;
                    }
                    if let Some(cap) = byte_cap {
                        if new_total >= cap {
                            warn!(
                                bytes = new_total,
                                cap, "session byte budget exhausted (client→upstream)"
                            );
                            if let Some(m) = metrics_c2u.as_ref() {
                                m.session_byte_budget_exhausted
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                            set_reason(&reason_c2u, "byte_budget_exhausted");
                            break;
                        }
                    }
                }
                Ok(Some(_empty)) => {} // keepalive
                Ok(None) => {
                    set_reason(&reason_c2u, "client_close");
                    break;
                }
                Err(_) => {
                    set_reason(&reason_c2u, "client_recv_err");
                    break;
                }
            }
        }
        let _ = up_w.shutdown().await;
    };
    let metrics_u2c = metrics.clone();
    let reason_u2c = std::sync::Arc::clone(&reason_cell);
    let bytes_u2c = std::sync::Arc::clone(&bytes_used);
    let upstream_to_client = async move {
        // 64 KiB to match AlphaSender::TX_BUF_CAPACITY: a full read
        // can fill the BufWriter and consecutive full reads coalesce
        // cleanly without exceeding it. Pre-iter-12 this was 16 KiB,
        // which split bulk responses (HTTP/2 long-poll, file
        // downloads, video chunks) across 4× the records strictly
        // needed.
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let read_fut = up_r.read(&mut buf);
            let n = match idle {
                Some(d) => match tokio::time::timeout(d, read_fut).await {
                    Ok(Ok(0)) => {
                        set_reason(&reason_u2c, "upstream_eof");
                        break;
                    }
                    Ok(Err(_)) => {
                        set_reason(&reason_u2c, "upstream_read_err");
                        break;
                    }
                    Ok(Ok(n)) => n,
                    Err(_) => {
                        warn!(idle_secs = d.as_secs(), "upstream→client idle timeout");
                        if let Some(m) = metrics_u2c.as_ref() {
                            m.session_idle_reaped
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        set_reason(&reason_u2c, "idle_timeout");
                        break;
                    }
                },
                None => match read_fut.await {
                    Ok(0) => {
                        set_reason(&reason_u2c, "upstream_eof");
                        break;
                    }
                    Err(_) => {
                        set_reason(&reason_u2c, "upstream_read_err");
                        break;
                    }
                    Ok(n) => n,
                },
            };
            let new_total =
                bytes_u2c.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed) + n as u64;
            if sender.send_record(&buf[..n]).await.is_err() {
                set_reason(&reason_u2c, "client_send_err");
                break;
            }
            // Adaptive flush (iter 12): only when the read returned
            // LESS than the buffer (= source paused, natural batch
            // boundary). A full-capacity read implies more bytes are
            // queued at the source — coalesce with the next chunk by
            // skipping the flush and letting the BufWriter
            // accumulate. Interactive RPC sees no added latency
            // because its reads are short; bulk transfer reclaims
            // the syscall + record-framing overhead it was wasting.
            if n < buf.len() && sender.flush().await.is_err() {
                set_reason(&reason_u2c, "client_send_err");
                break;
            }
            if let Some(cap) = byte_cap {
                if new_total >= cap {
                    warn!(
                        bytes = new_total,
                        cap, "session byte budget exhausted (upstream→client)"
                    );
                    if let Some(m) = metrics_u2c.as_ref() {
                        m.session_byte_budget_exhausted
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    set_reason(&reason_u2c, "byte_budget_exhausted");
                    break;
                }
            }
        }
        // Notify the peer that we are intentionally closing the inner
        // stream so it can distinguish a clean upstream-EOF from a
        // mid-session crash.
        let _ = sender
            .send_close(proteus_spec::close_error::NO_ERROR, b"upstream eof")
            .await;
        let _ = sender.shutdown().await;
    };

    // `tokio::select!` (NOT `tokio::join!`) so a unilateral close of
    // one direction tears down the other.
    //
    // Bug history: until commit 53c8dfc the client-side SOCKS5 pump
    // used `tokio::join!` here too. When the SOCKS5 client closed
    // its socket, the client→upstream half exited but the
    // upstream→client half blocked forever on `recv_record()` —
    // sessions leaked their permits permanently. The same class of
    // bug existed here on the server: when the upstream returned
    // EOF (e.g. an HTTP server replied with full content and closed),
    // `upstream_to_client` exited and sent a CLOSE record, but
    // `client_to_upstream` kept blocking on `recv_record()` because
    // the client never sent its own CLOSE. Sessions leaked → server's
    // `max_connections` semaphore filled up → server stopped
    // accepting new connections.
    //
    // `select!` drops the losing future when one branch wins; dropping
    // the future releases the captured `receiver` / `up_r` / etc.,
    // unblocking the underlying read futures. Both halves are
    // already structured to set a clean close reason before exiting,
    // so `reason_cell` still reports correctly.
    // Auto-quarantine cancel future. When no quarantine list is
    // wired (or the session has no user_id), we still need a
    // future to satisfy the select! branch — use a never-resolving
    // pending() so the branch is effectively disabled. When the
    // notify IS wired, this branch fires the moment
    // `qlist.tear_down_user(uid)` is called for this user_id
    // (typically on a fresh quarantine insert for that user).
    let cancel_fut = async {
        match session_cancel.as_ref() {
            Some(n) => n.notified().await,
            None => std::future::pending::<()>().await,
        }
    };
    tokio::pin!(cancel_fut);
    tokio::select! {
        _ = client_to_upstream => {
            // Client closed (or upstream write failed). Upstream side
            // is dropped here as the losing future unwinds.
        }
        _ = upstream_to_client => {
            // Upstream EOF (or send-to-client failed). The CLOSE
            // record was already emitted by upstream_to_client; the
            // client→upstream future is dropped here, cancelling its
            // `recv_record()` cleanly.
        }
        _ = &mut cancel_fut => {
            // Auto-quarantine fired for this session's user_id.
            // Set a distinct close_reason so the access log + the
            // outer handle_session see "session was killed by
            // quarantine" — operators reading access logs can
            // grep `quarantine_tear_down` to find every mid-burst
            // exfil that was interrupted.
            if let Ok(mut g) = reason_cell.lock() {
                *g = Some("quarantine_tear_down");
            }
        }
    }
    debug!("session closed");
    let reason = reason_cell
        .lock()
        .ok()
        .and_then(|g| *g)
        .unwrap_or("session_closed");
    Ok(reason)
}

/// Encode a CONNECT request the way the client transmits it. Public
/// for integration tests that need to drive `handle_session` end-to-end.
#[must_use]
#[allow(dead_code)] // used by integration tests via the lib target
pub fn encode_connect(host: &str, port: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + host.len() + 2);
    buf.push(u8::try_from(host.len()).expect("connect host > 255 bytes"));
    buf.extend_from_slice(host.as_bytes());
    buf.extend_from_slice(&port.to_be_bytes());
    buf
}

fn parse_connect(buf: &[u8]) -> Result<(String, u16), Box<dyn std::error::Error + Send + Sync>> {
    if buf.is_empty() {
        return Err("empty connect request".into());
    }
    let host_len = buf[0] as usize;
    if buf.len() < 1 + host_len + 2 {
        return Err("connect request truncated".into());
    }
    let host = std::str::from_utf8(&buf[1..1 + host_len])
        .map_err(|_| "host not valid utf-8")?
        .to_string();
    let port = u16::from_be_bytes([buf[1 + host_len], buf[1 + host_len + 1]]);
    Ok((host, port))
}
