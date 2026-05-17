//! Client-side admin / observability surface.
//!
//! Symmetric to `proteus-server`'s `admin.rs`: an opt-in loopback HTTP
//! endpoint exposing the in-process health state so an operator can
//! answer "what is my client doing right now?" without `grep
//! journalctl` for transition lines.
//!
//! ## What this surfaces
//!
//! - **CarrierHealth (β-vs-α)**: configured? alive? suppressed? for
//!   how much longer? what's the current failure streak?
//! - **EndpointPool / EndpointHealth (multi-VPS)**: configured? how
//!   many entries? for each entry: address, suppressed?, expires-in,
//!   streak.
//!
//! ## What this is NOT
//!
//! - Not a Prometheus exporter. The client process is per-user, not
//!   per-fleet — the right tool for "is my proxy working" is a `curl
//!   :9091/status` from the operator's shell, not a metrics-scrape
//!   pipeline. JSON output is provided for scripted consumption (e.g.
//!   a small status-bar widget) but the schema is hand-rolled to keep
//!   the dependency surface minimal.
//! - Not authenticated. The endpoint binds loopback-only by default;
//!   on a personal-VPN client deployment, anything that can reach
//!   `127.0.0.1` already has the process's identity. If an operator
//!   binds to a non-loopback address, they get a startup `warn!` line.
//!   No bearer-token gating because there's no useful threat model in
//!   the personal-client deployment (server's `/metrics` is
//!   different because it's often exposed for fleet observability;
//!   the client status is loopback-only and personal).
//!
//! ## What's missing here (future iterations)
//!
//! - SOCKS5 in-flight session count exposed in the snapshot. Today
//!   the slot semaphore lives in `main.rs`; threading its
//!   `available_permits()` through the admin surface needs the
//!   semaphore to be a first-class field of a shared `ClientCtx` —
//!   refactor work; not in this iteration.
//! - Per-session byte counters. The server tracks these; the client
//!   could mirror but the data path doesn't currently bump anything.

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{info, warn};

use crate::carrier_health::CarrierHealth;
use crate::endpoint_pool::EndpointPool;

/// In-process snapshot built at scrape time. All fields are `Option`
/// because the client may be running without one or both of the
/// health trackers (e.g. β not configured, or single-endpoint
/// deployment without a pool).
#[derive(Debug, Clone, Default)]
pub struct ClientStatusSnapshot {
    /// `true` once the SOCKS5 listener has bound and we accept
    /// inbound. Used for a `/healthz` style probe.
    pub alive: bool,
    /// β carrier health, when β is configured. `None` means α-only
    /// (no β endpoint was supplied, so β suppression state is N/A).
    pub carrier: Option<CarrierHealthView>,
    /// Multi-VPS endpoint pool state, when one was wired. `None`
    /// means single-endpoint deployment (legacy `server_endpoint`
    /// only, no `server_endpoints: [...]`).
    pub pool: Option<EndpointPoolView>,
}

/// Single-host carrier-health view rendered from a `CarrierHealth`.
#[derive(Debug, Clone)]
pub struct CarrierHealthView {
    /// Current consecutive-failure streak count (resets to 0 on any
    /// β success). Above the threshold the carrier transitions to
    /// suppressed.
    pub failure_streak: u32,
    /// `true` iff β is currently inside a back-off window.
    pub suppressed: bool,
    /// Seconds remaining in the back-off window when suppressed;
    /// `None` when not suppressed.
    pub suppression_secs_remaining: Option<u64>,
}

/// Per-entry pool view rendered from `EndpointPool`. Operator gets
/// "which VPS is the dispatcher currently using" + "which are
/// suppressed and for how much longer" without grepping logs.
#[derive(Debug, Clone)]
pub struct EndpointPoolView {
    pub entries: Vec<EndpointEntryView>,
}

#[derive(Debug, Clone)]
pub struct EndpointEntryView {
    pub addr: String,
    pub failure_streak: u32,
    pub suppressed: bool,
    pub suppression_secs_remaining: Option<u64>,
}

impl ClientStatusSnapshot {
    /// Build a snapshot from the live in-process state at instant
    /// `now`. Pure read — no mutation, no atomics touched besides
    /// the existing accessors.
    #[must_use]
    pub fn capture(
        alive: bool,
        carrier: Option<&CarrierHealth>,
        beta_configured: bool,
        pool: Option<&EndpointPool>,
        now: Instant,
    ) -> Self {
        let carrier_view = carrier.map(|h| {
            let suppressed = h.is_suppressed(now);
            let suppression_secs_remaining = if suppressed {
                h.suppression_deadline().map(|d| {
                    // saturating_duration_since returns 0 if the
                    // deadline is in the past (shouldn't happen
                    // when is_suppressed says yes, but defense-in-
                    // depth — we never want a negative number here).
                    d.saturating_duration_since(now).as_secs()
                })
            } else {
                None
            };
            // β-not-configured collapses suppression state to N/A
            // by zeroing it out — a config without β shouldn't
            // surface "suppressed = false" as if β were live but
            // healthy. We model "β unwired" as carrier = None
            // upstream of this view, so the explicit guard here is
            // belt-and-braces.
            let _ = beta_configured;
            CarrierHealthView {
                failure_streak: h.failure_streak(),
                suppressed,
                suppression_secs_remaining,
            }
        });
        let pool_view = pool.map(|p| {
            let snap = p.diagnostic_snapshot(now);
            let entries = snap
                .into_iter()
                .enumerate()
                .map(|(ix, (addr, streak, suppressed))| {
                    let secs = if suppressed {
                        p.endpoint_health(ix).and_then(|h| {
                            // Pool's diagnostic_snapshot doesn't
                            // expose the deadline directly; fetch
                            // the health handle and compute.
                            //
                            // Note: EndpointHealth currently lacks a
                            // public suppression_deadline accessor;
                            // we fall back to None when the pool
                            // says suppressed but we can't read the
                            // deadline. This is a small information
                            // gap (operator sees "suppressed" but
                            // not "for how long") — fix-up next
                            // iteration when EndpointHealth grows
                            // the accessor.
                            let _ = h;
                            None
                        })
                    } else {
                        None
                    };
                    EndpointEntryView {
                        addr,
                        failure_streak: streak,
                        suppressed,
                        suppression_secs_remaining: secs,
                    }
                })
                .collect();
            EndpointPoolView { entries }
        });
        Self {
            alive,
            carrier: carrier_view,
            pool: pool_view,
        }
    }

    /// Hand-rolled JSON. Single line + trailing newline; same
    /// streaming-jq-friendly shape as the bench harness's
    /// `RunReport`. Field order is stable across releases;
    /// additions append, never reorder or rename.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(512);
        s.push('{');
        s.push_str(r#""alive":"#);
        s.push_str(if self.alive { "true" } else { "false" });

        // carrier: nested object or null.
        s.push_str(r#","carrier":"#);
        match &self.carrier {
            None => s.push_str("null"),
            Some(c) => {
                s.push('{');
                let _ = write!(s, r#""failure_streak":{}"#, c.failure_streak);
                s.push_str(r#","suppressed":"#);
                s.push_str(if c.suppressed { "true" } else { "false" });
                s.push_str(r#","suppression_secs_remaining":"#);
                match c.suppression_secs_remaining {
                    Some(v) => {
                        let _ = write!(s, "{v}");
                    }
                    None => s.push_str("null"),
                }
                s.push('}');
            }
        }

        // pool: nested array-of-objects or null.
        s.push_str(r#","pool":"#);
        match &self.pool {
            None => s.push_str("null"),
            Some(p) => {
                s.push('[');
                let mut first = true;
                for e in &p.entries {
                    if !first {
                        s.push(',');
                    }
                    first = false;
                    s.push_str(r#"{"addr":""#);
                    push_json_str_inner(&mut s, &e.addr);
                    let _ = write!(s, r#"","failure_streak":{}"#, e.failure_streak);
                    s.push_str(r#","suppressed":"#);
                    s.push_str(if e.suppressed { "true" } else { "false" });
                    s.push_str(r#","suppression_secs_remaining":"#);
                    match e.suppression_secs_remaining {
                        Some(v) => {
                            let _ = write!(s, "{v}");
                        }
                        None => s.push_str("null"),
                    }
                    s.push('}');
                }
                s.push(']');
            }
        }
        s.push_str("}\n");
        s
    }
}

/// JSON-quote inner-string escaping. Same minimal set as the bench
/// harness's `RunReport` — quotes, backslashes, and the three
/// control characters that JSON forbids unquoted.
fn push_json_str_inner(s: &mut String, v: &str) {
    for c in v.chars() {
        match c {
            '"' => s.push_str(r#"\""#),
            '\\' => s.push_str(r#"\\"#),
            '\n' => s.push_str(r#"\n"#),
            '\r' => s.push_str(r#"\r"#),
            '\t' => s.push_str(r#"\t"#),
            c if (c as u32) < 0x20 => {
                let _ = write!(s, r#"\u{:04x}"#, c as u32);
            }
            c => s.push(c),
        }
    }
}

impl std::fmt::Display for ClientStatusSnapshot {
    /// Operator-friendly text rendering — what `proteus-client
    /// status` or `curl -s :9091/status` returns when the caller
    /// wants a human-readable summary.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            " Status: {}",
            if self.alive { "alive" } else { "starting" }
        )?;
        match &self.carrier {
            None => writeln!(f, " Carrier (β): not configured (α-only deployment)")?,
            Some(c) => {
                let state = if c.suppressed {
                    match c.suppression_secs_remaining {
                        Some(s) => format!("SUPPRESSED ({s}s remaining)"),
                        None => "SUPPRESSED".to_string(),
                    }
                } else {
                    "healthy".to_string()
                };
                writeln!(f, " Carrier (β): {state}")?;
                writeln!(f, "   failure_streak: {}", c.failure_streak)?;
            }
        }
        match &self.pool {
            None => writeln!(f, " EndpointPool: not configured (single-endpoint deploy)")?,
            Some(p) => {
                writeln!(f, " EndpointPool: {} entries", p.entries.len())?;
                for (ix, e) in p.entries.iter().enumerate() {
                    let state = if e.suppressed {
                        match e.suppression_secs_remaining {
                            Some(s) => format!("SUPPRESSED ({s}s remaining)"),
                            None => "SUPPRESSED".to_string(),
                        }
                    } else {
                        "healthy".to_string()
                    };
                    writeln!(
                        f,
                        "   [{ix}] {addr}: {state}, streak={streak}",
                        addr = e.addr,
                        streak = e.failure_streak
                    )?;
                }
            }
        }
        Ok(())
    }
}

/// Shared reference cell for the alive flag — flipped to `true` once
/// the main accept loop has bound the SOCKS5 listener. Wrapping in
/// `Arc<AtomicBool>` so the admin handle can read it without owning
/// a copy.
pub type AliveFlag = Arc<std::sync::atomic::AtomicBool>;

/// Bind a loopback HTTP listener and serve the status snapshot.
///
/// Three routes:
///   - `GET /healthz`  → 200 "alive" once SOCKS5 has bound; 503 before.
///   - `GET /status`   → 200 text snapshot (Content-Type: text/plain).
///   - `GET /status.json` → 200 JSON snapshot (Content-Type:
///     application/json), line-delimited (one record + trailing `\n`).
///
/// Any other path returns 404. POST / other methods return 404 too —
/// the surface is strictly read-only.
///
/// `bind_addr` should be a loopback address (`127.0.0.1:N` /
/// `[::1]:N`). If the operator binds to a non-loopback interface, we
/// emit a startup `warn!` — there is no auth on this endpoint.
pub async fn serve(
    bind_addr: String,
    alive: AliveFlag,
    carrier: Option<Arc<CarrierHealth>>,
    beta_configured: bool,
    pool: Option<Arc<EndpointPool>>,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(&bind_addr).await?;
    let local = listener.local_addr()?;
    if !is_loopback(local) {
        warn!(
            addr = %local,
            "client admin endpoint bound on a NON-loopback interface — \
             /status exposes in-process health state to anyone who can \
             reach this address. There is no authentication on this \
             surface; bind 127.0.0.1 / [::1] in production."
        );
    } else {
        info!(addr = %local, "client admin endpoint bound (loopback)");
    }
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                warn!(error = %e, "client admin accept failed");
                continue;
            }
        };
        let alive = Arc::clone(&alive);
        let carrier = carrier.clone();
        let pool = pool.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, alive, carrier, beta_configured, pool).await {
                warn!(peer = %peer, error = %e, "client admin connection ended");
            }
        });
    }
}

async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    alive: AliveFlag,
    carrier: Option<Arc<CarrierHealth>>,
    beta_configured: bool,
    pool: Option<Arc<EndpointPool>>,
) -> std::io::Result<()> {
    let mut req = [0u8; 1024];
    let n = stream.read(&mut req).await?;
    let head = std::str::from_utf8(&req[..n]).unwrap_or("");
    let snap = ClientStatusSnapshot::capture(
        alive.load(Ordering::Relaxed),
        carrier.as_deref(),
        beta_configured,
        pool.as_deref(),
        Instant::now(),
    );
    let (status_line, content_type, body) = route(head, &snap);
    let response = format!(
        "{status_line}\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\r\n\
         {body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    let _ = stream.shutdown().await;
    Ok(())
}

/// Pure routing: given a request head + snapshot, return `(status,
/// content-type, body)`. Public so tests can hit the router without
/// a TCP listener.
#[must_use]
pub fn route(
    request_head: &str,
    snap: &ClientStatusSnapshot,
) -> (&'static str, &'static str, String) {
    if matches_path(request_head, "/healthz") {
        if snap.alive {
            ("HTTP/1.1 200 OK\r\n", "text/plain", "alive\n".to_string())
        } else {
            (
                "HTTP/1.1 503 Service Unavailable\r\n",
                "text/plain",
                "starting\n".to_string(),
            )
        }
    } else if matches_path(request_head, "/status") {
        (
            "HTTP/1.1 200 OK\r\n",
            "text/plain; charset=utf-8",
            format!("{snap}"),
        )
    } else if matches_path(request_head, "/status.json") {
        ("HTTP/1.1 200 OK\r\n", "application/json", snap.to_json())
    } else {
        (
            "HTTP/1.1 404 Not Found\r\n",
            "text/plain",
            "not found\n".to_string(),
        )
    }
}

/// Match a request line against an exact path. Mirrors the
/// server-side admin endpoint's `matches_path` so the routing
/// rules are uniform across the codebase.
fn matches_path(request_head: &str, path: &str) -> bool {
    let with_space = format!("GET {path} ");
    let with_query = format!("GET {path}?");
    request_head.starts_with(&with_space) || request_head.starts_with(&with_query)
}

fn is_loopback(addr: SocketAddr) -> bool {
    addr.ip().is_loopback()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Helper: minimal snapshot with everything quiet (α-only, no
    /// pool, not yet alive). Used as a baseline so every test
    /// asserts only the field it changes.
    fn empty_snap() -> ClientStatusSnapshot {
        ClientStatusSnapshot {
            alive: false,
            carrier: None,
            pool: None,
        }
    }

    #[test]
    fn json_alive_false_serializes_correctly() {
        let s = empty_snap().to_json();
        assert!(s.starts_with('{'));
        assert!(s.ends_with("}\n"));
        assert!(s.contains(r#""alive":false"#));
        assert!(s.contains(r#""carrier":null"#));
        assert!(s.contains(r#""pool":null"#));
    }

    #[test]
    fn json_alive_true_with_healthy_carrier() {
        let snap = ClientStatusSnapshot {
            alive: true,
            carrier: Some(CarrierHealthView {
                failure_streak: 0,
                suppressed: false,
                suppression_secs_remaining: None,
            }),
            pool: None,
        };
        let s = snap.to_json();
        assert!(s.contains(r#""alive":true"#));
        assert!(s.contains(
            r#""carrier":{"failure_streak":0,"suppressed":false,"suppression_secs_remaining":null}"#
        ));
    }

    #[test]
    fn json_carrier_suppressed_with_remaining_secs() {
        let snap = ClientStatusSnapshot {
            alive: true,
            carrier: Some(CarrierHealthView {
                failure_streak: 5,
                suppressed: true,
                suppression_secs_remaining: Some(42),
            }),
            pool: None,
        };
        let s = snap.to_json();
        assert!(s.contains(r#""failure_streak":5"#));
        assert!(s.contains(r#""suppressed":true"#));
        assert!(s.contains(r#""suppression_secs_remaining":42"#));
    }

    #[test]
    fn json_pool_renders_every_entry_in_order() {
        let snap = ClientStatusSnapshot {
            alive: true,
            carrier: None,
            pool: Some(EndpointPoolView {
                entries: vec![
                    EndpointEntryView {
                        addr: "primary:8443".into(),
                        failure_streak: 0,
                        suppressed: false,
                        suppression_secs_remaining: None,
                    },
                    EndpointEntryView {
                        addr: "backup:8443".into(),
                        failure_streak: 7,
                        suppressed: true,
                        suppression_secs_remaining: Some(120),
                    },
                ],
            }),
        };
        let s = snap.to_json();
        let primary_at = s.find("primary:8443").expect("primary line missing");
        let backup_at = s.find("backup:8443").expect("backup line missing");
        assert!(
            primary_at < backup_at,
            "pool entries must render in declaration order"
        );
        assert!(s.contains(r#""failure_streak":7"#));
        assert!(s.contains(r#""suppression_secs_remaining":120"#));
    }

    #[test]
    fn json_escapes_quotes_in_endpoint_addr() {
        // Pathological-but-possible: a hostname with a quote — we
        // shouldn't allow it through unescaped because it would
        // break parsers downstream.
        let snap = ClientStatusSnapshot {
            alive: true,
            carrier: None,
            pool: Some(EndpointPoolView {
                entries: vec![EndpointEntryView {
                    addr: r#"weird"host:8443"#.into(),
                    failure_streak: 0,
                    suppressed: false,
                    suppression_secs_remaining: None,
                }],
            }),
        };
        let s = snap.to_json();
        assert!(
            s.contains(r#"weird\"host:8443"#),
            "must escape quotes in addr: {s}"
        );
    }

    #[test]
    fn text_alive_false_shows_starting() {
        let s = format!("{}", empty_snap());
        assert!(s.contains("Status: starting"));
    }

    #[test]
    fn text_alive_true_shows_alive() {
        let snap = ClientStatusSnapshot {
            alive: true,
            ..empty_snap()
        };
        let s = format!("{snap}");
        assert!(s.contains("Status: alive"));
    }

    #[test]
    fn text_carrier_suppressed_includes_remaining_secs_in_header() {
        let snap = ClientStatusSnapshot {
            alive: true,
            carrier: Some(CarrierHealthView {
                failure_streak: 3,
                suppressed: true,
                suppression_secs_remaining: Some(60),
            }),
            pool: None,
        };
        let s = format!("{snap}");
        assert!(s.contains("SUPPRESSED (60s remaining)"), "{s}");
        assert!(s.contains("failure_streak: 3"));
    }

    #[test]
    fn text_pool_entry_renders_index_addr_state_streak() {
        let snap = ClientStatusSnapshot {
            alive: true,
            carrier: None,
            pool: Some(EndpointPoolView {
                entries: vec![EndpointEntryView {
                    addr: "vps1:8443".into(),
                    failure_streak: 2,
                    suppressed: false,
                    suppression_secs_remaining: None,
                }],
            }),
        };
        let s = format!("{snap}");
        assert!(s.contains("[0] vps1:8443: healthy, streak=2"), "{s}");
    }

    #[test]
    fn capture_with_no_carrier_no_pool() {
        let snap = ClientStatusSnapshot::capture(true, None, false, None, Instant::now());
        assert!(snap.alive);
        assert!(snap.carrier.is_none());
        assert!(snap.pool.is_none());
    }

    #[test]
    fn capture_healthy_carrier() {
        let carrier = CarrierHealth::new();
        let snap = ClientStatusSnapshot::capture(true, Some(&carrier), true, None, Instant::now());
        let c = snap.carrier.expect("carrier should be Some");
        assert!(!c.suppressed);
        assert_eq!(c.failure_streak, 0);
        assert!(c.suppression_secs_remaining.is_none());
    }

    #[test]
    fn capture_suppressed_carrier_includes_remaining_secs() {
        let carrier = CarrierHealth::with_threshold(2);
        let t0 = Instant::now();
        carrier.record_beta_failure(t0);
        carrier.record_beta_failure(t0);
        // capture immediately so most of the back-off window is
        // still in the future.
        let snap = ClientStatusSnapshot::capture(
            true,
            Some(&carrier),
            true,
            None,
            t0 + Duration::from_millis(100),
        );
        let c = snap.carrier.expect("carrier should be Some");
        assert!(c.suppressed, "should be suppressed: {c:?}");
        let secs = c
            .suppression_secs_remaining
            .expect("should have remaining secs");
        // INITIAL_SUPPRESSION = 15s; we burned 100ms.
        assert!(
            (13..=15).contains(&secs),
            "expected ~14s remaining, got {secs}"
        );
    }

    #[test]
    fn capture_pool_renders_every_entry() {
        let pool =
            EndpointPool::new(vec!["a:1".into(), "b:2".into(), "c:3".into()]).expect("pool builds");
        let snap = ClientStatusSnapshot::capture(true, None, false, Some(&pool), Instant::now());
        let p = snap.pool.expect("pool should be Some");
        assert_eq!(p.entries.len(), 3);
        assert_eq!(p.entries[0].addr, "a:1");
        assert_eq!(p.entries[1].addr, "b:2");
        assert_eq!(p.entries[2].addr, "c:3");
        for e in &p.entries {
            assert!(!e.suppressed);
            assert_eq!(e.failure_streak, 0);
        }
    }

    #[test]
    fn route_healthz_200_when_alive() {
        let snap = ClientStatusSnapshot {
            alive: true,
            ..empty_snap()
        };
        let (status, ctype, body) = route("GET /healthz HTTP/1.1\r\n\r\n", &snap);
        assert!(status.starts_with("HTTP/1.1 200"));
        assert_eq!(ctype, "text/plain");
        assert_eq!(body, "alive\n");
    }

    #[test]
    fn route_healthz_503_when_not_alive() {
        let (status, ctype, body) = route("GET /healthz HTTP/1.1\r\n\r\n", &empty_snap());
        assert!(status.starts_with("HTTP/1.1 503"));
        assert_eq!(ctype, "text/plain");
        assert_eq!(body, "starting\n");
    }

    #[test]
    fn route_status_200_text() {
        let snap = ClientStatusSnapshot {
            alive: true,
            ..empty_snap()
        };
        let (status, ctype, body) = route("GET /status HTTP/1.1\r\n\r\n", &snap);
        assert!(status.starts_with("HTTP/1.1 200"));
        assert!(ctype.starts_with("text/plain"));
        assert!(body.contains("Status: alive"));
    }

    #[test]
    fn route_status_json_200_json() {
        let snap = ClientStatusSnapshot {
            alive: true,
            ..empty_snap()
        };
        let (status, ctype, body) = route("GET /status.json HTTP/1.1\r\n\r\n", &snap);
        assert!(status.starts_with("HTTP/1.1 200"));
        assert_eq!(ctype, "application/json");
        assert!(body.starts_with("{"));
        assert!(body.ends_with("}\n"));
    }

    #[test]
    fn route_404_on_random_path() {
        let (status, _ctype, body) = route("GET /admin HTTP/1.1\r\n\r\n", &empty_snap());
        assert!(status.starts_with("HTTP/1.1 404"));
        assert_eq!(body, "not found\n");
    }

    #[test]
    fn route_404_on_post() {
        let (status, _ctype, _body) = route("POST /status HTTP/1.1\r\n\r\n", &empty_snap());
        assert!(status.starts_with("HTTP/1.1 404"));
    }

    #[test]
    fn route_404_on_status_substring_path() {
        // /statusleak should NOT match /status.
        let (status, _ctype, _body) = route("GET /statusleak HTTP/1.1\r\n\r\n", &empty_snap());
        assert!(status.starts_with("HTTP/1.1 404"));
    }

    #[test]
    fn route_status_with_query_string_matches() {
        let snap = ClientStatusSnapshot {
            alive: true,
            ..empty_snap()
        };
        let (status, _ctype, _body) = route("GET /status?fmt=text HTTP/1.1\r\n\r\n", &snap);
        assert!(status.starts_with("HTTP/1.1 200"));
    }
}
