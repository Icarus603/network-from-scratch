//! Proteus α-profile client binary.
//!
//! Provides a local SOCKS5 listener that tunnels every accepted SOCKS5
//! CONNECT request through a Proteus α-profile session to the remote
//! Proteus server, which relays to the user-requested upstream.
//!
//! ```bash
//! proteus-client --config /etc/proteus/client.yaml
//! curl --socks5 127.0.0.1:1080 https://example.com/
//! ```

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

mod keygen;

use proteus_client::admin::{self, AliveFlag};
use proteus_client::carrier_health::CarrierHealth;
use proteus_client::config::ClientConfig;
use proteus_client::ctx::ClientCtx;
use proteus_client::endpoint_pool::EndpointPool;
use proteus_client::socks;
use std::sync::atomic::AtomicBool;

#[derive(Parser, Debug)]
#[command(version, about = "Proteus α-profile client")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(clap::Subcommand, Debug)]
enum Cmd {
    /// Generate a fresh Ed25519 identity keypair.
    Keygen {
        #[arg(long, default_value = "./keys/client")]
        out: PathBuf,
    },
    /// Run the SOCKS5 inbound + Proteus outbound.
    Run {
        #[arg(long, default_value = "/etc/proteus/client.yaml")]
        config: PathBuf,
    },
    /// Preflight: parse `client.yaml`, check every referenced file
    /// exists and decodes to the right size, sanity-check β coherence.
    /// Exit code 0 on green, 1 on any FAIL — suitable for CI / Ansible
    /// pre-deploy gates.
    Validate {
        /// Path to the YAML file to validate. Positional, like the
        /// server-side `proteus-server validate <path>`.
        path: PathBuf,
    },
    /// Query a running `proteus-client`'s admin endpoint for the
    /// in-process health snapshot (CarrierHealth + EndpointPool
    /// state). Requires the client to have been started with
    /// `admin_listen:` set in `client.yaml`.
    ///
    /// Mirrors the server-side `proteus-server admin status`
    /// workflow — operator answers "is my client actually working?"
    /// without grepping journalctl for transition logs.
    Status {
        /// Admin endpoint URL. Default points at the recommended
        /// loopback bind. Format: `http://HOST:PORT`. The client
        /// will append `/status` (text) or `/status.json` (JSON).
        #[arg(long, default_value = "http://127.0.0.1:9091")]
        url: String,
        /// Output format: `text` (default) or `json`.
        #[arg(long, default_value = "text")]
        format: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Keygen { out } => keygen::run(&out)?,
        Cmd::Run { config } => run(&config).await?,
        Cmd::Validate { path } => {
            let code = proteus_client::validate::cli_run(&path).await?;
            std::process::exit(code);
        }
        Cmd::Status { url, format } => status_cmd(&url, &format).await?,
    }
    Ok(())
}

/// `proteus-client status` — hit a running client's admin endpoint
/// and print the snapshot. Uses a hand-rolled HTTP/1.1 client (no
/// reqwest pull-in for one GET) — keeps the binary's dep surface
/// tight.
async fn status_cmd(url: &str, format: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = match format {
        "text" | "human" => "/status",
        "json" => "/status.json",
        other => {
            return Err(format!("unknown --format {other:?} (expected 'text' or 'json')").into());
        }
    };
    let (host, port, base_path) = parse_http_url(url)?;
    let request_path = if base_path == "/" {
        path.to_string()
    } else {
        // Compose; an operator who wrote `http://host:port/proxy` gets
        // `/proxy/status` etc. Unusual but harmless to support.
        format!("{base_path}{path}")
    };
    let req = format!(
        "GET {request_path} HTTP/1.1\r\n\
         Host: {host}:{port}\r\n\
         User-Agent: proteus-client-status/1\r\n\
         Accept: */*\r\n\
         Connection: close\r\n\r\n"
    );
    let mut stream = tokio::net::TcpStream::connect((host.as_str(), port)).await?;
    tokio::io::AsyncWriteExt::write_all(&mut stream, req.as_bytes()).await?;
    let mut buf = Vec::with_capacity(4096);
    tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut buf).await?;
    // Split off the headers; print only the body so a `--format json`
    // call yields parseable JSON straight to stdout.
    let s = std::str::from_utf8(&buf).map_err(|e| format!("non-UTF8 response: {e}"))?;
    let (status_line, body) = split_http_response(s)?;
    if !status_line.starts_with("HTTP/1.1 200") {
        return Err(format!("admin endpoint returned: {status_line}").into());
    }
    // Body already ends with newline from the server side; don't add another.
    print!("{body}");
    Ok(())
}

/// Parse `http://host:port` or `http://host:port/path`. We only
/// accept HTTP (not HTTPS) — the admin endpoint is loopback-only.
/// Returns `(host, port, path)`; `path` defaults to `"/"`.
fn parse_http_url(url: &str) -> Result<(String, u16, String), String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| format!("only http:// URLs supported (got {url:?})"))?;
    let (authority, path) = match rest.find('/') {
        Some(ix) => (&rest[..ix], rest[ix..].to_string()),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse::<u16>()
                .map_err(|e| format!("bad port in {url:?}: {e}"))?,
        ),
        None => {
            return Err(format!(
                "URL must include explicit port (got {url:?}); admin endpoint requires `host:port`"
            ));
        }
    };
    Ok((host, port, path))
}

/// Split a complete HTTP/1.1 response on `\r\n\r\n` and return
/// `(first status line, body)`. The status line is the first line of
/// the response (everything up to the first `\r\n`).
fn split_http_response(s: &str) -> Result<(&str, &str), String> {
    let break_at = s
        .find("\r\n\r\n")
        .ok_or_else(|| "no header/body separator in HTTP response".to_string())?;
    let status_end = s
        .find("\r\n")
        .ok_or_else(|| "no status line in HTTP response".to_string())?;
    Ok((&s[..status_end], &s[break_at + 4..]))
}

async fn run(config_path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let cfg = Arc::new(ClientConfig::load(config_path).await?);
    info!(
        server = %cfg.server_endpoint,
        socks = %cfg.socks_listen,
        "proteus-client starting"
    );

    let listener = TcpListener::bind(&cfg.socks_listen).await?;
    info!(addr = %listener.local_addr()?, "SOCKS5 inbound bound");

    // Single per-process carrier-health tracker for the β path.
    // Lives across CONNECTs so back-off survives the SOCKS5
    // request boundary — see `carrier_health.rs` for the policy.
    let health = Arc::new(CarrierHealth::new());

    // Process-wide alive flag. Flipped to true once the SOCKS5
    // listener has bound (above). The admin endpoint reads this for
    // /healthz. We flip BEFORE spawning the admin task so the
    // first scrape after admin-listener bind sees alive=true.
    let alive: AliveFlag = Arc::new(AtomicBool::new(true));
    // beta_configured is read once and shared via ClientCtx so the
    // admin snapshot and the dispatch path agree on whether β is
    // wired (vs. legacy paths that recomputed from cfg each time).
    let beta_configured = cfg.server_endpoint_beta.is_some();

    // Multi-VPS HA endpoint pool (operator-opt-in via
    // `server_endpoints: [...]` in client.yaml). When unset or
    // empty, dispatch falls back to the single `server_endpoint`
    // path (pre-pool behavior). When set, every CONNECT walks the
    // pool with per-endpoint health tracking — automatic failover
    // around any single-VPS outage without operator intervention.
    let endpoint_pool: Option<Arc<EndpointPool>> = if cfg.server_endpoints.is_empty() {
        None
    } else {
        let pool = EndpointPool::new(cfg.server_endpoints.clone()).map(Arc::new);
        if let Some(p) = &pool {
            info!(
                entries = p.len(),
                "multi-VPS endpoint pool wired — dispatch will failover across entries"
            );
        }
        pool
    };

    // ----- Concurrency cap -----
    //
    // Each in-flight SOCKS5 session holds one upstream Proteus session
    // (16 MiB rx-buffer ceiling) plus one SOCKS5 socket. Without a cap,
    // a burst of local SOCKS5 clients (legitimate misconfigured app or
    // a local-network attacker who can reach `socks_listen`) can OOM
    // the client process before any rate-limit fires.
    //
    // `max_inflight_sessions = 0` disables the cap (not recommended).
    // Default 1024 sessions ≈ 16 GiB worst-case memory ceiling.
    let max_inflight = cfg.max_inflight_sessions.unwrap_or(1024);
    let session_slots = if max_inflight == 0 {
        None
    } else {
        Some(Arc::new(Semaphore::new(max_inflight)))
    };
    if let Some(s) = &session_slots {
        info!(
            max_inflight = max_inflight,
            "concurrent-session cap configured"
        );
        let _ = s; // hold-handle for clarity in logs.
    } else {
        warn!("max_inflight_sessions=0 — concurrency cap disabled, vulnerable to local OOM");
    }

    // ----- ClientCtx assembly -----
    //
    // Everything the dispatch path and admin endpoint need to share
    // (carrier health, endpoint pool, session slots, dial counters)
    // lives in one struct from here on. Built AFTER the concurrency
    // cap is decided so `max_inflight` is final; built BEFORE the
    // admin endpoint spawn so the admin's first scrape sees the
    // real ctx (not a placeholder).
    let ctx = Arc::new(ClientCtx::new(
        Arc::clone(&health),
        endpoint_pool.clone(),
        session_slots.clone(),
        max_inflight,
        beta_configured,
    ));

    // ----- Admin HTTP endpoint -----
    //
    // Operator-opt-in via `admin_listen:` in client.yaml. When set,
    // spawn a loopback HTTP server exposing /healthz + /status +
    // /status.json. Disabled by default — operators who don't want
    // the extra port don't pay for it.
    if let Some(admin_addr) = cfg.admin_listen.clone() {
        let alive_for_admin = Arc::clone(&alive);
        let ctx_for_admin = Arc::clone(&ctx);
        tokio::spawn(async move {
            if let Err(e) = admin::serve_with_ctx(admin_addr, alive_for_admin, ctx_for_admin).await
            {
                warn!(error = %e, "client admin endpoint exited");
            }
        });
    }

    // ----- SIGHUP — hot-reload `server_endpoints:` from disk -----
    //
    // Mirrors the server-side SIGHUP-reload pattern (TLS cert,
    // firewall, rate limits). On SIGHUP:
    //   1. Re-read the YAML from `config_path`.
    //   2. Build a fresh EndpointPool from the new `server_endpoints`
    //      using `new_with_carryover` so unchanged entries keep
    //      their per-endpoint counters + suppression state.
    //   3. Atomically swap it into the ReloadablePool — every NEW
    //      CONNECT after the swap sees the new list; in-flight
    //      sessions complete on their already-chosen endpoint.
    //
    // What this DOESN'T reload (yet — explicit non-goals here):
    //   - `server_endpoint` (single) — operators using pool mode
    //     don't need it; operators using single mode restart.
    //   - `socks_listen` — would require listener re-bind.
    //   - TLS / bootstrap_dns keys — quinn / rustls don't expose
    //     a hot-swap API on existing connections.
    //   - β endpoint perf knobs — same reason.
    //
    // Operator workflow: edit client.yaml's `server_endpoints:`
    // list, then `killall -HUP proteus-client`. Watch
    // `/status.json` for the new entries + carryover counter
    // verification.
    {
        let config_path = config_path.to_path_buf();
        let ctx_for_reload = Arc::clone(&ctx);
        tokio::spawn(async move {
            let mut sighup = match tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::hangup(),
            ) {
                Ok(s) => s,
                Err(e) => {
                    warn!(error = %e, "install SIGHUP handler failed; pool hot-reload disabled");
                    return;
                }
            };
            while sighup.recv().await.is_some() {
                info!("SIGHUP received — reloading server_endpoints from disk");
                let fresh_cfg = match ClientConfig::load(&config_path).await {
                    Ok(c) => c,
                    Err(e) => {
                        warn!(error = %e, "SIGHUP: config reload failed; keeping current pool");
                        continue;
                    }
                };
                let new_endpoints = fresh_cfg.server_endpoints.clone();
                let (prev, new) = ctx_for_reload
                    .reloadable_pool
                    .reload_from_addrs(new_endpoints);
                let (added, removed) = proteus_client::endpoint_pool::pool_addr_diff(&prev, &new);
                info!(
                    prev_count = prev.len(),
                    new_count = new.len(),
                    added = ?added,
                    removed = ?removed,
                    reload_attempts = ctx_for_reload.reloadable_pool.reload_attempts(),
                    "endpoint pool reloaded (carryover preserved per-entry counters \
                     for unchanged addrs)"
                );
            }
        });
    }

    // ----- Graceful shutdown wiring -----
    let drain = Duration::from_secs(cfg.drain_secs.unwrap_or(15));
    let shutdown = async {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler");
        let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            .expect("install SIGINT handler");
        tokio::select! {
            _ = sigterm.recv() => info!("SIGTERM received, draining SOCKS5 sessions"),
            _ = sigint.recv() => info!("SIGINT received, draining SOCKS5 sessions"),
        }
    };
    tokio::pin!(shutdown);

    // ----- Accept loop with cap + backoff -----
    let mut accept_backoff_ms: u64 = 0;
    loop {
        // Acquire a session slot BEFORE accepting so a saturated server
        // never accepts a TCP connection it can't handle. The semaphore
        // permit is moved into the spawned task and released on drop.
        let permit = match &session_slots {
            Some(s) => match Arc::clone(s).acquire_owned().await {
                Ok(p) => Some(p),
                Err(_) => {
                    // Semaphore closed — shouldn't happen unless
                    // shutdown is in progress. Bail.
                    break;
                }
            },
            None => None,
        };

        tokio::select! {
            biased;
            _ = &mut shutdown => {
                drop(permit);
                break;
            }
            accept = listener.accept() => {
                match accept {
                    Ok((stream, peer)) => {
                        accept_backoff_ms = 0; // reset on success
                        // Disable Nagle so SOCKS5 round-trips don't
                        // pay an extra 40 ms per write — interactive
                        // workloads (HTTP/2 control frames, SSH)
                        // notice this immediately.
                        let _ = stream.set_nodelay(true);
                        let cfg = Arc::clone(&cfg);
                        let ctx_for_task = Arc::clone(&ctx);
                        tokio::spawn(async move {
                            let _permit = permit; // drop on task exit
                            if let Err(e) =
                                socks::handle_socks5_with_ctx(stream, &cfg, &ctx_for_task).await
                            {
                                warn!(peer = %peer, error = %e, "socks5 session ended");
                            }
                        });
                    }
                    Err(e) => {
                        // Transient errors (EMFILE, ENFILE, ECONNABORTED)
                        // can make the loop spin if we just retry
                        // immediately. Exponential backoff with a
                        // 1-second cap so the process recovers cleanly
                        // once the kernel resource pressure passes.
                        accept_backoff_ms = (accept_backoff_ms * 2).clamp(10, 1000);
                        warn!(
                            error = %e,
                            backoff_ms = accept_backoff_ms,
                            "accept() failed; backing off"
                        );
                        // Release the permit so it doesn't sit unused
                        // during the backoff.
                        drop(permit);
                        tokio::time::sleep(Duration::from_millis(accept_backoff_ms)).await;
                    }
                }
            }
        }
    }

    // ----- Drain window -----
    //
    // After we exit the accept loop, in-flight sessions are still
    // running on spawned tokio tasks. We don't have explicit handles
    // to await on (intentional — sessions are independent), so we
    // bound the drain by total available semaphore permits. Once
    // every permit returns to the semaphore, every spawned task has
    // exited cleanly.
    if let Some(slots) = &session_slots {
        info!(
            drain_secs = drain.as_secs(),
            in_flight = max_inflight - slots.available_permits(),
            "drain window started"
        );
        let drain_fut = async {
            while slots.available_permits() < max_inflight {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        };
        match tokio::time::timeout(drain, drain_fut).await {
            Ok(()) => info!("drain complete, exiting"),
            Err(_) => warn!(
                in_flight = max_inflight - slots.available_permits(),
                "drain window elapsed with sessions still in flight; exiting anyway"
            ),
        }
    }

    Ok(())
}

/// Emit a SOCKS5 "general failure" reply (`0x05 0x01`) on a connection
/// the client is about to drop. Best-effort: errors here are not
/// surfaced because the connection is being torn down anyway.
///
/// Used only by tests today; the main accept loop relies on the
/// session_slots semaphore being acquired BEFORE accept, so the
/// "cap reached" path simply backpressures the kernel TCP queue.
/// Keeping the helper around in case the cap moves to post-accept
/// in a future revision.
#[allow(dead_code)]
async fn socks5_general_failure(mut sock: tokio::net::TcpStream) {
    // SOCKS5 connect-reply: VER=05, REP=01(general failure), RSV=00,
    // ATYP=01(IPv4), BND.ADDR=0.0.0.0, BND.PORT=0.
    let reply: [u8; 10] = [0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    let _ = sock.write_all(&reply).await;
    let _ = sock.shutdown().await;
}

#[cfg(test)]
mod cli_helpers_tests {
    use super::*;

    #[test]
    fn parse_http_url_accepts_well_formed_loopback() {
        let (h, p, path) = parse_http_url("http://127.0.0.1:9091").unwrap();
        assert_eq!(h, "127.0.0.1");
        assert_eq!(p, 9091);
        assert_eq!(path, "/");
    }

    #[test]
    fn parse_http_url_extracts_path_when_present() {
        let (h, p, path) = parse_http_url("http://localhost:9091/sub").unwrap();
        assert_eq!(h, "localhost");
        assert_eq!(p, 9091);
        assert_eq!(path, "/sub");
    }

    #[test]
    fn parse_http_url_rejects_https() {
        let err = parse_http_url("https://example.com:443").unwrap_err();
        assert!(err.contains("http://"), "should reject https: {err}");
    }

    #[test]
    fn parse_http_url_rejects_missing_port() {
        let err = parse_http_url("http://example.com/path").unwrap_err();
        assert!(err.contains("port"), "should reject missing port: {err}");
    }

    #[test]
    fn split_http_response_returns_status_and_body() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let (status, body) = split_http_response(raw).unwrap();
        assert_eq!(status, "HTTP/1.1 200 OK");
        assert_eq!(body, "hello");
    }

    #[test]
    fn split_http_response_handles_empty_body() {
        let raw = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n";
        let (status, body) = split_http_response(raw).unwrap();
        assert_eq!(status, "HTTP/1.1 503 Service Unavailable");
        assert_eq!(body, "");
    }

    #[test]
    fn split_http_response_rejects_truncated_response() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n";
        assert!(split_http_response(raw).is_err());
    }
}
