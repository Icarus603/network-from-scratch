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
    /// Hit the running client's `/diagnose` endpoint and print the
    /// one-shot self-check report (FINDINGS + STATUS + METRICS).
    /// Operator-friendly alternative to `curl :9091/diagnose` —
    /// same body, no jq required. Suitable for screen-share /
    /// bug-report paste.
    Diagnose {
        #[arg(long, default_value = "http://127.0.0.1:9091")]
        url: String,
    },
    /// Offline host-posture preflight (mirror of the server-side
    /// `proteus-server preflight check-host`). Audits the
    /// client-specific footgun class: `client_ed25519_sk` mode
    /// (long-term identity exposure), server endpoint DNS
    /// resolvability (catches typos before first SOCKS connect),
    /// bootstrap_dns consistency (DoH-leak surface vs. dead-code
    /// direct_ip), trusted_ca PEM readability (silent rustls
    /// fallback to webpki-roots), /dev/urandom availability, and
    /// clock sync (broken NTP rejects every handshake as 'replay').
    ///
    /// Read-only — no chmod, no network handshake, no probes.
    /// DNS lookup is the only potential network access; gate with
    /// `--skip-dns-resolution` for air-gapped CI.
    ///
    /// Exit code 0 on PASS+WARN-only, 1 on any FAIL. Wire into
    /// CI / Ansible / Terraform deploy gates.
    CheckHost {
        /// Path to client YAML config. Optional: when absent, the
        /// config-derived checks (key file mode, DNS, bootstrap
        /// consistency, trusted_ca) are skipped; urandom + clock
        /// still run unconditionally.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Skip the DNS-resolution check (no network). Use in
        /// air-gapped CI environments where DNS will always
        /// time out.
        #[arg(long, default_value_t = false)]
        skip_dns_resolution: bool,
        /// Output format: `text` (default, human-friendly) or
        /// `json` (one-line append-only document for scripted
        /// deploy gates).
        #[arg(long, default_value = "text")]
        format: String,
    },
    /// One-shot Proteus α-profile handshake smoke test.
    ///
    /// Loads the supplied `client.yaml`, resolves `server_endpoint`
    /// under the configured `bootstrap_dns` policy, dials the
    /// server, runs the FULL Proteus handshake (ed25519 identity +
    /// ml-kem768 KEM + ChaCha20 ratchet + TLS channel binding when
    /// `tls:` is set), drops the session, and prints a per-stage
    /// timing breakdown.
    ///
    /// Designed for "did my new client.yaml actually work?"
    /// post-provisioning checks WITHOUT having to spin up the
    /// SOCKS5 daemon + curl through it. The server sees one
    /// session open + immediate close — operators running many
    /// smoke runs should adjust their server's abuse detectors
    /// to tolerate the burst.
    ///
    /// Exit code 0 on handshake success, 1 on failure, 2 on
    /// pre-handshake setup error (config load / TLS connector
    /// build).
    ConnectTest {
        /// Path to client YAML config.
        #[arg(long, default_value = "/etc/proteus/client.yaml")]
        config: PathBuf,
        /// Per-stage hard timeout. Wraps DNS, TCP connect, AND
        /// the Proteus handshake — a wedged server at any stage
        /// can't pin the test runner.
        #[arg(long, default_value_t = 10)]
        connect_timeout_secs: u64,
        /// Output format: `text` (default, human-readable with
        /// per-stage millis) or `json` (one-line append-only
        /// document for CI / scripted gates).
        #[arg(long, default_value = "text")]
        format: String,
        /// Iter-42: test EVERY entry in `server_endpoints:`
        /// (the multi-VPS pool) instead of only the primary
        /// `server_endpoint`. Each entry gets its own DNS + TCP
        /// plus handshake cycle; one entry failing does NOT
        /// abort the remaining tests. Exit code is 0 IFF every
        /// entry succeeded; ANY single failure -> exit 1.
        ///
        /// Useful before relying on pool failover: pre-iter-42
        /// operators could only test the primary; backup entries
        /// were unverified until first failover (i.e. precisely
        /// when surprises hurt). With this flag set the operator
        /// proves every backup also works at deploy time.
        ///
        /// If `server_endpoints:` is empty (legacy single-entry
        /// deploy), behaves identically to the no-flag default
        /// (one test against `server_endpoint`).
        #[arg(long, default_value_t = false)]
        all_endpoints: bool,
    },
    /// One-shot in-process evaluation of client-side production
    /// alert rules against a running client's `/metrics`
    /// endpoint. Symmetric with `proteus-server admin alerts-check`
    /// — operators get a per-rule verdict in 50-200 ms without
    /// standing up Prometheus.
    ///
    /// Rules evaluated:
    ///   ProteusClientNotAlive                — SOCKS5 not bound
    ///   ProteusClientBetaCarrierSuppressed   — β backing off
    ///   ProteusClientAllEndpointsSuppressed  — pool exhausted
    ///   ProteusClientNoRecentDialSuccess     — never dialed OK
    ///   ProteusClientHighDialFailureRatio    — more fail than ok
    ///   ProteusClientBootstrapViaSystemResolver — DoH-leak risk
    ///
    /// Exit code: 0 on PASS+WARN-only, 1 on any CRIT. Wire into
    /// Ansible/Terraform deploy gates for fresh-client smoke
    /// checks.
    AlertsCheck {
        /// URL of the admin endpoint. Default points at the
        /// recommended loopback bind. The endpoint is
        /// loopback-only by convention; no token gate.
        #[arg(long, default_value = "http://127.0.0.1:9091")]
        url: String,
        /// Per-step network timeout in seconds.
        #[arg(long, default_value_t = 5)]
        timeout_secs: u64,
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

    // Install the shared panic hook BEFORE any tasks spawn — tokio
    // absorbs spawned-task panics silently otherwise. The returned
    // counter is published via `process_panic_counter::set` so any
    // admin endpoint (today proteus-client doesn't surface metrics
    // directly the way the server does, but the wiring is in place
    // for the same `proteus_panics_total` series symmetric with the
    // server side). Honours RUST_PANIC_ABORT=1 for operators who
    // prefer systemd-restart-on-panic over keep-running semantics.
    let panic_counter = proteus_panic_hook::install();
    proteus_client::process_panic_counter::set(panic_counter);

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Keygen { out } => keygen::run(&out)?,
        Cmd::Run { config } => run(&config).await?,
        Cmd::Validate { path } => {
            let code = proteus_client::validate::cli_run(&path).await?;
            std::process::exit(code);
        }
        Cmd::Status { url, format } => status_cmd(&url, &format).await?,
        Cmd::Diagnose { url } => diagnose_cmd(&url).await?,
        Cmd::CheckHost {
            config,
            skip_dns_resolution,
            format,
        } => {
            let input = proteus_client::host_preflight::HostPreflightInput {
                config_path: config,
                skip_dns_resolution,
            };
            let code = proteus_client::host_preflight::cli_run(input, &format).await?;
            std::process::exit(code);
        }
        Cmd::ConnectTest {
            config,
            connect_timeout_secs,
            format,
            all_endpoints,
        } => {
            let code = if all_endpoints {
                proteus_client::connect_test::cli_run_all_endpoints(
                    &config,
                    connect_timeout_secs,
                    &format,
                )
                .await?
            } else {
                proteus_client::connect_test::cli_run(
                    &config,
                    connect_timeout_secs,
                    &format,
                )
                .await?
            };
            std::process::exit(code);
        }
        Cmd::AlertsCheck {
            url,
            timeout_secs,
            format,
        } => {
            // Iter-110: mirror of iter-108/iter-109 — reject
            // zero timeout with exit 2 + actionable stderr.
            if timeout_secs == 0 {
                eprintln!(
                    "alerts-check: timeout_secs = 0 deadlines every step instantly. \
                     Use a real value (default 5s, sensible range 1-30s)."
                );
                std::process::exit(2);
            }
            let code = proteus_client::admin_alerts_check::cli_run(
                &url,
                std::time::Duration::from_secs(timeout_secs),
                &format,
            )
            .await?;
            std::process::exit(code);
        }
    }
    Ok(())
}

/// `proteus-client diagnose` — hit `/diagnose` and stream the body.
/// Same hand-rolled HTTP/1.1 client as `status_cmd`; no extra deps.
async fn diagnose_cmd(url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let (host, port, base_path) = parse_http_url(url)?;
    let request_path = if base_path == "/" {
        "/diagnose".to_string()
    } else {
        format!("{base_path}/diagnose")
    };
    let req = format!(
        "GET {request_path} HTTP/1.1\r\n\
         Host: {host}:{port}\r\n\
         User-Agent: proteus-client-diagnose/1\r\n\
         Accept: */*\r\n\
         Connection: close\r\n\r\n"
    );
    let mut stream = tokio::net::TcpStream::connect((host.as_str(), port)).await?;
    tokio::io::AsyncWriteExt::write_all(&mut stream, req.as_bytes()).await?;
    let mut buf = Vec::with_capacity(16 * 1024);
    tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut buf).await?;
    let s = std::str::from_utf8(&buf).map_err(|e| format!("non-UTF8 response: {e}"))?;
    let (status_line, body) = split_http_response(s)?;
    if !status_line.starts_with("HTTP/1.1 200") {
        return Err(format!("admin endpoint returned: {status_line}").into());
    }
    print!("{body}");
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

    // Optional knock PSK. Symmetric to the server's startup
    // load (proteus-server::main loads its
    // `cfg.knock_psk_file`). When None: legacy mode, no
    // probe-resistance gate. When Some: validate + load NOW so
    // file-permission / format errors surface before the SOCKS5
    // listener binds (operator who asked for probe-resistance
    // shouldn't silently get the legacy mode).
    //
    // The Arc<KnockPsk> is held in `_knock_psk` and will be
    // consumed by the future transport-layer wiring that mints
    // a knock token per outbound handshake. This iteration just
    // loads it; the wire-format integration is iteration 4.
    let _knock_psk: Option<std::sync::Arc<proteus_handshake::knock::KnockPsk>> =
        match cfg.knock_psk_file.as_ref() {
            Some(path) => match proteus_client::knock_psk::load(path) {
                Ok(bytes) => {
                    info!(
                        path = ?path,
                        "knock PSK loaded — Path A probe-resistance primitive ready \
                         (transport-layer wire-format integration is a follow-up iteration)"
                    );
                    Some(std::sync::Arc::new(
                        proteus_handshake::knock::KnockPsk::from_bytes(bytes),
                    ))
                }
                Err(e) => {
                    return Err(format!(
                        "knock_psk_file {path:?} load failed: {e}. \
                         The server operator generated this file via \
                         `proteus-server knock-keygen` and distributed it to you — \
                         verify the bytes weren't corrupted in transit. To run \
                         WITHOUT probe-resistance temporarily, remove the \
                         `knock_psk_file:` line from client.yaml."
                    )
                    .into());
                }
            },
            None => {
                info!(
                    "knock_psk_file unset — probe-resistance disabled (legacy mode). \
                     For REALITY-grade probe resistance, ask the server operator for \
                     a knock PSK and set `knock_psk_file:` in client.yaml."
                );
                None
            }
        };

    let listener = TcpListener::bind(&cfg.socks_listen).await?;
    info!(addr = %listener.local_addr()?, "SOCKS5 inbound bound");

    // sd_notify(READY=1) — tell systemd the SOCKS5 listener is
    // actually accepting traffic. Lets `Type=notify` units order
    // an `After=proteus-client.service` upstream-app correctly.
    // No-op when $NOTIFY_SOCKET is unset (manual run / container
    // without systemd).
    let _ = proteus_sd_notify::notify_ready().await;
    let _ =
        proteus_sd_notify::notify_status(&format!("SOCKS5 on {}", listener.local_addr()?)).await;

    // Watchdog ping cycle for systemd liveness. systemd's
    // WatchdogSec= restarts us if no WATCHDOG=1 arrives within
    // the configured window — proves the tokio runtime is alive
    // even under hot-path lock contention. The cancel notify
    // stops the cycle on graceful shutdown so systemd's
    // TimeoutStopSec window isn't confused by a stale ping.
    let watchdog_cancel = Arc::new(tokio::sync::Notify::new());
    let _watchdog_handle = if let Some(interval) = proteus_sd_notify::watchdog_interval() {
        info!(
            interval_secs = interval.as_secs(),
            "sd_notify watchdog active"
        );
        Some(proteus_sd_notify::spawn_watchdog(
            interval,
            Arc::clone(&watchdog_cancel),
        ))
    } else {
        None
    };

    // Iter-27: periodic rollup of the iter-23 client-side failure-
    // log throttles. Mirrors the server-side
    // `rejection_log_throttle_drain_rollups` periodic task. Without
    // this, a long-running upstream-VPS-down outage produces a
    // sparse trickle of throttled WARN lines spread over hours;
    // with it, the journal carries one clean rollup line every 60s
    // showing "N WARN lines suppressed in the last window for site
    // X" — operators see the magnitude of an outage at a glance via
    // `journalctl -u proteus-client | grep log-throttle`.
    //
    // Window matches the server's 60s default. We `Skip` missed
    // ticks so a long pause (e.g. system sleep on a laptop) doesn't
    // generate a burst of catch-up rollups.
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tick.tick().await; // skip immediate fire
        loop {
            tick.tick().await;
            for (site, suppressed) in proteus_client::socks::drain_failure_log_rollups() {
                warn!(
                    site,
                    suppressed,
                    window_secs = 60,
                    "client log-throttle: suppressed similar failure messages in last window"
                );
            }
        }
    });

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
    // Process-lifecycle info: CARGO_PKG_VERSION baked at compile
    // time; rustc + target are best-effort (operator can wire a
    // build script if they want them populated). Same shape as
    // server-side metric — operators can build a unified Grafana
    // dashboard with `proteus_*_process_*` queries.
    let process_info =
        std::sync::Arc::new(proteus_transport_alpha::process_info::ProcessInfo::capture(
            env!("CARGO_PKG_VERSION"),
            option_env!("RUSTC_VERSION").unwrap_or(""),
            option_env!("TARGET").unwrap_or(""),
        ));
    // Build the TLS connector ONCE at startup so every SOCKS5
    // request doesn't pay for `build_connector_*` (root-store
    // parse + ALPN clone + crypto-provider installation). The
    // cached connector lives in `ClientCtx` and is `Arc`-cloned
    // per request — `tokio_rustls::TlsConnector` is internally
    // `Arc<ClientConfig>` so the clone itself is free. When the
    // operator's `tls:` block is unset (dev / plaintext-α mode)
    // we attach None and try_alpha falls through to its
    // per-request build path.
    let cached_tls_connector: Option<Arc<proteus_transport_alpha::tls::TlsConnector>> =
        if let Some(tls_cfg) = cfg.tls.as_ref() {
            let connector = match tls_cfg.trusted_ca.as_ref() {
                Some(ca) => {
                    proteus_transport_alpha::tls::build_connector_with_ca(ca).map_err(|e| {
                        format!("failed to build cached TLS connector (pinned CA): {e}")
                    })?
                }
                None => proteus_transport_alpha::tls::build_connector_webpki_roots()
                    .map_err(|e| format!("failed to build cached TLS connector (webpki): {e}"))?,
            };
            info!(
                server_name = %tls_cfg.server_name,
                "cached TLS connector built — SOCKS5 requests will reuse it instead of rebuilding per request"
            );
            Some(Arc::new(connector))
        } else {
            info!(
                "no tls: config — α handshakes will run in plaintext mode (dev/test only); \
             no cached TLS connector wired"
            );
            None
        };

    // Build the handshake-config source ONCE at startup. Reads
    // all 4 key files from disk (server_mlkem_pk,
    // server_x25519_pk, server_pq_fingerprint, client_ed25519_sk),
    // derives the Ed25519 signing key, validates lengths. Per
    // CONNECT, dispatch calls `source.alpha()` or `source.beta()`
    // (pure CPU clone — no disk, no parsing, no key derivation)
    // instead of paying for all that work per request.
    //
    // If this fails at startup we refuse to start — better an
    // explicit operator-visible error than silently failing
    // every SOCKS5 CONNECT.
    let cached_hs_source: Arc<proteus_client::config::HandshakeConfigSource> = Arc::new(
        cfg.build_handshake_config_source()
            .map_err(|e| format!("failed to build cached handshake-config source: {e}"))?,
    );
    info!(
        "cached handshake-config source built — SOCKS5 requests will skip 4 disk reads + ed25519 derivation per CONNECT"
    );

    // Iter-22: cache the β client crypto (rustls + quinn) ONCE
    // at startup so per-CONNECT β dials skip the webpki-roots
    // extend + rustls config build + QuicClientConfig::try_from
    // + PEM parse of trusted_ca on every request. Mirrors the
    // iter-11 α TlsConnector cache.
    //
    // When β isn't configured we skip the cache entirely; when
    // the trusted_ca file fails to load we log + proceed without
    // the cache (per-CONNECT path falls back to the legacy
    // make_client_crypto flow which has the same failure mode
    // it always did).
    let cached_beta_crypto: Option<Arc<proteus_transport_beta::client::BetaClientCrypto>> =
        if beta_configured {
            // Load extra_roots ONCE at startup. Same trusted_ca
            // file the α path consumes via `tls.trusted_ca`.
            let extra_roots = match cfg.tls.as_ref().and_then(|t| t.trusted_ca.as_ref()) {
                Some(ca) => match proteus_transport_alpha::tls::load_cert_chain(ca) {
                    Ok(chain) => chain,
                    Err(e) => {
                        warn!(
                            error = %e,
                            path = ?ca,
                            "failed to load tls.trusted_ca for β crypto cache — per-CONNECT \
                             β dials will fall back to the legacy uncached path (slower)"
                        );
                        Vec::new()
                    }
                },
                None => Vec::new(),
            };
            match proteus_transport_beta::client::build_client_crypto_cache(extra_roots) {
                Ok(c) => {
                    info!(
                        "cached β client crypto built — SOCKS5 β-CONNECTs will skip rustls + \
                         QuicClientConfig setup per request"
                    );
                    Some(Arc::new(c))
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        "failed to build β client crypto cache — per-CONNECT β dials \
                         will fall back to legacy uncached path"
                    );
                    None
                }
            }
        } else {
            None
        };

    let mut ctx_builder = ClientCtx::new(
        Arc::clone(&health),
        endpoint_pool.clone(),
        session_slots.clone(),
        max_inflight,
        beta_configured,
    )
    .with_process_info(process_info)
    .with_hs_config_source(Arc::clone(&cached_hs_source));
    if let Some(c) = cached_tls_connector.clone() {
        ctx_builder = ctx_builder.with_tls_connector(c);
    }
    if let Some(c) = cached_beta_crypto.clone() {
        ctx_builder = ctx_builder.with_beta_crypto(c);
    }
    let ctx = Arc::new(ctx_builder);

    // ----- Admin HTTP endpoint -----
    //
    // Operator-opt-in via `admin_listen:` in client.yaml. When set,
    // spawn a loopback HTTP server exposing /healthz + /status +
    // /status.json. Disabled by default — operators who don't want
    // the extra port don't pay for it.
    if let Some(admin_addr) = cfg.admin_listen.clone() {
        let alive_for_admin = Arc::clone(&alive);
        let ctx_for_admin = Arc::clone(&ctx);
        let staleness = cfg.healthz_staleness_secs.unwrap_or(0);
        if staleness > 0 {
            info!(
                staleness_secs = staleness,
                "client /healthz staleness rule wired (503 after no dial success for N seconds)"
            );
        }
        tokio::spawn(async move {
            if let Err(e) =
                admin::serve_with_ctx_v2(admin_addr, alive_for_admin, ctx_for_admin, staleness)
                    .await
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
                // sd_notify(RELOADING=1) — symmetric with the
                // server-side SIGHUP path. systemctl status shows
                // "reloading" instead of "active (running)" while
                // we work; READY=1 at the end of the block flips
                // it back. MUST be paired — leaving RELOADING=1
                // hanging would pin the unit in the reloading
                // state until the next restart.
                let _ = proteus_sd_notify::notify_reloading().await;
                let _ = proteus_sd_notify::notify_status("reloading endpoint pool (SIGHUP)").await;
                let fresh_cfg = match ClientConfig::load(&config_path).await {
                    Ok(c) => c,
                    Err(e) => {
                        // Iter-40: bump the failed-attempt counter so
                        // (reload_attempts - reload_succeeded) > 0
                        // and the entire ProteusClientPoolReloadFailing
                        // pentad (Prometheus alert + in-process check
                        // + dashboard panel + structured log) fires.
                        // Pre-iter-40 this silent edit-didn't-apply
                        // was invisible to every operator surface.
                        ctx_for_reload.reloadable_pool.record_attempt_failed();
                        warn!(
                            error = %e,
                            reload_attempts = ctx_for_reload.reloadable_pool.reload_attempts(),
                            reload_succeeded = ctx_for_reload.reloadable_pool.reload_succeeded(),
                            "SIGHUP: config reload FAILED; keeping current pool. Operator edit silently did NOT apply — investigate parse error above",
                        );
                        let _ = proteus_sd_notify::notify_ready().await;
                        let _ = proteus_sd_notify::notify_status(
                            "SIGHUP reload FAILED (config parse) — current pool preserved",
                        )
                        .await;
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
                let _ = proteus_sd_notify::notify_ready().await;
                let _ = proteus_sd_notify::notify_status(&format!(
                    "ready (last SIGHUP: {} → {} endpoints)",
                    prev.len(),
                    new.len()
                ))
                .await;
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
                        // Iter-19: distinguish transient kernel errors
                        // (EMFILE / ENFILE / ENOMEM — back off and
                        // retry) from fatal listener-fd-dead errors
                        // (EBADF, ENETDOWN — propagate up so systemd
                        // restarts us instead of spin-looping forever).
                        //
                        // Pre-iter-19: all errors were "transient" with
                        // exponential backoff. That meant a permanently
                        // broken listener (operator renamed the
                        // socks_listen address out from under us, the
                        // kernel state-loss class of bugs) would keep
                        // the process alive in a perpetual 1-second
                        // backoff spin — health checks pass, no traffic
                        // serviced, operator can't tell anything's
                        // wrong. Same silent-failure class as the
                        // server's iter-18 fix.
                        let is_transient =
                            proteus_transport_alpha::socket_opts::is_transient_accept_error(
                                e.raw_os_error(),
                            );
                        if is_transient {
                            accept_backoff_ms = (accept_backoff_ms * 2).clamp(10, 1000);
                            warn!(
                                error = %e,
                                raw_os_error = ?e.raw_os_error(),
                                backoff_ms = accept_backoff_ms,
                                "SOCKS5 accept() hit transient kernel error (FD/memory \
                                 exhaustion); backing off"
                            );
                            // Release the permit so it doesn't sit unused
                            // during the backoff.
                            drop(permit);
                            tokio::time::sleep(Duration::from_millis(accept_backoff_ms)).await;
                        } else {
                            // Fatal: log a single ERROR (operator's
                            // alerting will catch the restart from
                            // systemd anyway, but the explicit log
                            // makes diagnosis instant) and break out
                            // of the loop. The outer drain logic will
                            // notice the listener is gone and exit.
                            tracing::error!(
                                error = %e,
                                raw_os_error = ?e.raw_os_error(),
                                "SOCKS5 accept() hit non-transient error; \
                                 stopping listener — supervisor should restart us"
                            );
                            drop(permit);
                            break;
                        }
                    }
                }
            }
        }
    }

    // sd_notify(STOPPING=1) — tells systemd we're draining so
    // `TimeoutStopSec=` accounting starts now (not at process
    // exit). Cancel the watchdog cycle so a slow drain doesn't
    // race with a false "watchdog tripped" restart.
    let _ = proteus_sd_notify::notify_stopping().await;
    watchdog_cancel.notify_one();

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
