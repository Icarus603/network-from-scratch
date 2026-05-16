//! Proteus α-profile server binary.
//!
//! This is the **production entry point**. It:
//! 1. Loads YAML config (listen addr, keys, allowlist, cover URL pool).
//! 2. Listens on a TCP port (default 8443) for α-profile handshakes.
//! 3. For each authenticated session, decapsulates the inner stream
//!    (HTTP CONNECT-style `host:port` target spec, then bidirectional
//!    relay to upstream).
//! 4. Auth-fail handling: per spec §7.5, forwards the raw bytes to a
//!    configured cover URL via `splice`-style proxying. (M1 simplified:
//!    just drops the connection — full cover-forward is a single-file
//!    swap in M2.)
//!
//! ```bash
//! proteus-server keygen --out ./keys
//! proteus-server run --config /etc/proteus/server.yaml
//! ```

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use proteus_transport_alpha::server::{self, ServerCtx};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

mod gencert;
mod keygen;

use proteus_server::config;
use proteus_server::relay;

use config::{load_server_keys, ServerConfig};
use proteus_server::startup;

#[derive(Parser, Debug)]
#[command(version, about = "Proteus α-profile server")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Generate a fresh long-term keypair set and write to `--out`.
    Keygen {
        /// Output directory for keys.
        #[arg(long, default_value = "./keys")]
        out: PathBuf,
    },
    /// Generate a self-signed TLS certificate for `--dns-name`.
    ///
    /// For testing or trusted-LAN deployments. Production should use a
    /// real CA (Let's Encrypt) — the resulting `fullchain.pem` /
    /// `privkey.pem` files plug into the same `tls:` config block.
    Gencert {
        /// DNS SAN to embed in the certificate.
        #[arg(long)]
        dns_name: String,
        /// Output directory.
        #[arg(long, default_value = "./keys/tls")]
        out: PathBuf,
    },
    /// Start the server.
    Run {
        /// Path to YAML config file.
        #[arg(long, default_value = "/etc/proteus/server.yaml")]
        config: PathBuf,
    },
    /// Dry-run check: parse the YAML, load every referenced file,
    /// parse the TLS cert/key, parse the firewall CIDRs, and print
    /// a pass/fail report. Exits 0 on green (warnings only), 1 on
    /// any failure. Suitable for CI / Ansible / Terraform pre-deploy
    /// gating and for verifying a `SIGHUP`-style edit before signaling.
    Validate {
        /// Path to YAML config file.
        #[arg(long, default_value = "/etc/proteus/server.yaml")]
        config: PathBuf,
    },
    /// Admin commands against a running server.
    Admin {
        #[command(subcommand)]
        cmd: AdminCmd,
    },
}

#[derive(Subcommand, Debug)]
enum AdminCmd {
    /// Pretty-print a one-shot status snapshot by scraping the
    /// server's /metrics endpoint. Auth via --token-file or the
    /// PROTEUS_METRICS_TOKEN env var.
    Status {
        /// URL of the metrics endpoint. Default is the loopback bind
        /// from the bundled server.example.yaml.
        #[arg(long, default_value = "http://127.0.0.1:9090/metrics")]
        url: String,
        /// Path to a file containing the bearer token. If unset, the
        /// PROTEUS_METRICS_TOKEN env var is consulted; if both are
        /// unset the request is sent without auth (works only when
        /// the server has metrics_token_file unset too).
        #[arg(long)]
        token_file: Option<PathBuf>,
        /// Per-step network timeout in seconds. Default 5 s.
        #[arg(long, default_value_t = 5)]
        timeout_secs: u64,
        /// Output format: `text` (default, human-friendly) or
        /// `json` (one-line JSON for jq / scripted alerting).
        #[arg(long, default_value = "text")]
        format: String,
    },
    /// Compute counter deltas between two saved scrape bodies. Use
    /// when you want to see "what changed in the last N seconds"
    /// without leaving a live watcher running.
    ///
    /// Capture scrapes with:
    ///   curl http://127.0.0.1:9090/metrics > /tmp/before
    ///   sleep 30
    ///   curl http://127.0.0.1:9090/metrics > /tmp/after
    ///   proteus-server admin diff --before /tmp/before --after /tmp/after \
    ///                             --interval-secs 30
    Diff {
        /// Path to the OLDER scrape body.
        #[arg(long)]
        before: PathBuf,
        /// Path to the NEWER scrape body.
        #[arg(long)]
        after: PathBuf,
        /// Wall-clock seconds between the two scrapes. Used to
        /// render per-second rates. Defaults to 1 (treat deltas as
        /// raw counts).
        #[arg(long, default_value_t = 1.0)]
        interval_secs: f64,
        /// Output format: `text` (default) or `json`.
        #[arg(long, default_value = "text")]
        format: String,
    },
    /// Live delta loop: scrapes /metrics at the given interval and
    /// prints deltas between successive scrapes. First iteration is
    /// the absolute snapshot (no delta source yet). Clears the
    /// screen on every iteration when stdout is a TTY (text mode
    /// only). Ctrl-C to exit.
    Watch {
        /// URL of the metrics endpoint.
        #[arg(long, default_value = "http://127.0.0.1:9090/metrics")]
        url: String,
        /// Optional bearer-token file (or PROTEUS_METRICS_TOKEN).
        #[arg(long)]
        token_file: Option<PathBuf>,
        /// Per-request HTTP timeout in seconds.
        #[arg(long, default_value_t = 5)]
        timeout_secs: u64,
        /// Refresh interval in seconds.
        #[arg(long, default_value_t = 5)]
        interval_secs: u64,
        /// Output format: `text` (default) or `json` (JSON Lines —
        /// one document per refresh, screen clearing suppressed).
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
        Cmd::Gencert { dns_name, out } => gencert::run(&dns_name, &out)?,
        Cmd::Run { config } => run(&config).await?,
        Cmd::Validate { config } => {
            let ok = proteus_server::validate::run(&config).await?;
            if !ok {
                std::process::exit(1);
            }
        }
        Cmd::Admin { cmd } => match cmd {
            AdminCmd::Status {
                url,
                token_file,
                timeout_secs,
                format,
            } => {
                let token = match token_file {
                    Some(p) => Some(proteus_server::admin::read_token_file(&p)?),
                    None => std::env::var("PROTEUS_METRICS_TOKEN").ok(),
                };
                let fmt: proteus_server::admin::OutputFormat = format.parse()?;
                proteus_server::admin::run(
                    &url,
                    token.as_deref(),
                    std::time::Duration::from_secs(timeout_secs),
                    fmt,
                )?;
            }
            AdminCmd::Diff {
                before,
                after,
                interval_secs,
                format,
            } => {
                let fmt: proteus_server::admin::OutputFormat = format.parse()?;
                proteus_server::admin::run_diff(&before, &after, interval_secs, fmt)?;
            }
            AdminCmd::Watch {
                url,
                token_file,
                timeout_secs,
                interval_secs,
                format,
            } => {
                let token = match token_file {
                    Some(p) => Some(proteus_server::admin::read_token_file(&p)?),
                    None => std::env::var("PROTEUS_METRICS_TOKEN").ok(),
                };
                let fmt: proteus_server::admin::OutputFormat = format.parse()?;
                proteus_server::admin::run_watch(
                    &url,
                    token.as_deref(),
                    std::time::Duration::from_secs(timeout_secs),
                    std::time::Duration::from_secs(interval_secs),
                    fmt,
                )?;
            }
        },
    }
    Ok(())
}

async fn run(config_path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let cfg = ServerConfig::load(config_path).await?;
    info!(
        listen = %cfg.listen_alpha,
        users = cfg.client_allowlist.len(),
        "proteus-server starting"
    );

    let keys = load_server_keys(&cfg)?;
    let mut ctx = ServerCtx::new(keys);
    if let Some(cover) = &cfg.cover_endpoint {
        match proteus_transport_alpha::cover::parse_cover_endpoint(cover) {
            Some(parsed) => {
                info!(cover = %parsed, "cover endpoint configured");
                ctx = ctx.with_cover(parsed);
            }
            None => {
                warn!(cover = %cover, "invalid cover endpoint — auth-fail connections will be dropped")
            }
        }
    } else {
        warn!("no cover_endpoint configured — auth-fail connections will be dropped silently");
    }
    if let Some(rl) = &cfg.rate_limit {
        info!(
            burst = rl.burst,
            refill = rl.refill_per_sec,
            "per-IP rate limit configured"
        );
        ctx = ctx.with_rate_limiter(proteus_transport_alpha::rate_limit::RateLimiter::new(
            rl.burst,
            rl.refill_per_sec,
        ));
    } else {
        warn!("no rate_limit configured — server may be vulnerable to ML-KEM amplification DoS");
    }
    if let Some(b) = &cfg.handshake_budget {
        info!(
            burst = b.burst,
            refill = b.refill_per_sec,
            "global handshake budget configured"
        );
        ctx = ctx.with_handshake_budget(b.burst, b.refill_per_sec);
    }
    if let Some(u) = &cfg.user_rate_limit {
        info!(
            burst = u.burst,
            refill = u.refill_per_sec,
            max_users = u.max_users,
            "per-user rate limit configured"
        );
        ctx = ctx.with_user_rate_limit(u.burst, u.refill_per_sec, u.max_users);
    }
    if let Some(secs) = cfg.handshake_deadline_secs {
        ctx = ctx.with_handshake_deadline(std::time::Duration::from_secs(secs));
    }
    if let Some(secs) = cfg.tcp_keepalive_secs {
        ctx = ctx.with_tcp_keepalive_secs(secs);
    }
    if let Some(d) = cfg.pow_difficulty {
        if d > 0 {
            info!(difficulty = d, "anti-DoS proof-of-work enabled");
        }
        ctx = ctx.with_pow_difficulty(d);
    }
    if let Some(n) = cfg.max_connections {
        info!(max = n, "max_connections cap configured");
        ctx = ctx.with_max_connections(n);
    } else {
        warn!(
            "no max_connections configured — server may be vulnerable to \
             accept-flood OOM. Set max_connections in server.yaml."
        );
    }
    // Build a ReloadableFirewall up front (even when no rules are
    // configured) so SIGHUP can later install rules without a
    // restart. We hold a handle for the SIGHUP task below.
    let firewall_handle = proteus_transport_alpha::firewall::ReloadableFirewall::default();
    if let Some(fw_cfg) = cfg.firewall.as_ref() {
        match build_firewall_from_cfg(fw_cfg) {
            Ok(fw) => {
                if fw.is_active() {
                    info!(
                        rules = fw.rule_count(),
                        allow_count = fw_cfg.allow.len(),
                        deny_count = fw_cfg.deny.len(),
                        "CIDR firewall configured"
                    );
                }
                firewall_handle.reload(fw);
            }
            Err(e) => return Err(e.into()),
        }
    }
    ctx = ctx.with_reloadable_firewall(firewall_handle.clone());

    // Server-aggregated metrics — wire into ctx so the hot-path
    // increments the right counters.
    let metrics = Arc::new(proteus_transport_alpha::metrics::ServerMetrics::default());
    ctx = ctx.with_metrics(Arc::clone(&metrics));

    // Rate-limit abuse detector — lives on ServerCtx because the
    // rate-limit rejection happens in the per-IP-rate gate before
    // the relay even runs.
    if let Some(c) = cfg
        .abuse_detector
        .as_ref()
        .and_then(|d| d.rate_limit.as_ref())
    {
        info!(
            window_secs = c.window_secs,
            threshold = c.threshold,
            "rate-limit abuse detector configured"
        );
        ctx = ctx.with_abuse_detector_rate_limit(Arc::new(
            proteus_transport_alpha::abuse_detector::AbuseDetector::new(
                std::time::Duration::from_secs(c.window_secs),
                c.threshold,
            ),
        ));
    }

    let ctx = Arc::new(ctx);

    if let Some(metrics_addr) = cfg.metrics_listen.clone() {
        // Load the bearer-token gate (if configured). Failing to read
        // the token file is fatal — silently downgrading to "no auth"
        // would expose /metrics on whatever interface the operator
        // chose, defeating the whole point of configuring auth.
        let auth = match cfg.metrics_token_file.as_ref() {
            Some(path) => {
                let raw = std::fs::read_to_string(path)
                    .map_err(|e| format!("metrics_token_file {path:?}: {e}"))?;
                let token = raw.trim();
                match proteus_transport_alpha::metrics_http::MetricsAuth::new(token) {
                    Some(a) => {
                        info!(path = ?path, "/metrics bearer-token auth configured");
                        Some(a)
                    }
                    None => {
                        return Err(format!(
                            "metrics_token_file {path:?} is empty — refusing to start \
                             with a missing token but auth configured"
                        )
                        .into());
                    }
                }
            }
            None => {
                if !proteus_server::is_loopback(&metrics_addr) {
                    warn!(
                        addr = %metrics_addr,
                        "metrics_listen is non-loopback but metrics_token_file is unset — \
                         /metrics is exposed without authentication"
                    );
                }
                None
            }
        };
        let metrics = Arc::clone(&metrics);
        tokio::spawn(async move {
            if let Err(e) =
                proteus_transport_alpha::metrics_http::serve_with_auth(&metrics_addr, metrics, auth)
                    .await
            {
                error!(error = %e, "metrics endpoint exited");
            }
        });
    }

    // Optionally build the TLS 1.3 outer wrapper, wrapped in a
    // ReloadableAcceptor so SIGHUP can swap in a freshly-renewed
    // Let's Encrypt cert without disturbing in-flight sessions.
    let reloadable_acceptor = match cfg.tls.as_ref() {
        Some(tls_cfg) => {
            info!(cert = ?tls_cfg.cert_chain, "loading TLS cert chain");
            let chain = proteus_transport_alpha::tls::load_cert_chain(&tls_cfg.cert_chain)
                .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
            let key = proteus_transport_alpha::tls::load_private_key(&tls_cfg.private_key)
                .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
            let acceptor = proteus_transport_alpha::tls::build_acceptor(chain, key)
                .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
            info!("TLS 1.3 outer wrapper enabled (SIGHUP triggers reload)");
            Some(proteus_transport_alpha::tls::ReloadableAcceptor::new(
                acceptor,
            ))
        }
        None => {
            warn!(
                "no `tls:` block in config — server will run plain TCP. \
                 This is INSECURE in production; passive DPI will identify the protocol."
            );
            None
        }
    };

    // One canonical startup-config banner so operators can verify
    // their YAML edit took effect via a single `journalctl` grep.
    // Emitted before listener bind so the banner is in the journal
    // even if bind fails (e.g. EADDRINUSE).
    let summary = startup::StartupSummary::from_config(&cfg);
    for line in summary.to_string().lines() {
        info!(target: "proteus_server::startup", "{line}");
    }
    for w in summary.warnings() {
        warn!(target: "proteus_server::startup", "{w}");
    }

    let listener =
        proteus_transport_alpha::server::bind_listener_with_reuseaddr(&cfg.listen_alpha).await?;
    info!(addr = %listener.local_addr()?, "α-profile listener bound (SO_REUSEADDR enabled)");

    // Listener bound and accept loop about to start — we are live and
    // ready. `alive` stays true for the lifetime of the process;
    // `ready` flips back to false on SIGTERM so load balancers drain
    // before the process exits.
    metrics
        .alive
        .store(true, std::sync::atomic::Ordering::Relaxed);
    metrics
        .ready
        .store(true, std::sync::atomic::Ordering::Relaxed);

    // Periodic rate-limit vacuum (every 60 s) so per-IP token-bucket
    // memory stays bounded regardless of traffic patterns.
    {
        let ctx_for_vacuum = Arc::clone(&ctx);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                ctx_for_vacuum.vacuum_rate_limit();
                ctx_for_vacuum.vacuum_user_limit();
            }
        });
    }

    // Graceful-shutdown signal handlers.
    let shutdown = {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler");
        let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            .expect("install SIGINT handler");
        async move {
            tokio::select! {
                _ = sigterm.recv() => info!("SIGTERM received, draining"),
                _ = sigint.recv() => info!("SIGINT received, draining"),
            }
        }
    };

    // SIGHUP — reload mutable runtime state from disk. The following
    // independent reloads share this signal:
    //
    // 1. TLS cert chain + private key (certbot deploy-hooks after
    //    Let's Encrypt renewal).
    // 2. CIDR firewall allow/deny rules (the operator banned a fresh
    //    abusive netblock in server.yaml).
    // 3. Rate-limit parameters: per-IP, per-user, and global
    //    handshake-budget burst/refill. Previously these required a
    //    binary restart, which tore down every in-flight session.
    //    Hot-reload preserves bucket state so already-good clients
    //    are not punished by the operator turning the dial.
    //
    // Each reload is independent: a parse failure on one does NOT
    // skip the others. Each leaves the existing in-memory state
    // intact on failure so a typo can't brick the running process.
    //
    // Hot-reload can only re-configure limiters that were INSTALLED
    // at startup (capacity > 0, refill > 0). Adding or removing a
    // limiter entirely still requires a restart, because the
    // ServerCtx field is `Option<...>` set at construction. The
    // workaround is to install a near-infinite limiter at boot
    // (e.g. burst=1e6, refill=1e6) and tighten it via SIGHUP — this
    // matches the operator's typical workflow (start lax, tighten
    // under attack).
    {
        let reloadable_acceptor = reloadable_acceptor.clone();
        let firewall_handle = firewall_handle.clone();
        let config_path = config_path.to_path_buf();
        let tls_cfg_path = cfg.tls.clone();
        let ctx_for_reload = Arc::clone(&ctx);
        tokio::spawn(async move {
            let mut sighup =
                match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
                    Ok(s) => s,
                    Err(e) => {
                        error!(error = %e, "install SIGHUP handler failed");
                        return;
                    }
                };
            while sighup.recv().await.is_some() {
                info!("SIGHUP received — reloading TLS cert and firewall rules");

                // ----- 1. TLS cert reload (if configured) -----
                if let (Some(tls_cfg), Some(reloadable)) =
                    (tls_cfg_path.as_ref(), reloadable_acceptor.as_ref())
                {
                    match (
                        proteus_transport_alpha::tls::load_cert_chain(&tls_cfg.cert_chain),
                        proteus_transport_alpha::tls::load_private_key(&tls_cfg.private_key),
                    ) {
                        (Ok(chain), Ok(key)) => {
                            match proteus_transport_alpha::tls::build_acceptor(chain, key) {
                                Ok(new_acceptor) => {
                                    reloadable.reload(new_acceptor);
                                    info!(cert = ?tls_cfg.cert_chain, "TLS cert reloaded");
                                }
                                Err(e) => {
                                    error!(error = %e, "TLS reload: build_acceptor failed; keeping old cert");
                                }
                            }
                        }
                        (Err(e), _) => {
                            error!(error = %e, "TLS reload: cert chain load failed; keeping old cert");
                        }
                        (_, Err(e)) => {
                            error!(error = %e, "TLS reload: private key load failed; keeping old cert");
                        }
                    }
                }

                // ----- 2. Firewall + rate-limit reload (re-read full
                //          YAML so the new rules come from the
                //          operator's edit) -----
                match config::ServerConfig::load(&config_path).await {
                    Ok(fresh_cfg) => {
                        // 2a. Firewall.
                        match fresh_cfg.firewall.as_ref() {
                            Some(fw_cfg) => match build_firewall_from_cfg(fw_cfg) {
                                Ok(new_fw) => {
                                    let rules = new_fw.rule_count();
                                    firewall_handle.reload(new_fw);
                                    info!(rules, "firewall rules reloaded");
                                }
                                Err(e) => {
                                    error!(error = %e, "firewall reload: parse error; keeping old rules");
                                }
                            },
                            None => {
                                // Config now has no firewall block — clear the rules.
                                firewall_handle
                                    .reload(proteus_transport_alpha::firewall::Firewall::new());
                                info!("firewall block removed from config; rules cleared");
                            }
                        }

                        // 2b. Per-IP rate-limit hot-swap.
                        if let Some(rl) = fresh_cfg.rate_limit.as_ref() {
                            if ctx_for_reload.reload_rate_limit(rl.burst, rl.refill_per_sec) {
                                info!(
                                    burst = rl.burst,
                                    refill = rl.refill_per_sec,
                                    "per-IP rate limit hot-reloaded"
                                );
                            } else {
                                warn!(
                                    "rate_limit edit ignored — no per-IP limiter was \
                                     installed at startup. Restart the binary to install one."
                                );
                            }
                        }

                        // 2c. Per-user rate-limit hot-swap.
                        if let Some(u) = fresh_cfg.user_rate_limit.as_ref() {
                            if ctx_for_reload.reload_user_rate_limit(u.burst, u.refill_per_sec) {
                                info!(
                                    burst = u.burst,
                                    refill = u.refill_per_sec,
                                    "per-user rate limit hot-reloaded"
                                );
                            } else {
                                warn!(
                                    "user_rate_limit edit ignored — no per-user limiter \
                                     was installed at startup. Restart to install one."
                                );
                            }
                        }

                        // 2d. Global handshake-budget hot-swap.
                        if let Some(b) = fresh_cfg.handshake_budget.as_ref() {
                            if ctx_for_reload.reload_handshake_budget(b.burst, b.refill_per_sec) {
                                info!(
                                    burst = b.burst,
                                    refill = b.refill_per_sec,
                                    "global handshake budget hot-reloaded"
                                );
                            } else {
                                warn!(
                                    "handshake_budget edit ignored — no global limiter \
                                     was installed at startup. Restart to install one."
                                );
                            }
                        }
                    }
                    Err(e) => {
                        error!(error = %e, "config re-read failed; keeping old firewall + rate-limit state");
                    }
                }
            }
        });
    }

    // Optional structured access log — one JSON Lines record per
    // completed session. Init early so the spawn task is ready before
    // the accept loop starts. Keep both the concrete handle (for the
    // SIGUSR1 reopen task) and a type-erased Arc<dyn LogSink> for the
    // relay's `RelayConfig.access_log`.
    let (access_log_concrete, access_log_handle): (
        Option<proteus_transport_alpha::access_log::AccessLogger>,
        Option<proteus_transport_alpha::access_log::AccessLogHandle>,
    ) = match cfg.access_log.as_ref() {
        Some(path) => {
            let logger = proteus_transport_alpha::access_log::AccessLogger::spawn(path)
                .await
                .map_err(|e| format!("access log open {path:?}: {e}"))?;
            info!(path = ?path, "access log enabled (SIGUSR1 triggers reopen)");
            let arc: proteus_transport_alpha::access_log::AccessLogHandle =
                Arc::new(logger.clone());
            (Some(logger), Some(arc))
        }
        None => (None, None),
    };

    // SIGUSR1 — flush + reopen the access-log FD. logrotate-style:
    //   /var/log/proteus/access.log {
    //       daily
    //       rotate 14
    //       compress
    //       postrotate
    //           systemctl kill --signal=USR1 proteus-server
    //       endscript
    //   }
    if let Some(logger) = access_log_concrete {
        tokio::spawn(async move {
            let mut sigusr1 =
                match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())
                {
                    Ok(s) => s,
                    Err(e) => {
                        error!(error = %e, "install SIGUSR1 handler failed");
                        return;
                    }
                };
            while sigusr1.recv().await.is_some() {
                info!(path = ?logger.path(), "SIGUSR1 — reopening access log");
                logger.reopen();
            }
        });
    }

    // Outbound destination filter (SSRF defense). Default is the
    // production policy (ports 80/443, SSRF CIDRs blocked); operator
    // can extend, override, or explicitly opt out.
    let outbound_filter = build_outbound_filter(cfg.outbound_filter.as_ref())?;

    // Build the byte-budget abuse detector; the rate-limit detector
    // is wired into the ctx earlier (before the Arc<ServerCtx> wrap)
    // because it's a ctx-resident component, while this one is owned
    // by RelayConfig.
    let abuse_detector_byte_budget = cfg
        .abuse_detector
        .as_ref()
        .and_then(|d| d.byte_budget.as_ref())
        .map(|c| {
            info!(
                window_secs = c.window_secs,
                threshold = c.threshold,
                "byte-budget abuse detector configured"
            );
            Arc::new(proteus_transport_alpha::abuse_detector::AbuseDetector::new(
                std::time::Duration::from_secs(c.window_secs),
                c.threshold,
            ))
        });

    // Per-session relay knobs. session_idle_secs=0 disables; default 600s.
    let relay_cfg = relay::RelayConfig {
        idle_timeout: match cfg.session_idle_secs.unwrap_or(600) {
            0 => None,
            n => Some(std::time::Duration::from_secs(n)),
        },
        metrics: Some(Arc::clone(&metrics)),
        access_log: access_log_handle,
        max_session_bytes: cfg.max_session_bytes,
        abuse_detector_byte_budget,
        outbound_filter: outbound_filter.clone(),
        pad_quantum: cfg.pad_quantum,
    };
    if let Some(q) = cfg.pad_quantum {
        if q > 0 {
            info!(
                quantum = q,
                "data-plane padding enabled (server→client direction)"
            );
        }
    }
    if let Some(n) = relay_cfg.max_session_bytes {
        info!(bytes = n, "per-session byte budget configured");
    }
    if let Some(d) = relay_cfg.idle_timeout {
        info!(secs = d.as_secs(), "session idle timeout configured");
    } else {
        warn!("session idle timeout disabled — long-idle sessions will not be reaped");
    }

    // Optionally bind the β-profile (QUIC over UDP) listener alongside
    // α. Both carriers share the SAME ServerCtx, metrics, allowlist,
    // rate limiter, abuse detector, access log — so operators get a
    // single unified observability surface across protocols.
    let beta_serve_fut: Option<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>> =
        match build_beta_endpoint(&cfg)? {
            Some(beta_endpoint) => {
                info!(addr = ?beta_endpoint.local_addr().ok(), "β-profile (QUIC) listener bound");
                let metrics_beta = Arc::clone(&metrics);
                let relay_cfg_beta = relay_cfg.clone();
                let ctx_beta = Arc::clone(&ctx);
                let on_session_beta =
                    move |session: proteus_transport_alpha::session::AlphaSession<
                        quinn::RecvStream,
                        quinn::SendStream,
                    >| {
                        let metrics = Arc::clone(&metrics_beta);
                        let relay_cfg = relay_cfg_beta.clone();
                        async move {
                            metrics
                                .sessions_accepted
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            metrics
                                .handshakes_succeeded
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            let snap = session.metrics.snapshot();
                            let _guard = proteus_transport_alpha::metrics::InFlightGuard::enter(
                                Arc::clone(&metrics),
                                snap,
                            );
                            if let Err(e) = relay::handle_session(session, relay_cfg).await {
                                warn!(error = %e, "β session terminated");
                            }
                        }
                    };
                Some(Box::pin(async move {
                    if let Err(e) = proteus_transport_beta::server::serve(
                        beta_endpoint,
                        ctx_beta,
                        on_session_beta,
                    )
                    .await
                    {
                        error!(error = %e, "β accept loop failed");
                    }
                }))
            }
            None => None,
        };

    let serve_fut: std::pin::Pin<
        Box<dyn std::future::Future<Output = std::io::Result<()>> + Send>,
    > = {
        let metrics_tcp = Arc::clone(&metrics);
        let relay_cfg_tcp = relay_cfg.clone();
        let on_session_tcp = move |session: proteus_transport_alpha::session::AlphaSession| {
            let metrics = Arc::clone(&metrics_tcp);
            let relay_cfg = relay_cfg_tcp.clone();
            async move {
                metrics
                    .sessions_accepted
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                metrics
                    .handshakes_succeeded
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                // RAII guard: increments in_flight_sessions; decrements
                // AND merges per-session totals on drop, even if the
                // handler future panics.
                let snap = session.metrics.snapshot();
                let _guard = proteus_transport_alpha::metrics::InFlightGuard::enter(
                    Arc::clone(&metrics),
                    snap,
                );
                if let Err(e) = relay::handle_session(session, relay_cfg).await {
                    warn!(error = %e, "session terminated");
                }
            }
        };
        match reloadable_acceptor.clone() {
            Some(acceptor) => {
                let metrics = Arc::clone(&metrics);
                let relay_cfg_tls = relay_cfg.clone();
                let on_session_tls =
                    move |session: proteus_transport_alpha::session::AlphaSession<
                        tokio::io::ReadHalf<proteus_transport_alpha::tls::ServerStream>,
                        tokio::io::WriteHalf<proteus_transport_alpha::tls::ServerStream>,
                    >| {
                        let metrics = Arc::clone(&metrics);
                        let relay_cfg = relay_cfg_tls.clone();
                        async move {
                            metrics
                                .sessions_accepted
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            metrics
                                .handshakes_succeeded
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            let snap = session.metrics.snapshot();
                            let _guard = proteus_transport_alpha::metrics::InFlightGuard::enter(
                                Arc::clone(&metrics),
                                snap,
                            );
                            if let Err(e) = relay::handle_session(session, relay_cfg).await {
                                warn!(error = %e, "TLS session terminated");
                            }
                        }
                    };
                Box::pin(server::serve_tls_reloadable(
                    listener,
                    ctx,
                    acceptor,
                    on_session_tls,
                ))
            }
            None => Box::pin(server::serve(listener, ctx, on_session_tcp)),
        }
    };

    // If β is configured, spawn it as a background task that runs
    // for the lifetime of the process. The shutdown signal (SIGTERM
    // / SIGINT) reaches it through the same `serve_fut`-completes-
    // or-shutdown-signal-fires select below; on signal we drop both
    // futures together via tokio::select!'s cancel semantics.
    let _beta_task = beta_serve_fut.map(tokio::spawn);

    tokio::select! {
        res = serve_fut => {
            if let Err(e) = res {
                error!(error = %e, "accept loop failed");
            }
        }
        () = shutdown => {
            let drain_secs = cfg.drain_secs.unwrap_or(30);
            // Flip /readyz to 503 *immediately* so the load balancer
            // stops sending new traffic. Existing in-flight sessions
            // continue to run during the drain window.
            metrics.ready.store(false, std::sync::atomic::Ordering::Relaxed);
            info!(secs = drain_secs, "draining outstanding sessions, /readyz now reports 503");
            // tokio::spawn'd session tasks are detached; we give them
            // a window to flush. Production deployment should set
            // systemd's `TimeoutStopSec` to drain_secs + 5s of margin.
            tokio::time::sleep(std::time::Duration::from_secs(drain_secs)).await;
            // Final liveness flip — we are about to exit; any further
            // /healthz probe should see 503.
            metrics.alive.store(false, std::sync::atomic::Ordering::Relaxed);
            info!("proteus-server exiting");
        }
    }

    Ok(())
}

/// Build a [`proteus_transport_alpha::firewall::Firewall`] from a
/// config block. Returns a human-readable error on the first
/// invalid CIDR (so the operator's typo doesn't silently downgrade
/// to "no firewall").
/// Build the runtime [`OutboundPolicy`] from the operator's YAML.
///
/// Defaults (no `outbound_filter` block): the production policy
/// (`OutboundPolicy::default()`, ports 80/443, SSRF blocklist on).
///
/// `disabled: true`: returns `None` (relay runs with no filter).
/// Strongly discouraged in production — emit a WARN at startup.
/// Build the β-profile quinn endpoint from config, falling back to
/// the α `tls.cert_chain` / `tls.private_key` when β-specific paths
/// aren't set (the common case: same Let's Encrypt cert for both
/// carriers). Returns Ok(None) when `listen_beta` isn't configured.
fn build_beta_endpoint(
    cfg: &config::ServerConfig,
) -> Result<Option<quinn::Endpoint>, Box<dyn std::error::Error>> {
    let listen = match cfg.listen_beta.as_ref() {
        Some(l) => l,
        None => return Ok(None),
    };
    let bind: std::net::SocketAddr = listen
        .parse()
        .map_err(|e| format!("listen_beta {listen:?}: {e}"))?;
    // Resolve the cert + key. Prefer the β-specific paths if set;
    // fall back to the α `tls.*` paths so operators don't have to
    // double-configure on the common case.
    let (cert_path, key_path) = match (
        cfg.beta_cert_chain.as_ref(),
        cfg.beta_private_key.as_ref(),
        cfg.tls.as_ref(),
    ) {
        (Some(c), Some(k), _) => (c.clone(), k.clone()),
        (_, _, Some(tls)) => (tls.cert_chain.clone(), tls.private_key.clone()),
        _ => {
            return Err(
                "listen_beta is set but neither beta_cert_chain+beta_private_key nor tls.* is configured"
                    .into(),
            );
        }
    };
    let chain = proteus_transport_alpha::tls::load_cert_chain(&cert_path)
        .map_err(|e| format!("β cert chain {cert_path:?}: {e}"))?;
    let key = proteus_transport_alpha::tls::load_private_key(&key_path)
        .map_err(|e| format!("β private key {key_path:?}: {e}"))?;
    let endpoint = proteus_transport_beta::server::make_endpoint(bind, chain, key)
        .map_err(|e| format!("β endpoint: {e}"))?;
    Ok(Some(endpoint))
}

fn build_outbound_filter(
    cfg: Option<&config::OutboundFilterCfg>,
) -> Result<
    Option<Arc<proteus_transport_alpha::outbound_filter::OutboundPolicy>>,
    Box<dyn std::error::Error>,
> {
    let cfg = match cfg {
        Some(c) => c,
        None => {
            // Operator left the block unset → production defaults.
            info!("outbound destination filter: default (ports 80/443, SSRF CIDRs blocked)");
            return Ok(Some(Arc::new(
                proteus_transport_alpha::outbound_filter::OutboundPolicy::default(),
            )));
        }
    };
    if cfg.disabled {
        warn!(
            "outbound_filter.disabled = true — server will dial ANY destination including \
             cloud metadata endpoints (169.254.169.254) and RFC 1918 internal networks. \
             ONLY safe for testing / trusted-LAN deployments."
        );
        return Ok(None);
    }
    let mut policy = proteus_transport_alpha::outbound_filter::OutboundPolicy::default();
    // Port handling: explicit allowed_ports replaces the default;
    // extra_ports adds on top.
    if let Some(ports) = cfg.allowed_ports.clone() {
        policy = policy.with_allowed_ports(ports);
    }
    if !cfg.extra_ports.is_empty() {
        policy = policy.extend_allowed_ports(cfg.extra_ports.iter().copied());
    }
    if cfg.replace_default_blocklist {
        policy = policy.with_no_default_blocklist();
    }
    if !cfg.extra_blocked_cidrs.is_empty() {
        policy
            .extend_blocked_cidrs(&cfg.extra_blocked_cidrs)
            .map_err(|e| format!("outbound_filter.extra_blocked_cidrs: {e}"))?;
    }
    if !cfg.allowed_hostnames.is_empty() {
        policy
            .extend_allowed_hostnames(&cfg.allowed_hostnames)
            .map_err(|e| format!("outbound_filter.allowed_hostnames: {e}"))?;
    }
    if !cfg.blocked_hostnames.is_empty() {
        policy
            .extend_blocked_hostnames(&cfg.blocked_hostnames)
            .map_err(|e| format!("outbound_filter.blocked_hostnames: {e}"))?;
    }
    info!(
        replace_blocklist = cfg.replace_default_blocklist,
        extra_cidrs = cfg.extra_blocked_cidrs.len(),
        extra_ports = cfg.extra_ports.len(),
        allowed_hostnames = cfg.allowed_hostnames.len(),
        blocked_hostnames = cfg.blocked_hostnames.len(),
        "outbound destination filter configured"
    );
    Ok(Some(Arc::new(policy)))
}

fn build_firewall_from_cfg(
    cfg: &config::FirewallCfg,
) -> Result<proteus_transport_alpha::firewall::Firewall, String> {
    let mut fw = proteus_transport_alpha::firewall::Firewall::new();
    fw.extend_allow(&cfg.allow)
        .map_err(|e| format!("firewall.allow parse error: {e}"))?;
    fw.extend_deny(&cfg.deny)
        .map_err(|e| format!("firewall.deny parse error: {e}"))?;
    Ok(fw)
}
