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

mod config;
mod gencert;
mod keygen;
mod relay;

use config::{load_server_keys, ServerConfig};

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
            "rate limit configured"
        );
        ctx = ctx.with_rate_limiter(proteus_transport_alpha::rate_limit::RateLimiter::new(
            rl.burst,
            rl.refill_per_sec,
        ));
    } else {
        warn!("no rate_limit configured — server may be vulnerable to ML-KEM amplification DoS");
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

    // Server-aggregated metrics — wire into ctx so the hot-path
    // increments the right counters.
    let metrics = Arc::new(proteus_transport_alpha::metrics::ServerMetrics::default());
    ctx = ctx.with_metrics(Arc::clone(&metrics));
    let ctx = Arc::new(ctx);

    if let Some(metrics_addr) = cfg.metrics_listen.clone() {
        let metrics = Arc::clone(&metrics);
        tokio::spawn(async move {
            if let Err(e) =
                proteus_transport_alpha::metrics_http::serve(&metrics_addr, metrics).await
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

    // SIGHUP — reload TLS cert chain + private key from disk. Used by
    // certbot deploy-hooks after Let's Encrypt renewal. In-flight
    // sessions are unaffected; the new cert takes effect on the very
    // next accept().
    if let (Some(tls_cfg), Some(reloadable)) = (cfg.tls.clone(), reloadable_acceptor.clone()) {
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
                info!(cert = ?tls_cfg.cert_chain, "SIGHUP — reloading TLS cert chain");
                let chain = match proteus_transport_alpha::tls::load_cert_chain(&tls_cfg.cert_chain)
                {
                    Ok(c) => c,
                    Err(e) => {
                        // Reload failed — keep the old acceptor and
                        // log loudly. The operator can fix the file
                        // and signal again.
                        error!(error = %e, "TLS reload: cert chain load failed; keeping old cert");
                        continue;
                    }
                };
                let key = match proteus_transport_alpha::tls::load_private_key(&tls_cfg.private_key)
                {
                    Ok(k) => k,
                    Err(e) => {
                        error!(error = %e, "TLS reload: private key load failed; keeping old cert");
                        continue;
                    }
                };
                let new_acceptor = match proteus_transport_alpha::tls::build_acceptor(chain, key) {
                    Ok(a) => a,
                    Err(e) => {
                        error!(error = %e, "TLS reload: build_acceptor failed; keeping old cert");
                        continue;
                    }
                };
                reloadable.reload(new_acceptor);
                info!("TLS cert reloaded successfully");
            }
        });
    }

    let serve_fut: std::pin::Pin<
        Box<dyn std::future::Future<Output = std::io::Result<()>> + Send>,
    > = {
        let metrics_tcp = Arc::clone(&metrics);
        let on_session_tcp = move |session: proteus_transport_alpha::session::AlphaSession| {
            let metrics = Arc::clone(&metrics_tcp);
            async move {
                metrics
                    .sessions_accepted
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                metrics
                    .handshakes_succeeded
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                metrics
                    .in_flight_sessions
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let snap = session.metrics.snapshot();
                if let Err(e) = relay::handle_session(session).await {
                    warn!(error = %e, "session terminated");
                }
                metrics.merge_session(&snap);
                metrics
                    .in_flight_sessions
                    .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            }
        };
        match reloadable_acceptor.clone() {
            Some(acceptor) => {
                let metrics = Arc::clone(&metrics);
                let on_session_tls =
                    move |session: proteus_transport_alpha::session::AlphaSession<
                        tokio::io::ReadHalf<proteus_transport_alpha::tls::ServerStream>,
                        tokio::io::WriteHalf<proteus_transport_alpha::tls::ServerStream>,
                    >| {
                        let metrics = Arc::clone(&metrics);
                        async move {
                            metrics
                                .sessions_accepted
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            metrics
                                .handshakes_succeeded
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            metrics
                                .in_flight_sessions
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            let snap = session.metrics.snapshot();
                            if let Err(e) = relay::handle_session(session).await {
                                warn!(error = %e, "TLS session terminated");
                            }
                            metrics.merge_session(&snap);
                            metrics
                                .in_flight_sessions
                                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
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
