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

use proteus_client::config::ClientConfig;
use proteus_client::socks;

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
    }
    Ok(())
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
                        tokio::spawn(async move {
                            let _permit = permit; // drop on task exit
                            if let Err(e) = socks::handle_socks5(stream, &cfg).await {
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
