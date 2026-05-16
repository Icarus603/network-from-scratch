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

use clap::Parser;
use tokio::net::TcpListener;
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

    loop {
        let (stream, peer) = listener.accept().await?;
        let cfg = Arc::clone(&cfg);
        tokio::spawn(async move {
            if let Err(e) = socks::handle_socks5(stream, &cfg).await {
                warn!(peer = %peer, error = %e, "socks5 session ended");
            }
        });
    }
}
