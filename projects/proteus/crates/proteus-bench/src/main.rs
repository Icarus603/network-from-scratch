//! `proteus-bench` — reproducible throughput / latency benchmark.
//!
//! Subcommands:
//!
//!   - `bench beta` — same-host β QUIC bench. Mints fresh keys + cert,
//!     runs server + client in one process, emits one JSON-line report.
//!     This is the variant that works end-to-end today.
//!   - `bench beta-server` — cross-host bench server (binds, accepts
//!     forever, echos). Prints the leaf cert hex + the listen address
//!     so the operator can copy them to the `beta-client` invocation.
//!     **NOTE**: cross-host needs server-identity export which is not
//!     yet wired; today `beta-server` runs but the matching
//!     `beta-client` will fail handshake until the operator brings the
//!     two together with a key-export flag (next iteration).
//!
//! Usage examples:
//!
//! ```bash
//! # Single-host throughput baseline (default 16 MiB / 64 KiB chunks):
//! proteus-bench beta
//!
//! # Sweep a payload size:
//! for sz in 4 16 64; do
//!   proteus-bench beta --payload-mib $sz
//! done | tee /tmp/bench.jsonl
//!
//! # Compare PerfProfile padding on/off:
//! proteus-bench beta --pad-mtu false  # baseline
//! proteus-bench beta --pad-mtu true   # padded
//!
//! # Inside an OrbStack Linux VM with netem applied to lo0:
//! #   sudo tc qdisc add dev lo root netem loss 5% delay 50ms
//! # then in another shell:
//! proteus-bench beta --payload-mib 32
//! ```

use std::time::Duration;

use clap::{Parser, Subcommand};
use proteus_bench::beta;
use proteus_transport_beta::PerfProfile;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(version, about = "Proteus throughput / latency bench harness")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Same-host β QUIC bench. Mints fresh keys + cert, runs an
    /// in-process server, dials it, blasts a payload, prints JSON.
    Beta(BetaArgs),
    /// Cross-host β QUIC server. Binds + echos forever. NOT YET wired
    /// for full cross-host bench (server-identity export pending).
    BetaServer(BetaServerArgs),
}

#[derive(clap::Args, Debug)]
struct BetaArgs {
    /// Payload size in MiB. 16 is the in-tree throughput-smoke
    /// baseline; sweep [4, 16, 64, 256] for amortization curves.
    #[arg(long, default_value = "16")]
    payload_mib: u64,
    /// Per-`send_record` chunk size in KiB. 64 is the in-tree default
    /// and matches what real bulk transfers look like.
    #[arg(long, default_value = "64")]
    chunk_kib: u64,
    /// Number of runs to repeat back-to-back. Lets the operator
    /// average out cold-start variance with a single command.
    #[arg(long, default_value = "1")]
    runs: u32,
    /// Connect timeout in seconds (bounds handshake AND the per-
    /// operation timeout used to gate send/recv stalls).
    #[arg(long, default_value = "30")]
    connect_timeout_secs: u64,
    /// Total per-run timeout in seconds. Bounds the entire blast +
    /// drain phase so a stuck run terminates rather than hanging
    /// the bench script.
    #[arg(long, default_value = "120")]
    total_timeout_secs: u64,
    /// `PerfProfile.pad_quic_datagrams_to_mtu`. Off = raw throughput,
    /// on = uniform UDP datagram lengths (traffic-analysis defense).
    #[arg(long, default_value = "false")]
    pad_mtu: bool,
    /// `PerfProfile.initial_mtu`. 1350 = conservative default.
    #[arg(long, default_value = "1350")]
    initial_mtu: u16,
    /// `PerfProfile.mtu_upper_bound`. 1452 = Ethernet max under
    /// IPv6+UDP; raise for known jumbo-frame paths.
    #[arg(long, default_value = "1452")]
    mtu_upper_bound: u16,
    /// `PerfProfile.ack_eliciting_threshold`. 1 = disabled (BBR-safe
    /// default); 10 = aggressive long-fat-pipe tuning. Defaults to
    /// disabled because long-RTT-only optimization breaks loopback /
    /// LAN throughput when applied universally.
    #[arg(long, default_value = "1")]
    ack_eliciting_threshold: u32,
    /// `PerfProfile.allow_spin_bit`. false = privacy-default (no
    /// wire-visible RTT side channel); true = matches quinn upstream.
    #[arg(long, default_value = "false")]
    allow_spin_bit: bool,
}

#[derive(clap::Args, Debug)]
struct BetaServerArgs {
    /// Address to bind the QUIC server on.
    #[arg(long, default_value = "127.0.0.1:0")]
    bind: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // RUST_LOG=proteus_bench=info,info by default — bench output is
    // already structured (JSON to stdout), the tracing rail is just
    // for setup logs.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(true)
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Beta(args) => run_beta(args).await?,
        Cmd::BetaServer(args) => run_beta_server(args).await?,
    }
    Ok(())
}

async fn run_beta(args: BetaArgs) -> Result<(), Box<dyn std::error::Error>> {
    let perf = PerfProfile {
        initial_mtu: args.initial_mtu,
        pad_quic_datagrams_to_mtu: args.pad_mtu,
        allow_spin_bit: args.allow_spin_bit,
        ack_eliciting_threshold: args.ack_eliciting_threshold,
        mtu_upper_bound: args.mtu_upper_bound,
    };
    let payload_bytes = (args.payload_mib as usize) * 1024 * 1024;
    let chunk_bytes = (args.chunk_kib as usize) * 1024;
    let connect_timeout = Duration::from_secs(args.connect_timeout_secs);
    let total_timeout = Duration::from_secs(args.total_timeout_secs);

    for run_ix in 0..args.runs {
        info!(
            run = run_ix + 1,
            of = args.runs,
            payload_mib = args.payload_mib,
            chunk_kib = args.chunk_kib,
            "bench run starting"
        );
        let report = beta::run_same_host_bench(
            payload_bytes,
            chunk_bytes,
            perf,
            connect_timeout,
            total_timeout,
        )
        .await?;
        // ONE LINE OF JSON to stdout. Operators pipe stdout through
        // `tee /tmp/bench.jsonl | jq -c .` so the structured log is
        // captured and the human-friendly summary is rendered.
        print!("{}", report.to_json());
        info!(
            mib_per_sec = report.mib_per_sec,
            gbps = report.gbps,
            elapsed_secs = report.elapsed_secs,
            "bench run completed"
        );
    }
    Ok(())
}

async fn run_beta_server(args: BetaServerArgs) -> Result<(), Box<dyn std::error::Error>> {
    let cert = beta::mint_self_signed(None)?;
    let bind: std::net::SocketAddr = args.bind.parse()?;
    let (local, server_fut) = beta::spawn_echo_server(bind, cert, PerfProfile::default()).await?;
    info!(addr = %local, "bench β server bound");
    println!("BENCH_SERVER_LISTEN_ADDR={local}");
    // NOTE: leaf hex is intentionally NOT printed here — the matching
    // client-side decode flag is the next iteration, and printing
    // bytes that nothing-yet-consumes would just clutter the operator's
    // terminal. Once the cross-host bench client lands, this server
    // will print BENCH_SERVER_LEAF_CERT_HEX=<hex> for the operator to
    // copy into the client.
    server_fut.await?;
    Ok(())
}
