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
//! # Compare PerfProfile padding on/off (flag presence = on):
//! proteus-bench beta            # baseline (pad=false)
//! proteus-bench beta --pad-mtu  # padded (pad=true)
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
    /// Multi-client soak: spawn N concurrent clients, hammer one
    /// in-process server for T seconds, report per-interval JSON
    /// progress + an end-of-soak summary. Answers "does this
    /// binary survive N simultaneous CONNECTs for an hour without
    /// leaking sessions / memory / FDs?" — the production-stability
    /// question single-stream throughput cannot answer.
    Soak(SoakArgs),
    /// Same-host β QUIC bench. Mints fresh keys + cert, runs an
    /// in-process server, dials it, blasts a payload, prints JSON.
    Beta(BetaArgs),
    /// Cross-host β QUIC server. Binds + echos forever, prints the
    /// server identity banner the matching `beta-client` consumes.
    BetaServer(BetaServerArgs),
    /// Cross-host β QUIC client. Connects to a peer brought up via
    /// `bench beta-server`, blasts a payload, prints JSON.
    /// Identity fields are copy-pasted verbatim from the server's
    /// banner.
    BetaClient(BetaClientArgs),
}

#[derive(clap::Args, Debug)]
struct SoakArgs {
    /// Number of concurrent clients to spawn. Each runs an
    /// independent open-blast-close loop until the deadline.
    /// Production-scale targets: 50 (small VPN), 200 (medium),
    /// 1000+ (operator stress test).
    #[arg(long, default_value = "10")]
    clients: usize,
    /// Total soak duration in seconds. 60 for quick smoke,
    /// 3600 for "can this survive an hour", 86400 for an
    /// overnight memory-leak hunt.
    #[arg(long, default_value = "60")]
    duration_secs: u64,
    /// Per-session round-trip payload in KiB. Small (4-16) =
    /// connection-rate-bound (tests handshake + accept loop);
    /// large (1024+) = bandwidth-bound (tests pump + flow-control).
    #[arg(long, default_value = "16")]
    per_session_kib: u64,
    /// Progress reporter interval in seconds.
    #[arg(long, default_value = "5")]
    report_interval_secs: u64,
    /// Optional dial-concurrency cap. None = unbounded.
    /// Mirrors a production `max_inflight_sessions` setting if
    /// you want to soak the cap behavior too.
    #[arg(long)]
    max_concurrent_dials: Option<usize>,
    /// Minimum dial success rate the summary must meet for the
    /// process to exit 0. Below threshold OR any spawn leak →
    /// exit 1 (CI-friendly).
    #[arg(long, default_value = "0.99")]
    min_success_rate: f64,
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
    /// Override the per-stream receive window (MiB). The production
    /// default is 64 MiB which caps a single-stream β bench around
    /// 94 MiB/s on this dev box. Bump (e.g. `--stream-window-mib
    /// 256`) to test where BBR's bandwidth estimate stops being the
    /// bottleneck. **Bench-only knob; production keeps the 64 MiB
    /// default.**
    #[arg(long)]
    stream_window_mib: Option<u32>,
    /// Override the per-connection receive window (MiB). The
    /// production default is 256 MiB. Bench-only; matches the
    /// per-stream override semantics.
    #[arg(long)]
    connection_window_mib: Option<u32>,
    /// Synthetic packet-loss percentage applied by an in-process
    /// UDP forwarder between client and server. 0 = passthrough
    /// (no forwarder spawned, no overhead). The forwarder is
    /// pure Rust, runs in-process on any platform — no Linux
    /// netem / tc qdisc required. Common cells: 1 (typical
    /// Wi-Fi), 5 (congested cellular), 15 (degraded long-haul),
    /// 30 (Hy2 Brutal's stress design point).
    #[arg(long, default_value = "0.0")]
    loss_pct: f64,
    /// One-way packet delay (milliseconds) applied by the
    /// forwarder. RTT = `2 × delay`. 0 = passthrough. Common
    /// cells: 0 (LAN), 10 (regional), 50 (transcontinental),
    /// 200 (satellite).
    #[arg(long, default_value = "0")]
    delay_ms: u64,
}

#[derive(clap::Args, Debug)]
struct BetaServerArgs {
    /// Address to bind the QUIC server on.
    #[arg(long, default_value = "127.0.0.1:0")]
    bind: String,
    /// Extra SAN to include in the self-signed cert beyond `localhost`.
    /// Set to the hostname (or IP) the client will dial — otherwise
    /// the cross-host TLS handshake will fail with `NotValidForName`.
    /// Example: `--extra-san my-vps.example.com` or
    /// `--extra-san 203.0.113.4`.
    #[arg(long)]
    extra_san: Option<String>,
}

#[derive(clap::Args, Debug)]
struct BetaClientArgs {
    /// Peer's `host:port`. Same value the server's banner emitted as
    /// `BENCH_SERVER_LISTEN_ADDR=`.
    #[arg(long)]
    server_addr: String,
    /// SNI string the client presents during TLS. Must match a SAN
    /// in the server's self-signed cert; defaults to `localhost`
    /// which works only when the server cert was minted without
    /// `--extra-san`.
    #[arg(long, default_value = "localhost")]
    server_name: String,
    /// Server's leaf cert DER as hex. From the server banner's
    /// `BENCH_SERVER_LEAF_CERT_HEX=` line.
    #[arg(long)]
    server_leaf_cert_hex: String,
    /// Server's ML-KEM-768 EK as hex. From the server banner's
    /// `BENCH_SERVER_MLKEM_PK_HEX=` line.
    #[arg(long)]
    server_mlkem_pk_hex: String,
    /// Server's X25519 public key as hex. From the server banner's
    /// `BENCH_SERVER_X25519_PUB_HEX=` line.
    #[arg(long)]
    server_x25519_pub_hex: String,
    /// Server's PQ fingerprint (SHA-256 of mlkem_pk_bytes) as hex.
    /// From the server banner's `BENCH_SERVER_PQ_FINGERPRINT_HEX=`
    /// line. The client cross-checks this against a freshly-computed
    /// hash of the supplied mlkem_pk and refuses to connect on
    /// mismatch — protects against copy-paste error.
    #[arg(long)]
    server_pq_fingerprint_hex: String,
    /// Payload size in MiB. Same semantics as `bench beta`.
    #[arg(long, default_value = "16")]
    payload_mib: u64,
    /// Per-`send_record` chunk size in KiB.
    #[arg(long, default_value = "64")]
    chunk_kib: u64,
    /// Connect / idle timeout in seconds.
    #[arg(long, default_value = "30")]
    connect_timeout_secs: u64,
    /// Total per-run timeout in seconds.
    #[arg(long, default_value = "120")]
    total_timeout_secs: u64,
    /// `PerfProfile.pad_quic_datagrams_to_mtu`.
    #[arg(long, default_value = "false")]
    pad_mtu: bool,
    /// `PerfProfile.initial_mtu`.
    #[arg(long, default_value = "1350")]
    initial_mtu: u16,
    /// `PerfProfile.mtu_upper_bound`.
    #[arg(long, default_value = "1452")]
    mtu_upper_bound: u16,
    /// `PerfProfile.ack_eliciting_threshold`.
    #[arg(long, default_value = "1")]
    ack_eliciting_threshold: u32,
    /// `PerfProfile.allow_spin_bit`.
    #[arg(long, default_value = "false")]
    allow_spin_bit: bool,
    /// Per-stream receive window override (MiB). Same semantics as
    /// the same-host `beta` subcommand — bench-only knob.
    #[arg(long)]
    stream_window_mib: Option<u32>,
    /// Per-connection receive window override (MiB). Bench-only.
    #[arg(long)]
    connection_window_mib: Option<u32>,
    /// Number of runs to repeat back-to-back. Each opens a fresh
    /// connection (cold-start cost included).
    #[arg(long, default_value = "1")]
    runs: u32,
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
        Cmd::Soak(args) => run_soak_cmd(args).await?,
        Cmd::Beta(args) => run_beta(args).await?,
        Cmd::BetaServer(args) => run_beta_server(args).await?,
        Cmd::BetaClient(args) => run_beta_client(args).await?,
    }
    Ok(())
}

async fn run_soak_cmd(args: SoakArgs) -> Result<(), Box<dyn std::error::Error>> {
    use std::time::Duration;
    let cfg = proteus_bench::soak::SoakConfig {
        clients: args.clients,
        duration: Duration::from_secs(args.duration_secs),
        per_session_kib: args.per_session_kib,
        report_interval: Duration::from_secs(args.report_interval_secs),
        max_concurrent_dials: args.max_concurrent_dials,
    };
    info!(
        clients = cfg.clients,
        duration_secs = args.duration_secs,
        per_session_kib = args.per_session_kib,
        "soak run starting"
    );
    // Progress lines AND the final summary both go to stdout —
    // pipe `proteus-bench soak ... | tee soak.jsonl` and you get
    // the full record. Use `jq 'select(.kind=="summary")'` to
    // extract just the verdict.
    let summary = proteus_bench::soak::run_soak(cfg, PerfProfile::default(), |p| {
        print!("{}", p.to_json());
    })
    .await?;
    print!("{}", summary.to_json());
    info!(
        success_rate = summary.success_rate,
        dials_succeeded = summary.dials_succeeded,
        dials_failed = summary.dials_failed,
        peak_concurrent = summary.peak_concurrent,
        spawn_leak_count = summary.spawn_leak_count,
        "soak run completed"
    );
    if !summary.passed(args.min_success_rate) {
        return Err(format!(
            "soak FAILED: success_rate {:.4} < min {:.4} OR spawn_leak={} OR zero dials succeeded",
            summary.success_rate, args.min_success_rate, summary.spawn_leak_count
        )
        .into());
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
        stream_receive_window_override: args.stream_window_mib.map(|m| m * 1024 * 1024),
        connection_receive_window_override: args.connection_window_mib.map(|m| m * 1024 * 1024),
    };
    let payload_bytes = (args.payload_mib as usize) * 1024 * 1024;
    let chunk_bytes = (args.chunk_kib as usize) * 1024;
    let connect_timeout = Duration::from_secs(args.connect_timeout_secs);
    let total_timeout = Duration::from_secs(args.total_timeout_secs);
    let netem = proteus_bench::netem::NetemConfig {
        loss_pct: args.loss_pct,
        delay: Duration::from_millis(args.delay_ms),
        seed: None,
    };

    for run_ix in 0..args.runs {
        info!(
            run = run_ix + 1,
            of = args.runs,
            payload_mib = args.payload_mib,
            chunk_kib = args.chunk_kib,
            loss_pct = args.loss_pct,
            delay_ms = args.delay_ms,
            "bench run starting"
        );
        let report = beta::run_same_host_bench_with_netem(
            payload_bytes,
            chunk_bytes,
            perf,
            connect_timeout,
            total_timeout,
            netem,
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
    let cert = beta::mint_self_signed(args.extra_san.as_deref())?;
    let leaf_hex = cert.leaf_hex.clone();
    let bind: std::net::SocketAddr = args.bind.parse()?;
    let (local, identity, server_fut) =
        beta::spawn_echo_server(bind, cert, PerfProfile::default()).await?;
    info!(addr = %local, "bench β server bound");
    // ALL banner lines go to stdout in one print! call so the
    // operator can grep them as a unit (no interleaving with the
    // tracing rail's stderr output). Operator's `beta-client`
    // invocation copies each line's RHS into the matching `--server-*-hex`
    // flag.
    print!("{}", identity.banner(local, &leaf_hex));
    server_fut.await?;
    Ok(())
}

async fn run_beta_client(args: BetaClientArgs) -> Result<(), Box<dyn std::error::Error>> {
    let server_addr: std::net::SocketAddr = args.server_addr.parse()?;
    let pinned_leaf = beta::decode_pinned_cert(&args.server_leaf_cert_hex)?;
    let mlkem_pk = hex::decode(&args.server_mlkem_pk_hex)
        .map_err(|e| format!("server_mlkem_pk_hex decode: {e}"))?;
    let x25519_pub_bytes = hex::decode(&args.server_x25519_pub_hex)
        .map_err(|e| format!("server_x25519_pub_hex decode: {e}"))?;
    let pq_fp_bytes = hex::decode(&args.server_pq_fingerprint_hex)
        .map_err(|e| format!("server_pq_fingerprint_hex decode: {e}"))?;
    let x25519_pub: [u8; 32] = x25519_pub_bytes.as_slice().try_into().map_err(|_| {
        format!(
            "server_x25519_pub_hex must decode to exactly 32 bytes, got {}",
            x25519_pub_bytes.len()
        )
    })?;
    let pq_fingerprint: [u8; 32] = pq_fp_bytes.as_slice().try_into().map_err(|_| {
        format!(
            "server_pq_fingerprint_hex must decode to exactly 32 bytes, got {}",
            pq_fp_bytes.len()
        )
    })?;

    let perf = PerfProfile {
        initial_mtu: args.initial_mtu,
        pad_quic_datagrams_to_mtu: args.pad_mtu,
        allow_spin_bit: args.allow_spin_bit,
        ack_eliciting_threshold: args.ack_eliciting_threshold,
        mtu_upper_bound: args.mtu_upper_bound,
        stream_receive_window_override: args.stream_window_mib.map(|m| m * 1024 * 1024),
        connection_receive_window_override: args.connection_window_mib.map(|m| m * 1024 * 1024),
    };
    let payload_bytes = (args.payload_mib as usize) * 1024 * 1024;
    let chunk_bytes = (args.chunk_kib as usize) * 1024;
    let connect_timeout = Duration::from_secs(args.connect_timeout_secs);
    let total_timeout = Duration::from_secs(args.total_timeout_secs);

    for run_ix in 0..args.runs {
        info!(
            run = run_ix + 1,
            of = args.runs,
            server_addr = %server_addr,
            "cross-host bench run starting"
        );
        let report = beta::run_cross_host_bench(
            &args.server_name,
            server_addr,
            pinned_leaf.clone(),
            mlkem_pk.clone(),
            x25519_pub,
            pq_fingerprint,
            payload_bytes,
            chunk_bytes,
            perf,
            connect_timeout,
            total_timeout,
        )
        .await?;
        print!("{}", report.to_json());
        info!(
            mib_per_sec = report.mib_per_sec,
            gbps = report.gbps,
            elapsed_secs = report.elapsed_secs,
            "cross-host bench run completed"
        );
    }
    Ok(())
}
