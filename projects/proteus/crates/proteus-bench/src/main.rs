//! `proteus-bench` — reproducible throughput / latency benchmark.
//!
//! Subcommands:
//!
//!   - `bench beta` — same-host β QUIC bench. Mints fresh keys + cert,
//!     runs server + client in one process, emits one JSON-line report.
//!     This is the variant that works end-to-end today.
//!   - `bench beta-server` — cross-host bench server (binds, accepts
//!     forever, echos). Prints a 5-line identity banner — listen addr,
//!     leaf cert DER hex, ML-KEM-768 EK hex, X25519 pub hex, PQ
//!     fingerprint hex — that the operator copy-pastes into the
//!     matching `beta-client --server-*-hex` flags. The client
//!     re-derives `SHA-256(mlkem_pk)` and refuses the dial if the
//!     supplied fingerprint disagrees, catching copy-paste typos at
//!     parse time instead of an opaque handshake failure 30 s later.
//!   - `bench beta-client` — cross-host bench client. Consumes the
//!     banner emitted by `bench beta-server`, runs the throughput
//!     blast, emits one JSON-line report.
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

use clap::{Parser, Subcommand, ValueEnum};
use proteus_bench::{alpha, beta};
use proteus_transport_beta::{CongestionKind, PerfProfile};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(version, about = "Proteus throughput / latency bench harness")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum BenchCongestion {
    Bbr,
    Brutal,
}

impl From<BenchCongestion> for CongestionKind {
    fn from(value: BenchCongestion) -> Self {
        match value {
            BenchCongestion::Bbr => Self::Bbr,
            BenchCongestion::Brutal => Self::Brutal,
        }
    }
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
    /// Same-host α profile bench (raw TCP **or** TLS-wrapped). The
    /// `--tls` switch picks the production-shape variant; default is
    /// raw-TCP (matches the in-tree throughput_smoke test, which is
    /// the closest direct comparison to a regression-floor number).
    /// Operators asking "is α faster than my current REALITY setup
    /// on this VPS?" should pass `--tls`.
    Alpha(AlphaArgs),
    /// Cross-host α-TLS bench server. Binds + echoes + prints the
    /// same 5-line identity banner as `beta-server` (plus the leaf
    /// cert hex for the operator to pin client-side). Production-
    /// shape: TLS 1.3 + ALPN h2/http/1.1 + RFC 5705 channel binding.
    AlphaServerTls(AlphaServerTlsArgs),
    /// Cross-host α-TLS bench client. Consumes the
    /// `AlphaServerTls` banner via `--server-*-hex` flags.
    AlphaClientTls(AlphaClientTlsArgs),
    /// Standalone bidirectional UDP impairment forwarder for
    /// version-pinned external competitors such as Hysteria2 and
    /// TUIC. Emits a ready banner immediately and a final JSON row
    /// with measured packet/drop counters.
    UdpForwarder(UdpForwarderArgs),
    /// Protocol-neutral TCP echo endpoint for external SOCKS5 proxy
    /// benchmarks such as TUIC v5.
    TcpEchoServer(TcpEchoServerArgs),
    /// Byte-verified round-trip workload through a SOCKS5 listener.
    Socks5Roundtrip(Socks5RoundtripArgs),
}

#[derive(clap::Args, Debug)]
struct TcpEchoServerArgs {
    #[arg(long, default_value = "0.0.0.0:18080")]
    bind: String,
}

#[derive(clap::Args, Debug)]
struct Socks5RoundtripArgs {
    #[arg(long)]
    socks_addr: String,
    #[arg(long)]
    target_addr: String,
    #[arg(long, default_value = "64")]
    payload_mib: u64,
    #[arg(long, default_value = "64")]
    chunk_kib: u64,
    #[arg(long, default_value = "300")]
    timeout_secs: u64,
    #[arg(long, default_value = "1")]
    runs: u32,
}

#[derive(clap::Args, Debug)]
struct UdpForwarderArgs {
    /// Client-facing UDP address. Point the competitor client here.
    #[arg(long)]
    bind: String,
    /// Real competitor server UDP address.
    #[arg(long)]
    target: String,
    /// Independent per-packet loss percentage in each direction.
    #[arg(long, default_value = "0")]
    loss_pct: f64,
    /// One-way delay applied to every forwarded packet.
    #[arg(long, default_value = "0")]
    delay_ms: u64,
    /// How long to keep the forwarder alive before emitting stats.
    #[arg(long, default_value = "30")]
    duration_secs: u64,
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
    /// Distinct user_ids the soak rotates across (round-robin
    /// assignment). 1 = single-tenant (default). N = N tenants
    /// share the server, each gets `clients/N` of the load.
    /// Used to validate per-user bandwidth accounting under real
    /// concurrent handshakes — operators set this in scale
    /// validation runs to mirror their actual tenant count.
    #[arg(long, default_value = "1")]
    users: usize,
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
    /// `PerfProfile.packet_threshold`. 3 is the RFC 9002 default.
    /// Raise only for a measured reordered path because higher
    /// values delay recovery from genuine packet loss.
    #[arg(long, default_value = "3")]
    packet_threshold: u32,
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
    /// QUIC congestion controller under test. `bbr` is the
    /// production-safe default; `brutal` pins a target send rate and
    /// deliberately does not reduce its window on ordinary loss.
    #[arg(long, value_enum, default_value = "bbr")]
    congestion: BenchCongestion,
    /// Brutal target rate in Mbit/s. Ignored for BBR. Set this to the
    /// measured path capacity; an unrealistically high value can
    /// overwhelm a shared bottleneck and is not TCP-friendly.
    #[arg(long, default_value = "100")]
    brutal_target_mbps: u64,
}

#[derive(clap::Args, Debug)]
struct AlphaArgs {
    /// Payload size in MiB. Same semantics as `beta`.
    #[arg(long, default_value = "16")]
    payload_mib: u64,
    /// Per-`send_record` chunk size in KiB.
    #[arg(long, default_value = "64")]
    chunk_kib: u64,
    /// Number of runs to repeat back-to-back.
    #[arg(long, default_value = "1")]
    runs: u32,
    /// Connect timeout in seconds.
    #[arg(long, default_value = "30")]
    connect_timeout_secs: u64,
    /// Total per-run timeout in seconds.
    #[arg(long, default_value = "120")]
    total_timeout_secs: u64,
    /// Run the TLS-wrapped variant (production shape). Default is
    /// raw-TCP which mirrors the in-tree throughput_smoke test —
    /// useful for regression hunting. Operators wanting an
    /// honest "vs REALITY" speed number pass `--tls`.
    #[arg(long, default_value = "false")]
    tls: bool,
}

#[derive(clap::Args, Debug)]
struct AlphaServerTlsArgs {
    /// Address to bind the TCP listener on.
    #[arg(long, default_value = "127.0.0.1:0")]
    bind: String,
    /// Extra SAN to bake into the self-signed cert beyond
    /// `localhost`. Set to the hostname/IP the client will dial
    /// or TLS handshake fails with `NotValidForName`.
    #[arg(long)]
    extra_san: Option<String>,
}

#[derive(clap::Args, Debug)]
struct AlphaClientTlsArgs {
    /// Peer's `host:port`. Same as the server's banner.
    #[arg(long)]
    server_addr: String,
    /// SNI string the TLS handshake presents.
    #[arg(long, default_value = "localhost")]
    server_name: String,
    /// Server's leaf cert DER as hex.
    #[arg(long)]
    server_leaf_cert_hex: String,
    /// Server's ML-KEM-768 EK as hex.
    #[arg(long)]
    server_mlkem_pk_hex: String,
    /// Server's X25519 public key as hex.
    #[arg(long)]
    server_x25519_pub_hex: String,
    /// Server's PQ fingerprint as hex.
    #[arg(long)]
    server_pq_fingerprint_hex: String,
    /// Payload size in MiB.
    #[arg(long, default_value = "16")]
    payload_mib: u64,
    /// Per-`send_record` chunk size in KiB.
    #[arg(long, default_value = "64")]
    chunk_kib: u64,
    /// Connect timeout in seconds.
    #[arg(long, default_value = "30")]
    connect_timeout_secs: u64,
    /// Total per-run timeout in seconds.
    #[arg(long, default_value = "120")]
    total_timeout_secs: u64,
    /// Number of runs to repeat back-to-back.
    #[arg(long, default_value = "1")]
    runs: u32,
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
    /// QUIC congestion controller used for server-to-client echo
    /// traffic. Must match the client-side experiment setting.
    #[arg(long, value_enum, default_value = "bbr")]
    congestion: BenchCongestion,
    /// Brutal target rate in Mbit/s. Ignored for BBR.
    #[arg(long, default_value = "100")]
    brutal_target_mbps: u64,
    /// Server-side `PerfProfile.packet_threshold`. Use the same value
    /// on both peers when running a bidirectional reordering study.
    #[arg(long, default_value = "3")]
    packet_threshold: u32,
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
    /// `PerfProfile.packet_threshold`. 3 is the production default.
    #[arg(long, default_value = "3")]
    packet_threshold: u32,
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
    /// QUIC congestion controller used for client-to-server traffic.
    /// For a symmetric round-trip experiment, pass the same value to
    /// `beta-server`.
    #[arg(long, value_enum, default_value = "bbr")]
    congestion: BenchCongestion,
    /// Brutal target rate in Mbit/s. Ignored for BBR.
    #[arg(long, default_value = "100")]
    brutal_target_mbps: u64,
    /// Number of runs to repeat back-to-back. Each opens a fresh
    /// connection (cold-start cost included).
    #[arg(long, default_value = "1")]
    runs: u32,
}

/// Iter-126: shared validator for `--*-secs` / `--runs` /
/// `--payload-mib` style numeric arguments that must be positive.
/// Pre-iter-126 the bench accepted `--connect-timeout-secs 0` /
/// `--total-timeout-secs 0` and ran through to produce
/// `Error: Connect("handshake timed out after 0ns")` —
/// useless deadline-exceeded output that hides the operator
/// error. Symmetric fix with iter-108/109/110/111/117 on the
/// other binaries: reject zero-valued positive-required args
/// at parse time with exit 2 + a clean stderr message.
///
/// `f64` variant for `--min-success-rate` style fractions (0.0,
/// 1.0] is intentionally NOT covered here — soak's `0.0` means
/// "any success rate passes" and is occasionally useful for
/// regression-baseline runs that just want to fail on spawn-leak.
fn reject_zero_u64(name: &str, value: u64, hint: &str) -> Result<(), String> {
    if value == 0 {
        return Err(format!(
            "{name} = 0 is not a useful bench value — {hint}. \
             Re-run with a positive value (or omit the flag to use the default)."
        ));
    }
    Ok(())
}

fn reject_zero_u32(name: &str, value: u32, hint: &str) -> Result<(), String> {
    if value == 0 {
        return Err(format!(
            "{name} = 0 is not a useful bench value — {hint}. \
             Re-run with a positive value (or omit the flag to use the default)."
        ));
    }
    Ok(())
}

fn reject_zero_usize(name: &str, value: usize, hint: &str) -> Result<(), String> {
    if value == 0 {
        return Err(format!(
            "{name} = 0 is not a useful bench value — {hint}. \
             Re-run with a positive value (or omit the flag to use the default)."
        ));
    }
    Ok(())
}

fn reject_packet_threshold(value: u32) -> Result<(), String> {
    if value < 3 {
        return Err(format!(
            "--packet-threshold = {value} is below RFC 9002's packet \
             reordering threshold of 3. Use 3 for ordinary paths; raise \
             it only when a measured path reorders packets."
        ));
    }
    Ok(())
}

/// Iter-127: MTU values must be in the QUIC-realistic range
/// [576, 9000]. 576 is the IPv4 minimum any link must support;
/// 9000 is jumbo-frame ceiling. quinn-proto silently clamps
/// invalid values to its internal floor (1200 IIRC) so a typo
/// like `--initial-mtu 12` produces a perfectly normal-looking
/// JSON report with `mtu_init=12` echoed back — the operator
/// never learns the bench actually ran at 1200.
fn reject_out_of_range_mtu(name: &str, value: u16) -> Result<(), String> {
    const QUIC_MIN: u16 = 1200; // RFC 9000 §14 hard floor
    const PRACTICAL_MAX: u16 = 9000; // jumbo-frame ceiling
    if !(QUIC_MIN..=PRACTICAL_MAX).contains(&value) {
        return Err(format!(
            "{name} = {value} is outside the QUIC-realistic range \
             [{QUIC_MIN}, {PRACTICAL_MAX}] (RFC 9000 §14 floor + \
             jumbo-frame ceiling). quinn-proto silently clamps invalid \
             values to its internal default, so the bench would emit \
             a JSON report echoing the bad number while running at a \
             different MTU — useless. Pick a real path MTU."
        ));
    }
    Ok(())
}

/// Iter-127: synthetic loss percentage gated to [0, 100]. The
/// netem forwarder is documented to take 0 for passthrough (no
/// forwarder spawned at all) so 0 IS valid; the trap is on the
/// upper end — `--loss-pct 150.0` is accepted, then the bench
/// silently runs with 100% loss and dies with the misleading
/// "handshake timed out" message 5s later. Make the operator
/// error visible at parse time.
fn reject_invalid_loss_pct(value: f64) -> Result<(), String> {
    if !value.is_finite() || !(0.0..=100.0).contains(&value) {
        return Err(format!(
            "--loss-pct = {value} is outside [0, 100] (percentage). \
             Above 100 means 'lose more packets than exist', which is \
             mathematically meaningless — the bench would silently drop \
             every packet and report 'handshake timed out' 5s later \
             with no hint that the operator picked a bad number."
        ));
    }
    Ok(())
}

/// Iter-128: `--min-success-rate` is a fraction in [0.0, 1.0].
/// `--min-success-rate 2.5` makes EVERY soak fail (no real success
/// rate can exceed 1.0), and a CI script that fat-fingers `0.99`
/// as `2.99` would have every commit fail with a misleading
/// "regression" error — the soak ran fine but the gate is
/// impossible. The PASS-with-NaN trap is even worse: NaN
/// comparisons return false, so `passed(NaN)` always fails
/// silently regardless of the real success rate. Iter-128
/// rejects {non-finite, < 0.0, > 1.0} at parse time.
///
/// NB: 0.0 IS valid — explicit operator intent of "I want to
/// fail only on spawn_leak or zero-dials, not on success rate".
/// soak.rs's `passed()` already handles 0.0 correctly.
fn reject_invalid_success_rate(value: f64) -> Result<(), String> {
    if !value.is_finite() || !(0.0..=1.0).contains(&value) {
        return Err(format!(
            "--min-success-rate = {value} is outside [0.0, 1.0] (fraction, \
             NOT a percentage). 0.99 = 'at least 99% of dials succeed'; \
             0.0 = 'don't gate on success rate at all'. Values above 1.0 \
             make every soak fail (no real success rate can exceed 1.0); \
             NaN makes every soak silently fail (NaN comparisons return \
             false). A CI script that fat-fingers `0.99` as `2.99` would \
             have every commit produce a misleading 'regression' error."
        ));
    }
    Ok(())
}

fn validate_soak_args(a: &SoakArgs) -> Result<(), String> {
    reject_zero_usize(
        "--clients",
        a.clients,
        "0 concurrent clients = nothing to soak, summary would be a no-op",
    )?;
    reject_zero_u64(
        "--duration-secs",
        a.duration_secs,
        "0-second soak terminates before any dial completes — \
         the summary would always be empty",
    )?;
    reject_zero_u64(
        "--per-session-kib",
        a.per_session_kib,
        "0 KiB payload skips the bandwidth path entirely; \
         this isn't a bench, it's a handshake-only smoke",
    )?;
    reject_zero_u64(
        "--report-interval-secs",
        a.report_interval_secs,
        "0-second reporter would spin the CPU emitting JSON \
         lines as fast as it could",
    )?;
    reject_zero_usize(
        "--users",
        a.users,
        "0 users = no user_id to assign sessions to, soak \
         would panic on the first round-robin",
    )?;
    if let Some(mcd) = a.max_concurrent_dials {
        reject_zero_usize(
            "--max-concurrent-dials",
            mcd,
            "0 dial concurrency = no dials can fire, summary \
             would always read 0 dials attempted",
        )?;
    }
    // Iter-128: success-rate gate.
    reject_invalid_success_rate(a.min_success_rate)?;
    Ok(())
}

fn validate_beta_args(a: &BetaArgs) -> Result<(), String> {
    reject_zero_u64(
        "--payload-mib",
        a.payload_mib,
        "0 MiB payload measures nothing — bench would emit \
         a degenerate report",
    )?;
    reject_zero_u64(
        "--chunk-kib",
        a.chunk_kib,
        "0 KiB chunk size = infinite send loop OR div-by-zero \
         in the per-record accounting",
    )?;
    reject_zero_u32(
        "--runs",
        a.runs,
        "0 runs = bench main loop iterates zero times, no \
         output emitted",
    )?;
    reject_zero_u64(
        "--connect-timeout-secs",
        a.connect_timeout_secs,
        "0-second handshake deadline = instant timeout, every \
         run fails with 'handshake timed out after 0ns'",
    )?;
    reject_zero_u64(
        "--total-timeout-secs",
        a.total_timeout_secs,
        "0-second total deadline = run aborts before any data \
         can flow",
    )?;
    // Iter-127: MTU + loss-pct gates.
    reject_out_of_range_mtu("--initial-mtu", a.initial_mtu)?;
    reject_out_of_range_mtu("--mtu-upper-bound", a.mtu_upper_bound)?;
    if a.mtu_upper_bound < a.initial_mtu {
        return Err(format!(
            "--mtu-upper-bound ({}) < --initial-mtu ({}). The ceiling \
             must be ≥ the floor or quinn-proto can't probe upward at \
             all; the bench would silently run at --initial-mtu and \
             the upper-bound knob would be a no-op.",
            a.mtu_upper_bound, a.initial_mtu
        ));
    }
    reject_invalid_loss_pct(a.loss_pct)?;
    reject_packet_threshold(a.packet_threshold)?;
    reject_zero_u64(
        "--brutal-target-mbps",
        a.brutal_target_mbps,
        "Brutal needs a positive pacing target",
    )?;
    Ok(())
}

fn validate_beta_client_args(a: &BetaClientArgs) -> Result<(), String> {
    reject_zero_u64(
        "--payload-mib",
        a.payload_mib,
        "0 MiB payload measures nothing",
    )?;
    reject_zero_u64(
        "--chunk-kib",
        a.chunk_kib,
        "0 KiB chunk size = infinite send loop OR div-by-zero",
    )?;
    reject_zero_u32(
        "--runs",
        a.runs,
        "0 runs = bench main loop iterates zero times",
    )?;
    reject_zero_u64(
        "--connect-timeout-secs",
        a.connect_timeout_secs,
        "0-second handshake deadline = instant timeout",
    )?;
    reject_zero_u64(
        "--total-timeout-secs",
        a.total_timeout_secs,
        "0-second total deadline = run aborts before any data can flow",
    )?;
    // Iter-127: MTU gates (no loss-pct knob on beta-client; the
    // cross-host bench can't synthesise loss in-process).
    reject_out_of_range_mtu("--initial-mtu", a.initial_mtu)?;
    reject_out_of_range_mtu("--mtu-upper-bound", a.mtu_upper_bound)?;
    if a.mtu_upper_bound < a.initial_mtu {
        return Err(format!(
            "--mtu-upper-bound ({}) < --initial-mtu ({}). The ceiling \
             must be ≥ the floor or quinn-proto can't probe upward.",
            a.mtu_upper_bound, a.initial_mtu
        ));
    }
    reject_packet_threshold(a.packet_threshold)?;
    reject_zero_u64(
        "--brutal-target-mbps",
        a.brutal_target_mbps,
        "Brutal needs a positive pacing target",
    )?;
    Ok(())
}

fn validate_beta_server_args(a: &BetaServerArgs) -> Result<(), String> {
    reject_zero_u64(
        "--brutal-target-mbps",
        a.brutal_target_mbps,
        "Brutal needs a positive pacing target",
    )?;
    reject_packet_threshold(a.packet_threshold)
}

fn validate_udp_forwarder_args(a: &UdpForwarderArgs) -> Result<(), String> {
    let _: std::net::SocketAddr = a
        .bind
        .parse()
        .map_err(|e| format!("--bind must be an IP socket address: {e}"))?;
    let _: std::net::SocketAddr = a
        .target
        .parse()
        .map_err(|e| format!("--target must be an IP socket address: {e}"))?;
    reject_invalid_loss_pct(a.loss_pct)?;
    reject_zero_u64(
        "--duration-secs",
        a.duration_secs,
        "the forwarder would exit before a competitor can connect",
    )
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
    // Iter-126: gate zero-valued numeric args BEFORE we run any
    // bench setup. Exit 2 = clap-style usage error so the operator
    // immediately recognises "I passed a bad flag" rather than
    // "the bench failed to run for some mysterious reason".
    let validate_result = match &cli.cmd {
        Cmd::Soak(args) => validate_soak_args(args),
        Cmd::Beta(args) => validate_beta_args(args),
        Cmd::BetaServer(args) => validate_beta_server_args(args),
        Cmd::BetaClient(args) => validate_beta_client_args(args),
        Cmd::Alpha(args) => validate_alpha_args(args),
        Cmd::AlphaServerTls(_) => Ok(()),
        Cmd::AlphaClientTls(args) => validate_alpha_client_tls_args(args),
        Cmd::UdpForwarder(args) => validate_udp_forwarder_args(args),
        Cmd::TcpEchoServer(_) => Ok(()),
        Cmd::Socks5Roundtrip(args) => {
            if args.payload_mib == 0
                || args.chunk_kib == 0
                || args.timeout_secs == 0
                || args.runs == 0
            {
                Err("SOCKS5 round-trip sizes, timeout, and runs must be non-zero".into())
            } else {
                Ok(())
            }
        }
    };
    if let Err(msg) = validate_result {
        eprintln!("error: {msg}");
        std::process::exit(2);
    }
    match cli.cmd {
        Cmd::Soak(args) => run_soak_cmd(args).await?,
        Cmd::Beta(args) => run_beta(args).await?,
        Cmd::BetaServer(args) => run_beta_server(args).await?,
        Cmd::BetaClient(args) => run_beta_client(args).await?,
        Cmd::Alpha(args) => run_alpha(args).await?,
        Cmd::AlphaServerTls(args) => run_alpha_server_tls(args).await?,
        Cmd::AlphaClientTls(args) => run_alpha_client_tls(args).await?,
        Cmd::UdpForwarder(args) => run_udp_forwarder(args).await?,
        Cmd::TcpEchoServer(args) => run_tcp_echo_server(args).await?,
        Cmd::Socks5Roundtrip(args) => run_socks5_roundtrip(args).await?,
    }
    Ok(())
}

async fn run_tcp_echo_server(args: TcpEchoServerArgs) -> Result<(), Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind(&args.bind).await?;
    println!("TCP_ECHO_LISTEN_ADDR={}", listener.local_addr()?);
    proteus_bench::external::serve_tcp_echo(listener).await?;
    Ok(())
}

async fn run_socks5_roundtrip(args: Socks5RoundtripArgs) -> Result<(), Box<dyn std::error::Error>> {
    let socks_addr: std::net::SocketAddr = args.socks_addr.parse()?;
    let target_addr: std::net::SocketAddr = args.target_addr.parse()?;
    let payload_bytes = usize::try_from(args.payload_mib)?
        .checked_mul(1024 * 1024)
        .ok_or("payload size overflow")?;
    let chunk_bytes = usize::try_from(args.chunk_kib)?
        .checked_mul(1024)
        .ok_or("chunk size overflow")?;
    let timeout = Duration::from_secs(args.timeout_secs);
    for _ in 0..args.runs {
        let report = proteus_bench::external::run_socks5_roundtrip(
            socks_addr,
            target_addr,
            payload_bytes,
            chunk_bytes,
            timeout,
        )
        .await?;
        print!("{}", report.to_json());
    }
    Ok(())
}

async fn run_udp_forwarder(args: UdpForwarderArgs) -> Result<(), Box<dyn std::error::Error>> {
    let bind: std::net::SocketAddr = args.bind.parse()?;
    let target: std::net::SocketAddr = args.target.parse()?;
    let cfg = proteus_bench::netem::NetemConfig {
        loss_pct: args.loss_pct,
        delay: Duration::from_millis(args.delay_ms),
        seed: None,
    };
    let handle = proteus_bench::netem::spawn_forwarder_on(bind, target, cfg).await?;
    println!("FORWARDER_LISTEN_ADDR={}", handle.listen_addr);
    tokio::time::sleep(Duration::from_secs(args.duration_secs)).await;
    let c2s = handle.c2s_stats.snapshot().await;
    let s2c = handle.s2c_stats.snapshot().await;
    println!(
        "{{\"kind\":\"udp_forwarder\",\"listen_addr\":\"{}\",\"target_addr\":\"{}\",\
         \"loss_pct\":{},\"delay_ms\":{},\"duration_secs\":{},\
         \"c2s_packets_received\":{},\"c2s_packets_dropped\":{},\
         \"s2c_packets_received\":{},\"s2c_packets_dropped\":{}}}",
        handle.listen_addr,
        target,
        args.loss_pct,
        args.delay_ms,
        args.duration_secs,
        c2s.packets_received,
        c2s.packets_dropped,
        s2c.packets_received,
        s2c.packets_dropped,
    );
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
        users: args.users,
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
        minimum_mtu: 1200,
        pad_quic_datagrams_to_mtu: args.pad_mtu,
        allow_spin_bit: args.allow_spin_bit,
        ack_eliciting_threshold: args.ack_eliciting_threshold,
        packet_threshold: args.packet_threshold,
        mtu_upper_bound: args.mtu_upper_bound,
        stream_receive_window_override: args.stream_window_mib.map(|m| m * 1024 * 1024),
        connection_receive_window_override: args.connection_window_mib.map(|m| m * 1024 * 1024),
        send_window_override: None,
        congestion: args.congestion.into(),
        brutal_target_bps: args.brutal_target_mbps.saturating_mul(1_000_000),
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
    let perf = PerfProfile {
        congestion: args.congestion.into(),
        brutal_target_bps: args.brutal_target_mbps.saturating_mul(1_000_000),
        packet_threshold: args.packet_threshold,
        ..PerfProfile::default()
    };
    let (local, identity, server_fut) = beta::spawn_echo_server(bind, cert, perf).await?;
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
        minimum_mtu: 1200,
        pad_quic_datagrams_to_mtu: args.pad_mtu,
        allow_spin_bit: args.allow_spin_bit,
        ack_eliciting_threshold: args.ack_eliciting_threshold,
        packet_threshold: args.packet_threshold,
        mtu_upper_bound: args.mtu_upper_bound,
        stream_receive_window_override: args.stream_window_mib.map(|m| m * 1024 * 1024),
        connection_receive_window_override: args.connection_window_mib.map(|m| m * 1024 * 1024),
        send_window_override: None,
        congestion: args.congestion.into(),
        brutal_target_bps: args.brutal_target_mbps.saturating_mul(1_000_000),
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

fn validate_alpha_args(a: &AlphaArgs) -> Result<(), String> {
    reject_zero_u64(
        "--payload-mib",
        a.payload_mib,
        "0 MiB payload measures nothing",
    )?;
    reject_zero_u64(
        "--chunk-kib",
        a.chunk_kib,
        "0 KiB chunk size = infinite send loop OR div-by-zero",
    )?;
    reject_zero_u32(
        "--runs",
        a.runs,
        "0 runs = bench main loop iterates zero times",
    )?;
    reject_zero_u64(
        "--connect-timeout-secs",
        a.connect_timeout_secs,
        "0-second handshake deadline = instant timeout",
    )?;
    reject_zero_u64(
        "--total-timeout-secs",
        a.total_timeout_secs,
        "0-second total deadline = run aborts before any data can flow",
    )?;
    Ok(())
}

fn validate_alpha_client_tls_args(a: &AlphaClientTlsArgs) -> Result<(), String> {
    reject_zero_u64(
        "--payload-mib",
        a.payload_mib,
        "0 MiB payload measures nothing",
    )?;
    reject_zero_u64(
        "--chunk-kib",
        a.chunk_kib,
        "0 KiB chunk size = infinite send loop OR div-by-zero",
    )?;
    reject_zero_u32(
        "--runs",
        a.runs,
        "0 runs = bench main loop iterates zero times",
    )?;
    reject_zero_u64(
        "--connect-timeout-secs",
        a.connect_timeout_secs,
        "0-second handshake deadline = instant timeout",
    )?;
    reject_zero_u64(
        "--total-timeout-secs",
        a.total_timeout_secs,
        "0-second total deadline = run aborts before any data can flow",
    )?;
    Ok(())
}

async fn run_alpha(args: AlphaArgs) -> Result<(), Box<dyn std::error::Error>> {
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
            tls = args.tls,
            "α bench run starting"
        );
        let report = if args.tls {
            alpha::run_same_host_tls_bench(
                payload_bytes,
                chunk_bytes,
                connect_timeout,
                total_timeout,
            )
            .await?
        } else {
            alpha::run_same_host_raw_tcp_bench(
                payload_bytes,
                chunk_bytes,
                connect_timeout,
                total_timeout,
            )
            .await?
        };
        print!("{}", report.to_json());
        info!(
            mib_per_sec = report.mib_per_sec,
            gbps = report.gbps,
            elapsed_secs = report.elapsed_secs,
            "α bench run completed"
        );
    }
    Ok(())
}

async fn run_alpha_server_tls(args: AlphaServerTlsArgs) -> Result<(), Box<dyn std::error::Error>> {
    let cert = beta::mint_self_signed(args.extra_san.as_deref())?;
    let bind: std::net::SocketAddr = args.bind.parse()?;
    let (local, identity, leaf_hex, serve_fut) =
        alpha::spawn_alpha_tls_echo_server(bind, cert).await?;
    info!(addr = %local, "bench α-TLS server bound");
    // Mirror β's banner shape exactly so a single operator workflow
    // works for both profiles.
    print!("{}", identity.banner(local, &leaf_hex));
    serve_fut.await?;
    Ok(())
}

async fn run_alpha_client_tls(args: AlphaClientTlsArgs) -> Result<(), Box<dyn std::error::Error>> {
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

    let payload_bytes = (args.payload_mib as usize) * 1024 * 1024;
    let chunk_bytes = (args.chunk_kib as usize) * 1024;
    let connect_timeout = Duration::from_secs(args.connect_timeout_secs);
    let total_timeout = Duration::from_secs(args.total_timeout_secs);

    for run_ix in 0..args.runs {
        info!(
            run = run_ix + 1,
            of = args.runs,
            server_addr = %server_addr,
            "cross-host α-TLS bench run starting"
        );
        let report = alpha::run_cross_host_tls_bench(
            &args.server_name,
            server_addr,
            pinned_leaf.clone(),
            mlkem_pk.clone(),
            x25519_pub,
            pq_fingerprint,
            payload_bytes,
            chunk_bytes,
            connect_timeout,
            total_timeout,
        )
        .await?;
        print!("{}", report.to_json());
        info!(
            mib_per_sec = report.mib_per_sec,
            gbps = report.gbps,
            elapsed_secs = report.elapsed_secs,
            "cross-host α-TLS bench run completed"
        );
    }
    Ok(())
}
