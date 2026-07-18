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
// knock_keygen is now exposed via the lib (iter-54: validate
// uses the same load() helper to surface PSK parse errors at
// preflight time instead of fatal-at-startup).
use proteus_server::knock_keygen;

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
        /// Iter-130: refuse to overwrite existing key files by
        /// default. Pass `--force` to deliberately rotate (the
        /// old keys are LOST — make sure you have a backup or
        /// don't care about losing existing connections). Default
        /// false keeps the operator from accidentally clobbering
        /// production keys by re-running the bootstrap command.
        #[arg(long, default_value = "false")]
        force: bool,
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
        /// Iter-130: refuse to overwrite existing cert files by
        /// default. Pass `--force` to deliberately re-mint.
        #[arg(long, default_value = "false")]
        force: bool,
    },
    /// Mint a fresh 32-byte server-knock PSK and write it to
    /// `--out` with mode 0600. Operator distributes the SAME bytes
    /// to every Proteus client via the existing out-of-band
    /// channel; the client sends an HMAC-bound knock with each
    /// connection so the server can distinguish "real Proteus
    /// client" from "GFW active prober" BEFORE TLS even
    /// terminates locally (Path A → REALITY-grade probe
    /// resistance, builds on `proteus_handshake::knock`).
    ///
    /// Rotation: independent from the identity-key lifecycle
    /// (`keygen`) — rotate frequently after a client device is
    /// lost, infrequently when the distribution channel is
    /// expensive.
    ///
    /// File format: two comment lines + one base64-encoded line
    /// containing the 32 bytes. Hand-editable for emergency
    /// rotations; the loader rejects multi-data-line files so
    /// half-edits surface clearly.
    KnockKeygen {
        /// Output file path (NOT a directory — the knock PSK is
        /// a single key, not a bundle).
        #[arg(long, default_value = "/etc/proteus/keys/server.knock_psk")]
        out: PathBuf,
        /// Iter-130: refuse to overwrite an existing PSK file by
        /// default. Pre-iter-130 knock-keygen silently clobbered
        /// whatever was at the target path — any file, with mode
        /// 0600 lockdown afterwards. An operator who fat-fingered
        /// the path (`--out /etc/passwd`) would have a real
        /// disaster on their hands. Pass `--force` to deliberately
        /// rotate (every client must re-receive the new PSK or
        /// they STOP CONNECTING — make sure your distribution
        /// channel is ready).
        #[arg(long, default_value = "false")]
        force: bool,
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
    /// Offline IP-reputation preflight. Classifies the deployment IP
    /// against a curated cloud-prefix table + special-use ranges +
    /// optional operator watchlist, and prints an actionable report.
    /// Designed for the 2026 GFW threat model where Tiangou-class
    /// commercial DPI shares a cross-deployment IP blocklist; running
    /// this BEFORE deploying a fresh VPS catches the most common
    /// "I picked an already-burned IP" mistakes offline (no external
    /// network probes — see crates/proteus-server/src/ip_reputation.rs
    /// for the metadata-leakage rationale).
    ///
    /// Exit code 0 on PASS / WARN only; 1 on any FAIL.
    Preflight {
        #[command(subcommand)]
        cmd: PreflightCmd,
    },
    /// Capture the binary's TLS ClientHello fingerprint (JA4) and
    /// diff it against the curated browser reference table
    /// (Chrome / Firefox / Safari / Edge).
    ///
    /// Offline command — runs a one-shot loopback handshake, no
    /// network access, no running server required. Operators use
    /// this AT DEPLOY TIME to verify the wire fingerprint matches
    /// expectations BEFORE traffic touches a real censor's DPI.
    ///
    /// Output format: human-readable text by default; pass
    /// `--format json` for JSON Lines suitable for scripted
    /// deploy gates / CI alerts. Exit 0 on baseline-match, 1 on
    /// any drift (operator decides whether the drift is wanted).
    Fingerprint {
        /// Output format: `text` (default) or `json`.
        #[arg(long, default_value = "text")]
        format: String,
        /// When set to a target browser label, append a
        /// COMPONENT-LEVEL diff vs that browser's ClientHello
        /// (cipher / extension / sig_algs / ALPN /
        /// supported_versions lists with per-item
        /// add/remove/reorder bullets). The JA4 hash alone tells
        /// you "they differ"; the component diff tells you
        /// "remove cipher 0xc0a8, add extension 0x4469 at
        /// position 16, swap sig_alg positions 2↔3". When uTLS-
        /// replay ships and the diff hits zero, the whole tool
        /// becomes the gate.
        ///
        /// Supported targets (iter-17):
        ///   * `chrome-124`  — Chrome/Edge 124 (Chromium 124).
        ///     Dominant desktop browser fingerprint.
        ///   * `firefox-124` — Firefox 124. EU markets where
        ///     Firefox share is ~10%.
        ///   * `safari-17.4` — Safari 17.4 on macOS 14. Apple-
        ///     ecosystem deployments (Mac/iOS traffic mix).
        ///
        /// Empty string (default) skips the diff section.
        /// Other browsers (Edge mobile, Chrome Android, Safari
        /// iOS) tend to converge to one of these three on the
        /// JA4-relevant axes.
        #[arg(long, default_value = "")]
        target: String,
    },
}

#[derive(Subcommand, Debug)]
enum PreflightCmd {
    /// Classify the deployment's public IP against our offline
    /// reputation table.
    ///
    /// IP source priority: `--public-ip` literal > `--config`
    /// listen_alpha literal bind > FAIL with guidance.
    CheckIpReputation {
        /// Path to YAML config; the listen address is inspected for a
        /// literal public-IP bind. Optional when `--public-ip` is set.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Operator override: classify THIS IP directly, regardless
        /// of config. Use this for pre-provisioning checks (you know
        /// the VPS IP from the cloud console, but haven't written
        /// `server.yaml` yet).
        #[arg(long)]
        public_ip: Option<std::net::IpAddr>,
        /// Optional path to a text-format operator watchlist of
        /// known-burned CIDRs. Each non-comment line is `CIDR
        /// reason text`. Lines starting with `#` are skipped.
        #[arg(long)]
        watchlist: Option<PathBuf>,
    },
    /// Audit the deployment **host's runtime posture** — key file
    /// modes, ulimits, sysctl values that govern β QUIC throughput,
    /// /dev/urandom availability, NTP sync, disk free. Every check
    /// is read-only (no writes, no chmod, no probes).
    ///
    /// Catches the silent-degradation classes that bite operators
    /// AFTER a green `validate` run: world-readable PQ keys,
    /// distro-default ulimit 1024 (accept loop EMFILEs at a few
    /// thousand sessions), Ubuntu's 212992-byte SO_RCVBUF cap that
    /// silently clamps β QUIC's BBR window, broken NTP causing
    /// every handshake to look like a replay, etc.
    ///
    /// Exit code 0 on PASS+WARN-only; 1 on any FAIL. Wire into
    /// CI / Ansible / Terraform deploy gates the same way as
    /// `check-ip-reputation` and `fingerprint`.
    CheckHost {
        /// Path to YAML config — the audit reads it to locate key
        /// files for permission checks (relative paths resolve
        /// against the config's directory). Optional: when absent,
        /// only host-level checks (ulimit, sysctls, urandom, NTP,
        /// disk free) run; the key-file mode check is skipped.
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Run **every** offline preflight (`check-ip-reputation` +
    /// `check-host` + a fingerprint capture) in a single shot.
    /// One exit code, one unified report. Designed for the
    /// Ansible/Terraform deploy-gate use case: replace three
    /// chained `&&`-wired subcommands with one call.
    ///
    /// Output:
    ///   - `--format text` (default): per-section banners + the
    ///     same per-finding lines each sub-check emits, plus a
    ///     bottom-line `summary: Np, Nw, Nf  (exit N)` totals row.
    ///   - `--format json`: one-line JSON document
    ///     `{"kind":"preflight_summary", "sections":{...},
    ///     "totals":{...}, "exit_code":N}`. Schema is append-only.
    ///
    /// Exit code:
    ///   - `0` when every sub-check is PASS+WARN-only.
    ///   - `1` when any sub-check reports FAIL.
    ///
    /// Fingerprint drift is treated as WARN (not FAIL) — operators
    /// may have intentionally landed uTLS-replay; the
    /// `EXPECTED_BASELINE` constant in `tls_fingerprint_observer.rs`
    /// is the single source of truth they update when promoting.
    All {
        /// Shared YAML config (used by both ip_reputation and
        /// host_posture sub-checks).
        #[arg(long)]
        config: Option<PathBuf>,
        /// Operator-supplied public IP — wins over config-derived
        /// listen IP for the ip_reputation sub-check.
        #[arg(long)]
        public_ip: Option<std::net::IpAddr>,
        /// Optional operator watchlist of known-burned CIDRs for
        /// the ip_reputation sub-check.
        #[arg(long)]
        watchlist: Option<PathBuf>,
        /// Skip the fingerprint sub-check. Use when CI has already
        /// run `proteus-server fingerprint` separately and you
        /// don't want the extra ~50–100 ms loopback handshake.
        #[arg(long, default_value_t = false)]
        skip_fingerprint: bool,
        /// Output format: `text` (default, human-friendly) or
        /// `json` (single-document JSON for scripted gates).
        #[arg(long, default_value = "text")]
        format: String,
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
    /// Evaluate the bundled Prometheus alert rules
    /// (`deploy/prometheus/proteus-alerts.yaml`) against a one-shot
    /// `/metrics` scrape and print per-rule verdict.
    ///
    /// Designed for the "did my fresh deploy come up clean?" /
    /// "which documented alert is ACTIVELY firing right now?" /
    /// "CI smoke-gate the new binary" use cases — without
    /// standing up a full Prometheus + Alertmanager stack. The
    /// point-in-time evaluation can't replicate Prometheus's
    /// `rate(...[5m])` queries; rate-based alerts here are
    /// approximated by "is the counter currently non-zero".
    /// For full evaluation, wire the YAML into the operator's
    /// own Prometheus.
    ///
    /// Exit code: 0 on PASS+WARN-only, 1 on any CRIT.
    AlertsCheck {
        /// URL of the metrics endpoint.
        #[arg(long, default_value = "http://127.0.0.1:9090/metrics")]
        url: String,
        /// Optional bearer-token file (or PROTEUS_METRICS_TOKEN).
        #[arg(long)]
        token_file: Option<PathBuf>,
        /// Per-step network timeout in seconds. Default 5 s.
        #[arg(long, default_value_t = 5)]
        timeout_secs: u64,
        /// Output format: `text` (default, human-friendly) or
        /// `json` (one-line JSON for jq / scripted deploy gates).
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
    // counter is published via `process_panic_counter::set` so the
    // metrics endpoint can read it without threading the Arc through
    // every constructor. Honours RUST_PANIC_ABORT=1 when operators
    // prefer systemd-restart-on-panic semantics over keep-running-
    // with-one-session-down (default).
    let panic_counter = proteus_panic_hook::install();
    proteus_server::process_panic_counter::set(panic_counter);

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Keygen { out, force } => keygen::run_with_force(&out, force)?,
        Cmd::Gencert {
            dns_name,
            out,
            force,
        } => {
            // Iter-129: gate --dns-name at parse time + exit 2 on
            // operator error (not exit 1 = "the tool itself
            // failed"). exit 2 matches the clap-style "usage
            // error" convention every other binary surface uses
            // (iter-108 / 109 / 110 / 117 / 126 / 127 / 128).
            if let Err(msg) = gencert::validate_dns_name(&dns_name) {
                eprintln!("error: {msg}");
                std::process::exit(2);
            }
            gencert::run_with_force(&dns_name, &out, force)?;
        }
        Cmd::KnockKeygen { out, force } => {
            knock_keygen::run_with_force(&out, force)?;
        }
        Cmd::Run { config } => run(&config).await?,
        Cmd::Validate { config } => {
            let ok = proteus_server::validate::run(&config).await?;
            if !ok {
                std::process::exit(1);
            }
        }
        Cmd::Preflight { cmd } => match cmd {
            PreflightCmd::CheckIpReputation {
                config,
                public_ip,
                watchlist,
            } => {
                let input = proteus_server::preflight::PreflightInput {
                    config_path: config,
                    public_ip_override: public_ip,
                    watchlist_path: watchlist,
                };
                let code = proteus_server::preflight::cli_run(input)?;
                if code != 0 {
                    std::process::exit(code);
                }
            }
            PreflightCmd::CheckHost { config } => {
                let input = proteus_server::host_preflight::HostPreflightInput {
                    config_path: config,
                    ..Default::default()
                };
                let code = proteus_server::host_preflight::cli_run(input)?;
                if code != 0 {
                    std::process::exit(code);
                }
            }
            PreflightCmd::All {
                config,
                public_ip,
                watchlist,
                skip_fingerprint,
                format,
            } => {
                let input = proteus_server::preflight_orchestrator::PreflightAllInput {
                    config_path: config,
                    public_ip_override: public_ip,
                    watchlist_path: watchlist,
                    skip_fingerprint,
                };
                let code = proteus_server::preflight_orchestrator::cli_run(input, &format).await?;
                if code != 0 {
                    std::process::exit(code);
                }
            }
        },
        Cmd::Admin { cmd } => match cmd {
            AdminCmd::Status {
                url,
                token_file,
                timeout_secs,
                format,
            } => {
                // Iter-109: reject zero timeout (deadline-exceeded
                // on every step → useless output). Same pattern as
                // client iter-108 on connect-test.
                if timeout_secs == 0 {
                    eprintln!(
                        "admin status: timeout_secs = 0 deadlines every step instantly. \
                         Use a real value (default 5s, sensible range 1-30s)."
                    );
                    std::process::exit(2);
                }
                let token = match token_file {
                    Some(p) => Some(proteus_server::admin::read_token_file(&p)?),
                    None => std::env::var("PROTEUS_METRICS_TOKEN")
                        .ok()
                        .map(zeroize::Zeroizing::new),
                };
                let fmt: proteus_server::admin::OutputFormat = format.parse()?;
                proteus_server::admin::run(
                    &url,
                    token.as_deref().map(|s| s.as_str()),
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
                // Iter-117: reject negative / NaN / zero interval.
                // The renderer has a guard (≤0 → 1.0) but the JSON
                // output echoes the raw value verbatim, which
                // breaks scripts that filter by it. Catch the bad
                // value at the CLI boundary.
                if !interval_secs.is_finite() || interval_secs <= 0.0 {
                    eprintln!(
                        "admin diff: interval_secs = {interval_secs} must be positive + \
                         finite. The value is the wall-clock seconds between the two \
                         scrapes; non-positive values produce divide-by-zero or \
                         nonsense rates. Use a real value (typical 30s)."
                    );
                    std::process::exit(2);
                }
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
                // Iter-109: reject zero timeout/interval. timeout=0
                // deadlines every scrape; interval=0 spins the
                // watch loop with no pause (100 % CPU + scrape
                // storm against the server).
                if timeout_secs == 0 {
                    eprintln!(
                        "admin watch: timeout_secs = 0 deadlines every scrape instantly. \
                         Use a real value (sensible range 1-30s)."
                    );
                    std::process::exit(2);
                }
                if interval_secs == 0 {
                    eprintln!(
                        "admin watch: interval_secs = 0 spins the watch loop with no \
                         pause, hammering the server with scrapes at 100% CPU. Use a \
                         real value (sensible range 1-60s)."
                    );
                    std::process::exit(2);
                }
                let token = match token_file {
                    Some(p) => Some(proteus_server::admin::read_token_file(&p)?),
                    None => std::env::var("PROTEUS_METRICS_TOKEN")
                        .ok()
                        .map(zeroize::Zeroizing::new),
                };
                let fmt: proteus_server::admin::OutputFormat = format.parse()?;
                proteus_server::admin::run_watch(
                    &url,
                    token.as_deref().map(|s| s.as_str()),
                    std::time::Duration::from_secs(timeout_secs),
                    std::time::Duration::from_secs(interval_secs),
                    fmt,
                )?;
            }
            AdminCmd::AlertsCheck {
                url,
                token_file,
                timeout_secs,
                format,
            } => {
                // Iter-109: reject zero timeout (same as Status).
                if timeout_secs == 0 {
                    eprintln!(
                        "admin alerts-check: timeout_secs = 0 deadlines every step \
                         instantly. Use a real value (sensible range 1-30s)."
                    );
                    std::process::exit(2);
                }
                let token = match token_file {
                    Some(p) => Some(proteus_server::admin::read_token_file(&p)?),
                    None => std::env::var("PROTEUS_METRICS_TOKEN")
                        .ok()
                        .map(zeroize::Zeroizing::new),
                };
                let code = proteus_server::admin_alerts_check::cli_run(
                    &url,
                    token.as_deref().map(|s| s.as_str()),
                    std::time::Duration::from_secs(timeout_secs),
                    &format,
                )?;
                if code != 0 {
                    std::process::exit(code);
                }
            }
        },
        Cmd::Fingerprint { format, target } => {
            let code = run_fingerprint_cmd(&format, &target).await?;
            std::process::exit(code);
        }
    }
    Ok(())
}

/// Implementation of `proteus-server fingerprint`. Captures the
/// live ClientHello JA4 via a loopback handshake, diffs it against
/// the curated browser reference table, prints the result in the
/// operator-selected format, and returns the exit code.
async fn run_fingerprint_cmd(
    format: &str,
    target: &str,
) -> Result<i32, Box<dyn std::error::Error>> {
    // Iter-115: validate format up-front. Pre-iter-115 typos
    // like `--format jsno` silently fell through to text mode,
    // breaking scripted jq pipelines. Mirror of iter-113/114
    // format-validation pattern.
    if format != "text" && format != "json" {
        return Err(format!(
            "fingerprint: unknown --format {format:?} (expected 'text' or 'json')"
        )
        .into());
    }
    // Mint a fresh throwaway leaf so we don't need the operator's
    // production cert to run this offline command. JA4 is computed
    // entirely from the CLIENT side, so the cert is irrelevant
    // (only used to make the rustls connector accept the
    // loopback).
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "localhost");
    params.subject_alt_names = vec![rcgen::SanType::DnsName(
        rcgen::Ia5String::try_from("localhost").unwrap(),
    )];
    let key_pair = rcgen::KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;
    let leaf = rustls::pki_types::CertificateDer::from(cert.der().to_vec());

    let observed = proteus_server::tls_fingerprint_observer::observe_live_ja4(leaf.clone()).await;
    let live_ja4 = observed.ja4.clone();
    let matches_baseline = observed.matches_baseline();
    let closest = proteus_fingerprint::find_closest(&live_ja4);

    // Optional component-level diff against a target browser.
    // Only fires when the operator passed --target chrome-124
    // (or future target labels). The deep-diff capture re-runs
    // the loopback observer because the underlying observer
    // doesn't return the raw bytes; the cost is one extra
    // ~50ms handshake, only when the operator asked.
    // Iter-17: --target now accepts chrome-124, firefox-124,
    // safari-17.4. The diff infrastructure is target-agnostic;
    // we just route the operator's label to the corresponding
    // canonical `TargetComponents` const. Other browsers (Edge,
    // mobile Chrome / Safari iOS) tend to converge to one of
    // these three — operators with niche needs can add a row
    // to ja4_diff.rs and a case here.
    let (target_components, target_label): (
        Option<&proteus_fingerprint::ja4_diff::TargetComponents>,
        &str,
    ) = match target {
        "" => (None, ""),
        "chrome-124" => (
            Some(&proteus_fingerprint::ja4_diff::CHROME_124),
            "chrome-124",
        ),
        "firefox-124" => (
            Some(&proteus_fingerprint::ja4_diff::FIREFOX_124),
            "firefox-124",
        ),
        "safari-17.4" => (
            Some(&proteus_fingerprint::ja4_diff::SAFARI_17_4),
            "safari-17.4",
        ),
        other => {
            eprintln!(
                "unknown --target {other:?}; supported: chrome-124, firefox-124, safari-17.4 (or empty for no diff)"
            );
            return Ok(2);
        }
    };
    let component_diff = if let Some(tgt) = target_components {
        proteus_server::tls_fingerprint_observer::observe_live_ja4_with_components(leaf)
            .await
            .map(|(_ja4, components)| {
                proteus_fingerprint::ja4_diff::ComponentDiff::compute(&components, tgt)
            })
    } else {
        None
    };

    match format {
        "json" => {
            // JSON Lines — one line per record. Schema is
            // append-only: kind, live_ja4, expected_baseline,
            // matches_baseline, closest_{browser,version,ja4,
            // exact}.
            use std::fmt::Write as _;
            let mut s = String::with_capacity(384);
            let _ = write!(
                s,
                r#"{{"kind":"fingerprint","live_ja4":"{}","expected_baseline":"{}","matches_baseline":{}"#,
                live_ja4, observed.expected_baseline, matches_baseline
            );
            if let Some((b, exact)) = closest {
                let _ = write!(
                    s,
                    r#","closest_browser":"{}","closest_version":"{}","closest_platform":"{}","closest_ja4":"{}","closest_exact":{}"#,
                    b.browser, b.version, b.platform, b.ja4, exact
                );
            }
            if let Some(diff) = component_diff.as_ref() {
                let _ = write!(
                    s,
                    r#","component_diff_target":"{}","component_diff_all_match":{}"#,
                    target_label, diff.all_match
                );
                for (field_name, field) in [
                    ("ciphers", &diff.ciphers),
                    ("extensions", &diff.extensions),
                    ("signature_algorithms", &diff.signature_algorithms),
                    ("alpn_offered", &diff.alpn_offered),
                    ("supported_versions", &diff.supported_versions),
                ] {
                    let _ = write!(s, r#","diff_{field_name}":{{"only_in_ours":["#);
                    for (i, item) in field.only_in_ours.iter().enumerate() {
                        if i > 0 {
                            s.push(',');
                        }
                        let _ = write!(s, r#""{}""#, item.replace('"', "\\\""));
                    }
                    s.push_str(r#"],"only_in_theirs":["#);
                    for (i, item) in field.only_in_theirs.iter().enumerate() {
                        if i > 0 {
                            s.push(',');
                        }
                        let _ = write!(s, r#""{}""#, item.replace('"', "\\\""));
                    }
                    s.push_str("]}");
                }
            }
            s.push('}');
            s.push('\n');
            print!("{s}");
        }
        _ => {
            // Text (default) — human-friendly multiline.
            println!("Proteus α — live TLS ClientHello JA4 fingerprint");
            println!("=================================================");
            println!("  Live JA4:  {}", live_ja4);
            println!("  Baseline:  {}", observed.expected_baseline);
            println!(
                "  Match:     {}",
                if matches_baseline {
                    "yes (locked baseline)"
                } else {
                    "NO — drifted from locked baseline"
                }
            );
            println!();
            println!("Closest browser in reference table:");
            if let Some((b, exact)) = closest {
                println!("  Browser:   {} {}", b.browser, b.version);
                println!("  Platform:  {}", b.platform);
                println!("  Their JA4: {}", b.ja4);
                println!(
                    "  Identical: {}",
                    if exact {
                        "YES — bit-perfect ClientHello match (uTLS-grade)"
                    } else {
                        "no — ext_count and/or hashes still differ"
                    }
                );
                if !exact {
                    let (live_cc, live_ec) = decompose_counts(&live_ja4);
                    println!(
                        "  Counts:    ours [cipher={}, ext={}] vs theirs [cipher={}, ext={}]",
                        live_cc, live_ec, b.cipher_count, b.ext_count
                    );
                }
            } else {
                println!("  (reference table empty — should never happen; file a bug)");
            }
            println!();
            println!("All reference browsers in table:");
            for b in proteus_fingerprint::BROWSERS {
                println!(
                    "  {:<8} {:<6} {:<32} {}",
                    b.browser, b.version, b.platform, b.ja4
                );
            }
            if let Some(diff) = component_diff.as_ref() {
                println!();
                println!("=================================================");
                println!("Component-level diff vs Chrome 124 (uTLS-gap visibility):");
                print!("{}", diff.render_text());
            }
        }
    }

    // Exit code: 0 on baseline-match, 1 on drift. Operators
    // wire this into CI / deploy gates so a quiet rustls bump
    // that shifts the wire fingerprint fails the pipeline.
    if matches_baseline {
        Ok(0)
    } else {
        Ok(1)
    }
}

/// Pull cipher_count + ext_count from the JA4 prefix block —
/// fixed-position 2-digit fields. Returns (0, 0) on malformed.
fn decompose_counts(ja4: &str) -> (u8, u8) {
    let prefix_end = ja4.find('_').unwrap_or(ja4.len());
    let prefix = &ja4[..prefix_end];
    if prefix.len() < 10 {
        return (0, 0);
    }
    let cc = prefix[4..6].parse::<u8>().unwrap_or(0);
    let ec = prefix[6..8].parse::<u8>().unwrap_or(0);
    (cc, ec)
}

async fn run(config_path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let cfg = ServerConfig::load(config_path).await?;
    info!(
        listen = %cfg.listen_alpha,
        users = cfg.client_allowlist.len(),
        "proteus-server starting"
    );

    // Startup self-test: run a full loopback handshake against the
    // operator's REAL keys BEFORE binding the public listener.
    // Catches mismatched mlkem_pk/sk, broken dep regressions, RNG
    // starvation — failures the operator would otherwise only
    // learn about when real users start failing handshakes.
    //
    // The self-test consumes ServerKeys (moves into the throwaway
    // ctx), so we load the keys twice: once for the test, once for
    // the production ctx. This is cheap (file I/O + a few ML-KEM
    // operations) and the deliberate redundancy ALSO tests the
    // load_server_keys path under load.
    //
    // Set `startup_self_test_timeout_secs: 0` in YAML to skip
    // (NOT recommended for production).
    let self_test_secs = cfg.startup_self_test_timeout_secs.unwrap_or(10);
    let self_test_passed = if self_test_secs > 0 {
        let test_keys = load_server_keys(&cfg)?;
        let t = std::time::Duration::from_secs(self_test_secs);
        match proteus_server::startup_self_test::run_self_test(test_keys, t).await {
            Ok(outcome) => {
                info!(
                    total_ms = outcome.total.as_millis() as u64,
                    handshake_ms = outcome.handshake.as_millis() as u64,
                    roundtrip_ms = outcome.roundtrip.as_millis() as u64,
                    "startup self-test PASSED — crypto stack is healthy, proceeding to bind listener"
                );
                true
            }
            Err(e) => {
                error!(
                    error = %e,
                    "startup self-test FAILED — refusing to bind public listener with broken crypto stack"
                );
                return Err(format!("startup self-test failed: {e}").into());
            }
        }
    } else {
        warn!(
            "startup_self_test_timeout_secs=0 — startup self-test DISABLED. \
             Operator gives up the deploy-time trip-wire for mismatched keys, \
             broken dep regressions, RNG starvation. Re-enable for production."
        );
        false
    };

    let keys = load_server_keys(&cfg)?;
    let mut ctx = ServerCtx::new(keys);

    // Load the optional knock PSK. When set, this PSK gates
    // the Path A pre-auth-passthrough behavior (REALITY-grade
    // probe resistance) — the transport-layer consumer ships
    // in a follow-up iteration. Loading at startup catches
    // file-permission / format errors NOW rather than at the
    // first connection.
    let knock_psk: Option<proteus_handshake::knock::KnockPsk> = match cfg.knock_psk_file.as_ref() {
        Some(path) => match knock_keygen::load(path) {
            Ok(bytes) => {
                info!(
                    path = ?path,
                    "knock PSK loaded — Path A probe-resistance gate will run at accept time"
                );
                // Iter-191: `bytes` is Zeroizing<[u8;32]>; deref
                // via `*bytes` AT THE LAST MOMENT to extract the
                // bare array for KnockPsk::from_bytes (which
                // wraps it in its own internal Zeroizing). The
                // Zeroizing wrapper around `bytes` scrubs the
                // outer copy on the match-arm exit.
                Some(proteus_handshake::knock::KnockPsk::from_bytes(*bytes))
            }
            Err(e) => {
                // Fatal — operator explicitly asked for
                // probe-resistance, refusing to start with
                // an invalid file is safer than silently
                // running without the gate.
                return Err(format!(
                    "knock_psk_file {path:?} load failed: {e}. \
                     Mint a fresh one with `proteus-server knock-keygen \
                     --out {path:?}` or remove the `knock_psk_file:` line \
                     from server.yaml to disable probe-resistance."
                )
                .into());
            }
        },
        None => {
            info!(
                "knock_psk_file unset — probe-resistance gate is OFF \
                 (binary runs in legacy auth-fail-then-cover-forward mode). \
                 Run `proteus-server knock-keygen` and set knock_psk_file: \
                 in server.yaml to enable."
            );
            None
        }
    };
    // Cover-endpoint wiring with precedence:
    //   1. `cover_endpoints` (the POOL with per-source-IP affinity) — wins
    //      when non-empty; defeats time-series active probing.
    //   2. `cover_endpoint` (the single-URL shorthand) — backward
    //      compatibility for operators who haven't migrated yet.
    //   3. Neither → silent drop on auth fail.
    if !cfg.cover_endpoints.is_empty() {
        let mut parsed_list = Vec::with_capacity(cfg.cover_endpoints.len());
        let mut rejected = 0usize;
        for raw in &cfg.cover_endpoints {
            match proteus_transport_alpha::cover::parse_cover_endpoint(raw) {
                Some(p) => parsed_list.push(p),
                None => {
                    rejected += 1;
                    warn!(cover = %raw, "invalid cover endpoint in cover_endpoints pool — skipping");
                }
            }
        }
        if parsed_list.is_empty() {
            warn!(
                rejected,
                "every cover_endpoints entry was invalid — auth-fail connections will be dropped"
            );
        } else {
            info!(
                pool_size = parsed_list.len(),
                rejected, "cover endpoint POOL configured (per-src-IP /24 affinity)"
            );
            ctx = ctx.with_cover_pool(parsed_list);
            if cfg.cover_endpoint.is_some() {
                warn!(
                    "cover_endpoint is also set — IGNORED because cover_endpoints pool wins; \
                     remove cover_endpoint from the YAML to silence this warning"
                );
            }
        }
    } else if let Some(cover) = &cfg.cover_endpoint {
        match proteus_transport_alpha::cover::parse_cover_endpoint(cover) {
            Some(parsed) => {
                info!(cover = %parsed, "cover endpoint configured (single)");
                ctx = ctx.with_cover(parsed);
            }
            None => {
                warn!(cover = %cover, "invalid cover endpoint — auth-fail connections will be dropped")
            }
        }
    } else {
        warn!("no cover_endpoint or cover_endpoints configured — auth-fail connections will be dropped silently");
    }

    // Path-A dispatch config. Composes the loaded knock PSK
    // (if any) with the operator's single-cover endpoint
    // (cover_endpoint), so the gate's RouteToCover path has a
    // splice target. Operators wanting probe resistance MUST
    // set BOTH `knock_psk_file:` and a single `cover_endpoint:`
    // — the pool path (cover_endpoints) is per-source-IP
    // affinity for the legacy auth-fail flow and isn't wired
    // into Path A's pre-auth splice yet.
    //
    // FAIL-CLOSED: if knock_psk is set but no cover_endpoint
    // is configured, refuse to start. A Path-A deploy without
    // cover would leave probers seeing a TCP RST or hung
    // connection — exactly the fingerprint Path A is meant
    // to eliminate. Operator either configures a cover or
    // unsets knock_psk_file.
    let dispatch_cfg: std::sync::Arc<proteus_transport_alpha::knock_dispatch::DispatchConfig> =
        std::sync::Arc::new({
            let mut c = proteus_transport_alpha::knock_dispatch::DispatchConfig::default();
            if let Some(psk) = knock_psk.as_ref() {
                // Path A wants its own splice target string —
                // re-resolve the cover endpoint from cfg rather
                // than reaching into ctx (which already consumed
                // it via with_cover()).
                let cover_for_path_a = cfg
                    .cover_endpoint
                    .as_deref()
                    .and_then(proteus_transport_alpha::cover::parse_cover_endpoint);
                if cover_for_path_a.is_none() {
                    return Err("knock_psk_file is set but cover_endpoint is unconfigured. \
                     Path A's gate routes probers to the cover endpoint; without \
                     a configured cover the probe-resistance behavior degrades to \
                     'TCP RST or hang' which IS itself a fingerprint. Set \
                     cover_endpoint: in server.yaml (e.g. www.cloudflare.com:443) \
                     or unset knock_psk_file: to disable Path A."
                        .into());
                }
                c.psk = Some(psk.clone());
                c.cover_endpoint = cover_for_path_a;
                info!(
                    cover = ?c.cover_endpoint,
                    "Path A dispatch config built — probe-resistance gate is ARMED"
                );
            }
            c
        });

    if let Some(pa) = &cfg.probe_anomaly {
        info!(
            window_secs = pa.window_secs,
            threshold = pa.threshold,
            max_prefixes = pa.max_prefixes,
            autodeny_minutes = pa.autodeny_minutes,
            autodeny_max_entries = pa.autodeny_max_entries,
            "probe-anomaly detector configured (per-/24 sliding window)"
        );
        let detector = std::sync::Arc::new(
            proteus_transport_alpha::probe_anomaly::ProbeAnomalyDetector::new(
                std::time::Duration::from_secs(pa.window_secs),
                pa.threshold,
                pa.max_prefixes,
            ),
        );
        ctx = ctx.with_probe_anomaly_detector(detector);
        // Auto-deny is operator-opt-in: only wired when
        // `autodeny_minutes > 0`. The detector still fires regardless
        // (alerting != enforcement), so operators who only want the
        // metric/log surface can leave autodeny unset.
        if pa.autodeny_minutes > 0 {
            let auto_deny =
                std::sync::Arc::new(proteus_transport_alpha::auto_deny::AutoDenyList::new(
                    std::time::Duration::from_secs(pa.autodeny_minutes * 60),
                    pa.autodeny_max_entries,
                ));
            info!(
                ttl_minutes = pa.autodeny_minutes,
                max_entries = pa.autodeny_max_entries,
                "auto-deny list wired — anomaly fires will short-circuit subsequent connections from the same /24 (v4) / /48 (v6)"
            );
            ctx = ctx.with_auto_deny_list(auto_deny);
        }
    } else {
        // No-op: detector silent when unset; operators on long-lived
        // deployments should turn it on so probe-volume signals
        // surface as metrics rather than disappearing into noise.
        info!(
            "probe_anomaly detector unset — cover-forward bursts will not surface as \
             alerts (consider enabling for production)"
        );
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
    // Iter-20: cover-forward concurrency cap. Default to None if
    // operator didn't set it, but auto-derive `max_connections * 4`
    // when max_connections IS set — that's the production-recommended
    // rule of thumb (most cover-forwards exit in <2s when the cover
    // endpoint is healthy, so 4× headroom over the in-flight session
    // count absorbs normal bursts without letting an unbounded
    // probe storm exhaust FDs).
    let resolved_cover_cap = match (cfg.max_cover_forwards, cfg.max_connections) {
        (Some(explicit), _) => Some(explicit),
        (None, Some(n)) => Some(n.saturating_mul(4)),
        (None, None) => None,
    };
    if let Some(n) = resolved_cover_cap {
        info!(
            max = n,
            derived_from = if cfg.max_cover_forwards.is_some() {
                "explicit max_cover_forwards"
            } else {
                "max_connections * 4 (default rule of thumb)"
            },
            "max_cover_forwards cap configured — cover-forward path bounded"
        );
        ctx = ctx.with_max_cover_forwards(n);
    } else {
        warn!(
            "no max_cover_forwards or max_connections configured — cover-forward path \
             is unbounded; under a probe storm this can exhaust FDs even with iter-18 \
             EMFILE-survival in place. Set max_cover_forwards in server.yaml."
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

    // Restart-history tracker. Only enabled when the operator sets
    // `restart_state_file:` in the YAML — without it we'd silently
    // create a state file under whatever cwd the binary launched
    // from, which is hostile to operators who launch from a
    // read-only systemd unit. Opt-in by intent: when the file path
    // is present, the tracker persists + exposes the counter +
    // classifies the previous run. When absent, restart tracking
    // is off and the metrics block isn't emitted.
    let restart_tracker = cfg
        .restart_state_file
        .as_ref()
        .map(|p| proteus_server::restart_tracker::RestartTracker::init(p.clone()));

    // Single per-process DNS-resolver stats sink. The relay path
    // bumps these counters on every upstream-dial DNS lookup; the
    // metrics endpoint exposes them as
    // `proteus_dns_lookups_total{outcome="ok|failed|timeout"}`.
    // Closes the silent-DNS-hang class: without per-outcome
    // counters, a wedged recursive nameserver silently pegs every
    // relay task at the lookup timeout and the only signal is
    // upstream-dial-timeout cascades (which look identical to a
    // genuinely-unreachable destination).
    let dns_resolver_stats =
        Arc::new(proteus_transport_alpha::outbound_filter::DnsResolverStats::default());
    // Propagate the self-test outcome to the operator-visible
    // gauge BEFORE the metrics endpoint binds — operators
    // alert on `proteus_startup_self_test_passed == 0` to spot
    // deploys where the binary started but couldn't prove its
    // own crypto path works.
    metrics
        .startup_self_test_passed
        .store(self_test_passed, std::sync::atomic::Ordering::Relaxed);
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

    // Per-user bandwidth accumulator — bounded at 4096 distinct
    // user_ids by default. Operators with > 4096 users in
    // client_allowlist will see overflow attribution under the
    // `__overflow__` bucket on /metrics; raising the cap is a
    // future-config item (today it's a const because shipping the
    // YAML knob is one more iteration and the default already
    // covers typical personal-VPN-for-friends scale).
    let per_user_bandwidth =
        Arc::new(proteus_transport_alpha::per_user_bandwidth::PerUserBandwidth::new(4096));
    ctx = ctx.with_per_user_bandwidth(Arc::clone(&per_user_bandwidth));

    // Per-user sustained bandwidth-rate detector. Wired into the
    // accumulator so every session-close runs the rate check, and a
    // burst-alert fires inside InFlightGuard::drop (one WARN line +
    // bump of `proteus_abuse_alerts_per_user_bandwidth_total`).
    //
    // When the operator's YAML has no `per_user_bandwidth_rate:`
    // block, NO detector is wired — the accumulator stays in its
    // back-compat (counter-only, no rate alerts) mode. When the
    // block is present with threshold=0, a detector IS wired but
    // silent — gauges still emit so operators can verify the slot.
    if let Some(rcfg) = cfg.per_user_bandwidth_rate.as_ref() {
        let det = std::sync::Arc::new(
            proteus_transport_alpha::per_user_bandwidth_rate_detector::PerUserBandwidthRateDetector::new(
                std::time::Duration::from_secs(rcfg.window_secs),
                rcfg.threshold_mb_per_sec.saturating_mul(1024 * 1024),
                rcfg.max_users,
            )
            .with_exit_factor(rcfg.exit_factor),
        );
        per_user_bandwidth.set_rate_detector(Some(Arc::clone(&det)));
        if rcfg.threshold_mb_per_sec == 0 {
            info!(
                window_secs = rcfg.window_secs,
                max_users = rcfg.max_users,
                "per-user bandwidth-rate detector WIRED but SILENT (threshold_mb_per_sec=0)"
            );
        } else {
            info!(
                window_secs = rcfg.window_secs,
                threshold_mb_per_sec = rcfg.threshold_mb_per_sec,
                exit_factor = rcfg.exit_factor,
                max_users = rcfg.max_users,
                "per-user bandwidth-rate detector configured (fire-once-per-burst with hysteresis)"
            );
        }
    } else {
        info!(
            "per_user_bandwidth_rate unset — sustained-bandwidth abuse alerts disabled \
             (set in server.yaml to enable in-process credential-abuse detection without Prometheus)"
        );
    }

    // Per-user concurrent-session cap. When wired, every session-
    // handler closure (β/α-TCP/α-TLS) consults the limiter AFTER
    // handshake (user_id known) and BEFORE the relay. A user_id at
    // the cap gets its session torn down without paying the relay
    // cost; bumps `proteus_per_user_conn_limit_rejected_total`.
    //
    // The limiter handle ALSO threads into ctx (`with_per_user_conn_limiter`)
    // so other code paths can introspect / render its Prometheus
    // block via the metrics endpoint (separate wire below).
    let per_user_conn_limiter = cfg.per_user_conn_limit.as_ref().map(|c| {
        let l = proteus_transport_alpha::per_user_conn_limit::PerUserConnLimiter::new(c.max_per_user);
        if c.max_per_user == 0 {
            info!(
                "per-user concurrent-session limiter WIRED but DISABLED (max_per_user=0)"
            );
        } else {
            info!(
                max_per_user = c.max_per_user,
                "per-user concurrent-session cap configured — credential abuse via parallel-session amplification is now bounded"
            );
        }
        l
    });
    if let Some(l) = per_user_conn_limiter.as_ref() {
        ctx = ctx.with_per_user_conn_limiter(Arc::clone(l));
    } else {
        info!(
            "per_user_conn_limit unset — one stolen credential could open unbounded \
             parallel sessions. Recommended: max_per_user=4-10 (mirrors commercial-VPN per-account device cap)."
        );
    }

    // Recent-abuse-fires ring buffer. Default capacity 64 — covers
    // ~last hour for any sane deployment. Filled by all three
    // detector fire sites (byte_budget in relay.rs, rate_limit in
    // server.rs, per_user_bandwidth_rate via PerUserBandwidth's
    // record_with_rate_check). Operators query the contents via
    // `/diagnose`, `admin abuse-fires`, or the count gauge on
    // `/metrics`.
    //
    // The buffer is ALWAYS wired (no YAML opt-in needed) because
    // the memory footprint is bounded (64 fires × 24 bytes ≈ 1.5KB)
    // and the operational value is high — "WHO fired" is the
    // question every abuse alert immediately raises.
    let abuse_fires_buffer = Arc::new(proteus_transport_alpha::abuse_fires::AbuseFireBuffer::new(
        64,
    ));
    ctx = ctx.with_abuse_fires(Arc::clone(&abuse_fires_buffer));
    per_user_bandwidth.set_abuse_fires(Some(Arc::clone(&abuse_fires_buffer)));
    info!(
        capacity = 64,
        "recent-abuse-fires ring buffer wired (query via /diagnose or `admin abuse-fires`)"
    );

    // Auto-quarantine list (optional). When configured, abuse-fire
    // detectors flagged in `on_kinds` will auto-insert the offending
    // user_id into a TTL-bounded ban list. Subsequent handshakes
    // from that user_id are rejected at the post-handshake admission
    // gate — closing the loop from observation to enforcement
    // automatically, with no human in the loop. The IP-based
    // auto_deny.rs does the analogous job for source-IP prefixes;
    // this is the per-credential sibling that defends against
    // stolen-credential abuse spread across many source IPs.
    let user_quarantine_list: Option<
        Arc<proteus_transport_alpha::user_quarantine::UserQuarantineList>,
    > = match cfg.user_quarantine.as_ref() {
        Some(qcfg) => {
            // Load prior state from disk when persistence is configured;
            // otherwise start with an empty list. Either way the
            // returned instance has persistence wired so subsequent
            // inserts auto-write.
            let list = Arc::new(match qcfg.persistence_path.as_ref() {
                Some(path) => {
                    proteus_transport_alpha::user_quarantine::UserQuarantineList::load_from_disk(
                        path.clone(),
                        std::time::Duration::from_secs(qcfg.ttl_secs),
                        qcfg.max_entries,
                    )
                }
                None => proteus_transport_alpha::user_quarantine::UserQuarantineList::new(
                    std::time::Duration::from_secs(qcfg.ttl_secs),
                    qcfg.max_entries,
                ),
            });
            if list.loaded_from_disk() > 0 {
                info!(
                    restored = list.loaded_from_disk(),
                    path = ?qcfg.persistence_path,
                    "user_quarantine: restored prior bans from disk"
                );
            }
            // Filter on_kinds to the known set of labels (forward-
            // compat: unknown labels are silently accepted but
            // never trigger enforcement). Build the static-str set
            // by matching exactly so the ServerCtx slot stays
            // `&'static str`-keyed.
            let mut accepted: Vec<&'static str> = Vec::new();
            for k in &qcfg.on_kinds {
                let lit: Option<&'static str> = match k.as_str() {
                    "byte_budget" => Some(
                        proteus_transport_alpha::abuse_fires::AbuseFireKind::ByteBudget.as_label(),
                    ),
                    "rate_limit" => Some(
                        proteus_transport_alpha::abuse_fires::AbuseFireKind::RateLimit.as_label(),
                    ),
                    "per_user_bandwidth_rate" => Some(
                        proteus_transport_alpha::abuse_fires::AbuseFireKind::PerUserBandwidthRate
                            .as_label(),
                    ),
                    other => {
                        warn!(
                            kind = %other,
                            "user_quarantine.on_kinds entry not recognized — ignored \
                             (valid: byte_budget, rate_limit, per_user_bandwidth_rate)"
                        );
                        None
                    }
                };
                if let Some(l) = lit {
                    accepted.push(l);
                }
            }
            ctx = ctx
                .with_user_quarantine(Arc::clone(&list))
                .with_quarantine_on_kinds(accepted.iter().copied());
            // The per-user bandwidth accumulator needs its own
            // handle because its `Fired` outcome happens INSIDE
            // record_with_rate_check (not at the post-handshake
            // gate where ctx is consulted).
            let opt_in_pubr = accepted.contains(
                &proteus_transport_alpha::abuse_fires::AbuseFireKind::PerUserBandwidthRate
                    .as_label(),
            );
            per_user_bandwidth.set_quarantine(Some(Arc::clone(&list)), opt_in_pubr);
            if qcfg.ttl_secs == 0 {
                info!("user_quarantine WIRED but DISABLED (ttl_secs=0; SIGHUP-swap slot ready)");
            } else {
                info!(
                    ttl_secs = qcfg.ttl_secs,
                    max_entries = qcfg.max_entries,
                    on_kinds = ?accepted,
                    "user_quarantine configured — abuse fires from listed kinds AUTO-BAN the user_id for TTL"
                );
            }
            Some(list)
        }
        None => {
            info!(
                "user_quarantine unset — abuse fires emit alerts + recent-fires ring entries \
                 but DO NOT auto-ban. Recommended for production: enable with at least \
                 `on_kinds: [per_user_bandwidth_rate]` so stolen credentials self-block."
            );
            None
        }
    };

    // Per-user period-based data quota tracker. Closes the gap
    // left by the rate / event detectors: a patient attacker who
    // stays under any single-session cap AND any sustained-rate
    // threshold can drain TBs over weeks. Every commercial VPN
    // has period caps; Proteus's tracker matches that shape.
    let user_quotas_list: Option<Arc<proteus_transport_alpha::user_quota::PerUserQuotaTracker>> =
        match cfg.user_quotas.as_ref() {
            Some(qcfg) => {
                let tracker = Arc::new(match qcfg.persistence_path.as_ref() {
                    Some(path) => {
                        proteus_transport_alpha::user_quota::PerUserQuotaTracker::load_from_disk(
                            path.clone(),
                            std::time::Duration::from_secs(qcfg.period_secs),
                            qcfg.default_period_bytes,
                            qcfg.max_entries,
                        )
                    }
                    None => proteus_transport_alpha::user_quota::PerUserQuotaTracker::new(
                        std::time::Duration::from_secs(qcfg.period_secs),
                        qcfg.default_period_bytes,
                        qcfg.max_entries,
                    ),
                });
                // Apply YAML-supplied overrides (operator's
                // per-user cap_overrides). The set_user_cap call
                // also persists, so the override survives the
                // next restart even if the file didn't have it
                // previously.
                for ov in &qcfg.overrides {
                    let bytes = ov.user_id.as_bytes();
                    if bytes.len() > 8 {
                        warn!(
                            user_id = %ov.user_id,
                            "user_quotas override: user_id > 8 bytes, ignored"
                        );
                        continue;
                    }
                    let mut uid = [0u8; 8];
                    uid[..bytes.len()].copy_from_slice(bytes);
                    tracker.set_user_cap(uid, ov.period_bytes);
                    info!(
                        user_id = %ov.user_id,
                        period_bytes = ov.period_bytes,
                        "user_quotas: override applied"
                    );
                }
                info!(
                    period_secs = qcfg.period_secs,
                    default_period_bytes = qcfg.default_period_bytes,
                    overrides = qcfg.overrides.len(),
                    restored = tracker.loaded_from_disk(),
                    "user_quotas configured — per-user period byte caps active"
                );
                Some(tracker)
            }
            None => {
                info!(
                    "user_quotas unset — no per-user period byte caps. A patient \
                 attacker staying under per-session + rate thresholds can drain \
                 TBs over weeks. Recommended for production: enable with a \
                 sensible default_period_bytes (e.g. 100 GiB monthly)."
                );
                None
            }
        };
    if let Some(tracker) = user_quotas_list.as_ref() {
        ctx = ctx.with_user_quota(Arc::clone(tracker));
        per_user_bandwidth.set_quota(Some(Arc::clone(tracker)));
    }

    let ctx = Arc::new(ctx);

    // Build the TLS 1.3 outer wrapper FIRST (before the metrics
    // listener spawns) so the metrics endpoint can include the
    // cert-expiry gauge + SIGHUP reload counters on its very first
    // scrape. Moved up from below-the-metrics-block on 2026-05-18 when
    // `proteus_tls_cert_not_after_unix_seconds` landed — operators
    // want the cert ticking down to be visible from t=0, not from the
    // first SIGHUP.
    let (reloadable_acceptor, tls_cert_watcher, tls_leaf_for_ja4) = match cfg.tls.as_ref() {
        Some(tls_cfg) => {
            info!(cert = ?tls_cfg.cert_chain, "loading TLS cert chain");
            let chain = proteus_transport_alpha::tls::load_cert_chain(&tls_cfg.cert_chain)
                .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
            let key = proteus_transport_alpha::tls::load_private_key(&tls_cfg.private_key)
                .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
            let leaf_for_ja4 = chain.first().cloned();
            let acceptor = proteus_transport_alpha::tls::build_acceptor(chain.clone(), key)
                .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
            let reloadable =
                proteus_transport_alpha::tls::ReloadableAcceptor::new_with_expiry(acceptor, &chain);
            if let Some(ts) = reloadable.leaf_not_after() {
                info!(
                    not_after_unix = ts,
                    "TLS 1.3 outer wrapper enabled (SIGHUP triggers reload, cert expiry tracked)"
                );
            } else {
                info!("TLS 1.3 outer wrapper enabled (SIGHUP triggers reload)");
            }
            // Build the file-mtime watcher EVEN when the operator
            // hasn't set `tls_cert_watcher_interval_secs` — the
            // initial mtime stamp is cheap, and a future SIGHUP
            // that flips on the periodic task starts from a sane
            // baseline. Without the watcher built here, an
            // operator who later enables the feature would see
            // every cert file's mtime as "changed" on the first
            // poll cycle (false positive).
            let watcher = Arc::new(proteus_transport_alpha::tls_watcher::CertFileWatcher::new(
                tls_cfg.cert_chain.clone(),
                tls_cfg.private_key.clone(),
            ));
            (Some(reloadable), Some(watcher), leaf_for_ja4)
        }
        None => {
            warn!(
                "no `tls:` block in config — server will run plain TCP. \
                 This is INSECURE in production; passive DPI will identify the protocol."
            );
            (None, None, None)
        }
    };

    // Live JA4 capture — runs once at startup after the TLS
    // cert is loaded. Surfaces the binary's actual on-wire
    // ClientHello fingerprint via /metrics so operators can
    // verify what JA4 their deploy emits without running tshark.
    // Skipped when TLS isn't configured (no leaf to drive the
    // loopback handshake against).
    let live_ja4_block: Option<Arc<String>> = if let Some(leaf) = tls_leaf_for_ja4 {
        let observed = proteus_server::tls_fingerprint_observer::observe_live_ja4(leaf).await;
        if observed.matches_baseline() {
            info!(
                ja4 = %observed.ja4,
                "live TLS ClientHello JA4 captured (matches locked baseline)"
            );
        } else {
            warn!(
                live_ja4 = %observed.ja4,
                expected_baseline = %observed.expected_baseline,
                "live TLS ClientHello JA4 does NOT match the locked baseline — \
                 either a dep drift (rustls upgrade) regressed the fingerprint OR \
                 uTLS-replay work landed (update EXPECTED_BASELINE in BOTH \
                 tls_fingerprint_observer.rs AND the proteus-fingerprint \
                 baseline test, then rebuild)."
            );
        }
        Some(Arc::new(observed.prometheus()))
    } else {
        None
    };

    if let Some(metrics_addr) = cfg.metrics_listen.clone() {
        // Load the bearer-token gate (if configured). Failing to read
        // the token file is fatal — silently downgrading to "no auth"
        // would expose /metrics on whatever interface the operator
        // chose, defeating the whole point of configuring auth.
        let auth = match cfg.metrics_token_file.as_ref() {
            Some(path) => {
                // Iter-180: wrap the file-read String in
                // `Zeroizing` so the backing buffer scrubs on
                // drop. `raw` carries the bearer token verbatim
                // (with leading/trailing whitespace) and the
                // trimmed `&str` slice in `token` references the
                // same bytes — the token is moved into the
                // Arc-Zeroizing<String> inside `MetricsAuth::new`,
                // but the source `raw` String lingered on the
                // heap pre-iter-180 until later activity reused
                // its backing.
                //
                // Bearer-token recovery via coredump = the
                // attacker can scrape `/metrics`, `/diagnose`,
                // `/healthz` against the live binary — same
                // operator-privilege set, including the
                // per-user-bandwidth + auto-deny + abuse-fires
                // observability surfaces that reveal who's
                // connected.
                use zeroize::Zeroizing;
                let raw = Zeroizing::new(
                    std::fs::read_to_string(path)
                        .map_err(|e| format!("metrics_token_file {path:?}: {e}"))?,
                );
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
        // Pull the probe-anomaly detector + auto-deny list out of
        // the ServerCtx so the /metrics endpoint exposes their
        // diagnostic gauges + per-prefix labelled lines. Operators
        // get the "WHICH /24 fired?" + "WHO is currently denied?"
        // signals without grepping logs.
        let probe_anomaly = ctx.probe_anomaly().cloned();
        let auto_deny = ctx.auto_deny().cloned();
        // Hand the `ReloadableAcceptor` to the metrics endpoint so the
        // `/metrics` scrape exposes:
        //   - `proteus_tls_cert_not_after_unix_seconds` — leaf cert
        //     notAfter; PromQL `(_ - time()) < 14*86400` for cert-
        //     expiry pages BEFORE Let's Encrypt silently dies.
        //   - `proteus_tls_reload_attempts_total` and
        //     `_succeeded_total` — silent-SIGHUP-failure detector
        //     (`attempts - succeeded > 0` ⇒ certbot's renewal hook
        //     ran but Proteus didn't pick the cert up).
        let tls_for_metrics = reloadable_acceptor.clone();
        // Pre-render the config-presence Prometheus block ONCE at
        // startup — the section-active gauges + cover-pool size +
        // allowlist size are set-at-startup values that don't
        // mutate without a process restart. Wrapping in Arc<String>
        // lets every scrape clone the pointer cheaply.
        //
        // **Why the block is captured at startup and NOT regenerated
        // on SIGHUP**: the existing SIGHUP path hot-swaps INSIDE
        // sections (firewall rules, rate-limit values) but cannot
        // toggle a section's presence — adding a brand-new section
        // to a previously-bare config requires a restart anyway
        // (you can't hot-install a limiter that wasn't installed at
        // startup; that's documented in the reload counter
        // semantics). Re-rendering on SIGHUP would change the
        // gauge in cases where the underlying runtime didn't change,
        // which is confusing rather than helpful.
        // Pre-render the operator-visibility blocks (config
        // presence + live JA4) as a single Arc<String> so the
        // metrics endpoint emits them on every scrape without
        // re-computing. Both are set ONCE at startup; the JA4
        // observer doesn't re-run unless the binary restarts.
        let mut presence_text = cfg.presence().prometheus();
        if let Some(ja4) = &live_ja4_block {
            presence_text.push_str(ja4);
        }
        let config_presence_block = Some(std::sync::Arc::new(presence_text));
        // Process-lifecycle metrics — start time captured here so
        // the gauge reflects "when the metrics endpoint came up"
        // (≈ process start, within a few ms of binary main()). The
        // version comes from CARGO_PKG_VERSION baked at compile
        // time. `rustc` and `target` are best-effort: passed as
        // empty strings unless the operator wired a build script;
        // the rendered labels are still valid Prometheus (empty
        // label values are spec-allowed) and operators querying
        // `proteus_build_info{version="0.1.0"}` get the answer
        // they want even without the other fields.
        let process_info = Some(std::sync::Arc::new(
            proteus_transport_alpha::process_info::ProcessInfo::capture(
                env!("CARGO_PKG_VERSION"),
                option_env!("RUSTC_VERSION").unwrap_or(""),
                option_env!("TARGET").unwrap_or(""),
            ),
        ));
        let per_user_for_metrics = Some(Arc::clone(&per_user_bandwidth));
        let per_user_conn_limiter_for_metrics = per_user_conn_limiter.as_ref().map(Arc::clone);
        let abuse_fires_for_metrics = Some(Arc::clone(&abuse_fires_buffer));
        let user_quarantine_for_metrics = user_quarantine_list.as_ref().map(Arc::clone);
        let user_quotas_for_metrics = user_quotas_list.as_ref().map(Arc::clone);
        let tls_cert_watcher_for_metrics = tls_cert_watcher.as_ref().map(Arc::clone);
        // Live-evaluated Prometheus blocks. Canonical cases today:
        //
        //   * panic counter — process-global, mutates on every
        //     spawned-task panic, MUST be readable per scrape.
        //     Alerts wire `rate(proteus_panics_total[5m]) > 0`.
        //   * restart tracker — `last_clean_shutdown_unix` mutates
        //     when SIGTERM hits the drain handler mid-process, so
        //     a closure-rendered block keeps that gauge fresh.
        //     Skipped when `restart_state_file:` isn't configured.
        //
        // Closures are cheap (atomic load + format!()) and run in
        // the scrape handler's task — no allocation when zero
        // panics, single allocation when ≥ 1.
        let mut live_blocks: Vec<
            std::sync::Arc<proteus_transport_alpha::metrics_http::LiveMetricsBlock>,
        > = vec![std::sync::Arc::new(|| {
            proteus_server::process_panic_counter::prometheus()
        })];
        if let Some(rt) = restart_tracker.as_ref().cloned() {
            live_blocks.push(std::sync::Arc::new(move || rt.prometheus()));
        }
        // DNS resolver stats — same closure pattern as the
        // restart tracker. Three counters (ok/failed/timeout)
        // emitted as a labelled series so dashboards can compute
        // timeout-ratio cheaply.
        {
            let dns_stats = Arc::clone(&dns_resolver_stats);
            live_blocks.push(std::sync::Arc::new(move || dns_stats.prometheus()));
        }
        // Rejection-log throttle counters — surfaces the count
        // of WARN lines that the in-process throttle admitted
        // vs. suppressed on each hot rejection path
        // (firewall_denied, handshake_budget_exhausted,
        // max_connections_reached). Operators alert on
        // `rate(proteus_log_throttle_suppressed_total[5m]) > 0`
        // to spot a sustained scanner / DoS hammer that's
        // generating thousands of rejections per second.
        live_blocks.push(std::sync::Arc::new(|| {
            proteus_transport_alpha::server::rejection_log_throttle_prometheus()
        }));
        // Access-log writer health + throughput — surfaces the
        // `proteus_access_log_records_total{outcome=...}` +
        // `proteus_access_log_writer_alive` series. Operators
        // alert IMMEDIATELY on writer_alive=0 (disk full, FS
        // unwritable, fsync failure → no audit trail) and on
        // `outcome="dropped_writer_dead" > 0` for the same
        // reason from the producer side.
        //
        // The closure reads from process_access_log_stats — a
        // OnceLock that the access_log spawn populates LATER in
        // main(). When unset (no `access_log:` in config), the
        // helper returns the empty string so the /metrics body
        // gains no spurious lines.
        live_blocks.push(std::sync::Arc::new(|| {
            proteus_server::process_access_log_stats::prometheus()
        }));
        tokio::spawn(async move {
            if let Err(e) = proteus_transport_alpha::metrics_http::serve_with_auth_full_v12(
                &metrics_addr,
                metrics,
                auth,
                probe_anomaly,
                auto_deny,
                tls_for_metrics,
                config_presence_block,
                process_info,
                per_user_for_metrics,
                per_user_conn_limiter_for_metrics,
                abuse_fires_for_metrics,
                user_quarantine_for_metrics,
                user_quotas_for_metrics,
                tls_cert_watcher_for_metrics,
                live_blocks,
            )
            .await
            {
                error!(error = %e, "metrics endpoint exited");
            }
        });
    }

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

    // sd_notify(READY=1) — tell systemd we're actually ready to
    // accept traffic. With Type=notify in the unit file, a
    // downstream `After=proteus-server.service` (e.g. a Caddy
    // reverse proxy) starts only AFTER this point — past TLS
    // load, past self-test, past listener bind. Without this
    // (Type=simple), systemd marks "active" the moment the
    // process forks and the downstream races us. No-op when
    // $NOTIFY_SOCKET is unset (manual run / non-systemd
    // container).
    let _ = proteus_sd_notify::notify_ready().await;
    let _ = proteus_sd_notify::notify_status(&format!("ready on {}", listener.local_addr()?)).await;

    // Watchdog ping task. systemd's WatchdogSec= declaration
    // restarts the process if no WATCHDOG=1 arrives within the
    // configured window. We ping at half the systemd-supplied
    // timeout so scheduling jitter doesn't trip a false restart.
    // A deadlocked tokio runtime can't run the ping task → the
    // watchdog fires → systemd restarts → the new process picks
    // up restart_tracker.previous_run_unclean = 1 (visible on
    // /metrics). Closes the silent-deadlock class.
    let watchdog_cancel = std::sync::Arc::new(tokio::sync::Notify::new());
    let _watchdog_handle = if let Some(interval) = proteus_sd_notify::watchdog_interval() {
        info!(
            interval_secs = interval.as_secs(),
            "sd_notify watchdog active — pinging WATCHDOG=1 at half the configured WatchdogSec"
        );
        Some(proteus_sd_notify::spawn_watchdog(
            interval,
            std::sync::Arc::clone(&watchdog_cancel),
        ))
    } else {
        info!(
            "sd_notify watchdog disabled (no WATCHDOG_USEC env var; \
                 set WatchdogSec= in the systemd unit to enable)"
        );
        None
    };

    // Periodic sd_notify STATUS refresher (every 60s when systemd
    // is present). Without this, `systemctl status proteus-server`
    // shows the STATUS line frozen at startup ("ready on
    // 0.0.0.0:8443") forever — useless for triaging a live
    // deployment. With it, operators see a fresh snapshot of
    // in-flight sessions + cumulative handshakes per minute.
    //
    // No-ops when $NOTIFY_SOCKET is unset, so dev launches don't
    // pay for the task. Cheap: an atomic load + format!() + a
    // single sendto on a unix-dgram socket.
    {
        let metrics_for_status = Arc::clone(&metrics);
        let cancel_for_status = std::sync::Arc::clone(&watchdog_cancel);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // Skip the immediate-fire so the first STATUS refresh
            // happens 60s after startup — startup already wrote
            // a fresh STATUS line.
            tick.tick().await;
            loop {
                tokio::select! {
                    _ = tick.tick() => {
                        use std::sync::atomic::Ordering as O;
                        let in_flight = metrics_for_status
                            .in_flight_sessions
                            .load(O::Relaxed);
                        let handshakes_ok = metrics_for_status
                            .handshakes_succeeded
                            .load(O::Relaxed);
                        let handshakes_failed = metrics_for_status
                            .handshakes_failed
                            .load(O::Relaxed);
                        let _ = proteus_sd_notify::notify_status(&format!(
                            "in_flight={in_flight} handshakes_ok={handshakes_ok} \
                             handshakes_failed={handshakes_failed}"
                        )).await;
                    }
                    () = cancel_for_status.notified() => {
                        // Same cancel notify the watchdog uses —
                        // drain begins, we stop posting STATUS so
                        // the drain handler's STATUS line is the
                        // last thing systemctl shows.
                        return;
                    }
                }
            }
        });
    }

    // Periodic rejection-log throttle rollup. Every 60s, drain
    // the suppressed-count from each throttled call site and
    // emit a single `warn!(suppressed=N, site="..")` line for
    // each non-zero bucket. Without this, the suppression count
    // sits invisible until an operator scrapes /metrics — with
    // it, the journal carries the rollup so `journalctl -u
    // proteus-server` shows a periodic line each window where
    // throttling fired.
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tick.tick().await; // skip immediate fire
        loop {
            tick.tick().await;
            for (site, suppressed) in
                proteus_transport_alpha::server::rejection_log_throttle_drain_rollups()
            {
                warn!(
                    site,
                    suppressed,
                    window_secs = 60,
                    "log-throttle: suppressed similar messages in last window"
                );
            }
        }
    });

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

    // Periodic self-test (optional). Runs the same loopback
    // handshake the startup self-test ran, every N seconds. On
    // failure, flips `last_periodic_self_test_passed = false` so
    // `/healthz` returns 503 — load balancers route traffic away
    // from this degraded instance until the test recovers.
    //
    // Re-reads keys from disk every cycle: cheap (file I/O) and
    // ALSO catches a chmod-broken-keys-file mid-run.
    let periodic_interval_secs = cfg.periodic_self_test_interval_secs.unwrap_or(0);
    if periodic_interval_secs > 0 {
        // Publish the configured interval so /healthz can apply
        // the staleness rule (3× interval = unhealthy).
        metrics
            .periodic_self_test_interval_secs
            .store(periodic_interval_secs, std::sync::atomic::Ordering::Relaxed);
        // Publish the hysteresis threshold (default 2). /healthz
        // reads `consecutive_periodic_self_test_failures >=
        // failure_threshold` to decide whether to flip to 503;
        // operators wanting legacy single-failure-drain set
        // this to 1.
        let failure_threshold = cfg.periodic_self_test_failure_threshold.unwrap_or(2);
        metrics
            .periodic_self_test_failure_threshold
            .store(failure_threshold, std::sync::atomic::Ordering::Relaxed);
        info!(
            failure_threshold,
            "periodic self-test hysteresis: /healthz flips to 503 only after \
             this many consecutive failures (set periodic_self_test_failure_threshold=1 \
             for legacy single-failure-drain)"
        );
        // Deadline for each cycle = the interval itself (max
        // bound; a cycle that takes longer than the interval is
        // operationally a hang). Cap at 30s for sanity so an
        // operator who sets a long interval (e.g. 600s) doesn't
        // wait forever for a failing test to time out.
        let cycle_deadline = std::time::Duration::from_secs(periodic_interval_secs.min(30));
        let metrics_for_test = Arc::clone(&metrics);
        let config_path = config_path.to_path_buf();
        info!(
            interval_secs = periodic_interval_secs,
            cycle_deadline_secs = cycle_deadline.as_secs(),
            "periodic self-test wired (background cycle + /healthz integration)"
        );
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(periodic_interval_secs));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // Hysteresis helper: every failure path calls this. It
            // bumps the failed-total + streak counters, and flips
            // /healthz=503 ONLY when the streak crosses the
            // configured threshold. Threshold=0 or 1 = legacy
            // single-failure-drain (no hysteresis). Returns the
            // post-bump streak so the caller can format the log
            // line with "1/2", "2/2", etc.
            let bump_failure = |reason: &str, err_msg: String| -> u64 {
                use std::sync::atomic::Ordering;
                metrics_for_test
                    .periodic_self_test_failed_total
                    .fetch_add(1, Ordering::Relaxed);
                let streak = metrics_for_test
                    .consecutive_periodic_self_test_failures
                    .fetch_add(1, Ordering::Relaxed)
                    + 1;
                let threshold = metrics_for_test
                    .periodic_self_test_failure_threshold
                    .load(Ordering::Relaxed)
                    .max(1);
                if streak >= threshold {
                    // Threshold crossed — flip /healthz=503.
                    metrics_for_test
                        .last_periodic_self_test_passed
                        .store(false, Ordering::Relaxed);
                    error!(
                        reason,
                        error = %err_msg,
                        streak,
                        threshold,
                        "periodic self-test: consecutive-failure streak hit threshold — \
                         /healthz now returning 503"
                    );
                } else {
                    // Under the threshold — log a warn so
                    // operators see the deteriorating signal,
                    // but DON'T drop /healthz. The next pass
                    // resets the streak.
                    warn!(
                        reason,
                        error = %err_msg,
                        streak,
                        threshold,
                        "periodic self-test failed but within hysteresis window — \
                         /healthz still 200 (one more failure drains)"
                    );
                }
                streak
            };
            // Success path: reset the streak, mark passed=true.
            let mark_success = |outcome: &proteus_server::startup_self_test::SelfTestOutcome| {
                use std::sync::atomic::Ordering;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let prev_streak = metrics_for_test
                    .consecutive_periodic_self_test_failures
                    .swap(0, Ordering::Relaxed);
                metrics_for_test
                    .last_periodic_self_test_passed
                    .store(true, Ordering::Relaxed);
                metrics_for_test
                    .last_periodic_self_test_unix_seconds
                    .store(now, Ordering::Relaxed);
                if prev_streak > 0 {
                    info!(
                        previous_streak = prev_streak,
                        "periodic self-test recovered — streak reset, /healthz remains 200"
                    );
                }
                // Only INFO-log on unusual durations; otherwise
                // the loop is too chatty for journald.
                if outcome.total > std::time::Duration::from_millis(100) {
                    info!(
                        total_ms = outcome.total.as_millis() as u64,
                        handshake_ms = outcome.handshake.as_millis() as u64,
                        roundtrip_ms = outcome.roundtrip.as_millis() as u64,
                        "periodic self-test passed (note: > 100ms — investigate)"
                    );
                }
            };
            loop {
                interval.tick().await;
                metrics_for_test
                    .periodic_self_test_attempts_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let fresh_keys = match ServerConfig::load(&config_path).await {
                    Ok(c) => match load_server_keys(&c) {
                        Ok(k) => k,
                        Err(e) => {
                            bump_failure("key_reload", e.to_string());
                            continue;
                        }
                    },
                    Err(e) => {
                        bump_failure("config_reload", e.to_string());
                        continue;
                    }
                };
                match proteus_server::startup_self_test::run_self_test(fresh_keys, cycle_deadline)
                    .await
                {
                    Ok(outcome) => mark_success(&outcome),
                    Err(e) => {
                        bump_failure("self_test", e.to_string());
                    }
                }
            }
        });
    } else {
        info!(
            "periodic_self_test_interval_secs unset/0 — /healthz returns 200 \
             based on accept-loop liveness alone. For production, set a value \
             (e.g. 60) so /healthz reflects live crypto health."
        );
    }

    // TLS cert file mtime watcher (optional). Polls the cert/key
    // file mtimes every N seconds; if either changed, fires an
    // auto-reload through the same reload_with_expiry path that
    // SIGHUP uses. Closes the "non-Let's-Encrypt operator
    // forgets to signal after rotation" gap.
    let watcher_interval_secs = cfg.tls_cert_watcher_interval_secs.unwrap_or(0);
    #[allow(clippy::collapsible_match, clippy::collapsible_if)]
    match (
        watcher_interval_secs,
        tls_cert_watcher.as_ref(),
        reloadable_acceptor.as_ref(),
        cfg.tls.as_ref(),
    ) {
        (0, _, _, _) => {
            if cfg.tls.is_some() {
                info!(
                    "tls_cert_watcher_interval_secs unset/0 — operators using \
                     non-Let's-Encrypt cert rotations should set this (e.g. 60) \
                     so Proteus picks up renewed certs without a SIGHUP"
                );
            }
        }
        (interval, Some(watcher), Some(reloadable), Some(tls_cfg)) => {
            let watcher = Arc::clone(watcher);
            let reloadable = reloadable.clone();
            let cert_path = tls_cfg.cert_chain.clone();
            let key_path = tls_cfg.private_key.clone();
            info!(
                interval_secs = interval,
                cert = ?cert_path,
                "TLS cert file-mtime watcher wired (auto-reload on disk-rotate)"
            );
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(interval));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tick.tick().await;
                    if watcher.check_and_record().is_none() {
                        continue;
                    }
                    watcher.record_attempt();
                    info!(
                        cert = ?cert_path,
                        key = ?key_path,
                        "tls_cert_watcher: mtime change detected — reloading"
                    );
                    let load_result = (|| {
                        let chain = proteus_transport_alpha::tls::load_cert_chain(&cert_path)
                            .map_err(|e| format!("load_cert_chain: {e}"))?;
                        let key = proteus_transport_alpha::tls::load_private_key(&key_path)
                            .map_err(|e| format!("load_private_key: {e}"))?;
                        let acceptor =
                            proteus_transport_alpha::tls::build_acceptor(chain.clone(), key)
                                .map_err(|e| format!("build_acceptor: {e}"))?;
                        Ok::<_, String>((chain, acceptor))
                    })();
                    match load_result {
                        Ok((chain, acceptor)) => {
                            match reloadable.reload_with_expiry(acceptor, &chain) {
                                Ok(()) => {
                                    watcher.record_success();
                                    info!(
                                        not_after_unix = reloadable.leaf_not_after(),
                                        "tls_cert_watcher: auto-reload succeeded"
                                    );
                                }
                                Err(e) => {
                                    // Acceptor IS swapped in;
                                    // only the leaf parse failed.
                                    // Count as failure for the
                                    // operator's "alert on broken
                                    // deploy" workflow.
                                    watcher.record_failure();
                                    error!(
                                        error = %e,
                                        "tls_cert_watcher: leaf cert DER parse failed; expiry gauge held stale"
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            watcher.record_failure();
                            error!(
                                error = %e,
                                "tls_cert_watcher: auto-reload FAILED; old cert continues serving traffic"
                            );
                        }
                    }
                }
            });
        }
        _ => {
            // No `tls:` block configured — watcher would have
            // nothing to watch. Already warned above.
        }
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
        // Hold a metrics ref inside the SIGHUP task so it can bump
        // the 8 new reload counters (4 sections × {attempts,
        // succeeded}). Existing TLS-reload counters already live on
        // `reloadable_acceptor`; this brings the firewall + 3 rate-
        // limit reloads to the same observability bar.
        let metrics_for_reload = Arc::clone(&metrics);
        // Hold the quarantine list so SIGHUP can reconcile the
        // in-memory map against the on-disk persistence file —
        // operators hand-edit the file (lift a false-positive,
        // add an emergency manual ban, extend a TTL) and SIGHUP
        // picks it up without a restart.
        let user_quarantine_for_reload = user_quarantine_list.as_ref().map(Arc::clone);
        let user_quotas_for_reload = user_quotas_list.as_ref().map(Arc::clone);
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
                info!(
                    "SIGHUP received — reloading TLS cert, firewall rules, \
                     rate limits, and user_quarantine state"
                );

                // sd_notify(RELOADING=1) — tells systemd we're in
                // the middle of a reload cycle. `systemctl status`
                // now shows "reloading" instead of "active
                // (running)" while we work, and any service
                // ordered `After=proteus-server.service` that
                // happens to be probing knows to wait. The READY=1
                // at the bottom of this loop body flips us back to
                // "active". MUST be paired — leaving RELOADING=1
                // hanging would pin the unit in the reloading
                // state until the next restart.
                let _ = proteus_sd_notify::notify_reloading().await;
                let _ = proteus_sd_notify::notify_status("reloading config (SIGHUP)").await;

                // ----- 1. TLS cert reload (if configured) -----
                if let (Some(tls_cfg), Some(reloadable)) =
                    (tls_cfg_path.as_ref(), reloadable_acceptor.as_ref())
                {
                    match (
                        proteus_transport_alpha::tls::load_cert_chain(&tls_cfg.cert_chain),
                        proteus_transport_alpha::tls::load_private_key(&tls_cfg.private_key),
                    ) {
                        (Ok(chain), Ok(key)) => {
                            match proteus_transport_alpha::tls::build_acceptor(chain.clone(), key) {
                                Ok(new_acceptor) => {
                                    // Use `reload_with_expiry` so the
                                    // `proteus_tls_cert_not_after_unix_seconds`
                                    // gauge refreshes to the freshly-
                                    // renewed cert's notAfter AND the
                                    // success counter bumps. The legacy
                                    // `reload` path would leave both
                                    // stale, hiding silent rotation
                                    // failures from the operator.
                                    match reloadable.reload_with_expiry(new_acceptor, &chain) {
                                        Ok(()) => {
                                            info!(
                                                cert = ?tls_cfg.cert_chain,
                                                not_after_unix = reloadable.leaf_not_after(),
                                                "TLS cert reloaded"
                                            );
                                        }
                                        Err(e) => {
                                            // Acceptor IS swapped in
                                            // (reload_with_expiry's
                                            // documented behavior); the
                                            // notAfter gauge held its
                                            // previous value because
                                            // leaf parsing failed.
                                            // Surface so the operator
                                            // can re-issue.
                                            error!(
                                                error = %e,
                                                "TLS reload: leaf cert DER parse failed — \
                                                 acceptor swapped, expiry gauge held stale"
                                            );
                                        }
                                    }
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
                //
                // Each reload bumps its own attempts_total counter
                // upfront (so an operator who SIGHUPed knows the
                // signal reached us, even if the YAML re-read failed
                // and we never reached the per-section logic).
                // Per-section *_reload_succeeded_total is bumped
                // only on successful hot-swap — operators alert on
                // `attempts - succeeded` to catch silent reload
                // failures.
                use std::sync::atomic::Ordering;
                let m = &metrics_for_reload;
                m.firewall_reload_attempts.fetch_add(1, Ordering::Relaxed);
                m.rate_limit_reload_attempts.fetch_add(1, Ordering::Relaxed);
                m.user_rate_limit_reload_attempts
                    .fetch_add(1, Ordering::Relaxed);
                m.handshake_budget_reload_attempts
                    .fetch_add(1, Ordering::Relaxed);
                match config::ServerConfig::load(&config_path).await {
                    Ok(fresh_cfg) => {
                        // 2a. Firewall.
                        match fresh_cfg.firewall.as_ref() {
                            Some(fw_cfg) => match build_firewall_from_cfg(fw_cfg) {
                                Ok(new_fw) => {
                                    let rules = new_fw.rule_count();
                                    firewall_handle.reload(new_fw);
                                    m.firewall_reload_succeeded.fetch_add(1, Ordering::Relaxed);
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
                                m.firewall_reload_succeeded.fetch_add(1, Ordering::Relaxed);
                                info!("firewall block removed from config; rules cleared");
                            }
                        }

                        // 2b. Per-IP rate-limit hot-swap.
                        //
                        // Iter-41 false-positive fix: bump succeeded
                        // on EVERY non-failure outcome so the
                        // (attempts - succeeded) gap is a true
                        // failure signal, not a "the operator
                        // doesn't use this section" signal.
                        // Pre-iter-41 every SIGHUP from an operator
                        // who didn't configure rate_limit bumped
                        // attempts but never succeeded → gap grew
                        // forever → ProteusRateLimitReloadFailing
                        // (iter-38 alert) fired permanently as a
                        // false positive. The "edit ignored — no
                        // limiter at startup" branch ALSO now bumps
                        // succeeded; that's still warn!-logged so
                        // the operator sees the message in journal,
                        // but we don't pin a perma-alert on it.
                        match fresh_cfg.rate_limit.as_ref() {
                            Some(rl) => {
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
                                m.rate_limit_reload_succeeded
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                            None => {
                                // No rate_limit block in config — nothing to do.
                                // Count as success (the reload attempt completed
                                // without error; there was nothing to reload).
                                m.rate_limit_reload_succeeded
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                        }

                        // 2c. Per-user rate-limit hot-swap.
                        match fresh_cfg.user_rate_limit.as_ref() {
                            Some(u) => {
                                if ctx_for_reload.reload_user_rate_limit(u.burst, u.refill_per_sec)
                                {
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
                                m.user_rate_limit_reload_succeeded
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                            None => {
                                m.user_rate_limit_reload_succeeded
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                        }

                        // 2d. Global handshake-budget hot-swap.
                        match fresh_cfg.handshake_budget.as_ref() {
                            Some(b) => {
                                if ctx_for_reload.reload_handshake_budget(b.burst, b.refill_per_sec)
                                {
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
                                m.handshake_budget_reload_succeeded
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                            None => {
                                m.handshake_budget_reload_succeeded
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    Err(e) => {
                        error!(error = %e, "config re-read failed; keeping old firewall + rate-limit state");
                    }
                }

                // ----- 3. User-quarantine reconcile from disk -----
                //
                // Operators hand-edit /var/lib/proteus/user_quarantine.jsonl
                // (lift a false-positive ban by deleting a line,
                // add an emergency manual ban, extend a TTL) and
                // SIGHUP picks the edits up without a restart.
                // The reconciliation is bidirectional (file is
                // canonical) — see `reload_from_disk` docstring.
                if let Some(qlist) = user_quarantine_for_reload.as_ref() {
                    match qlist.reload_from_disk() {
                        Ok(outcome) => {
                            if outcome.added > 0
                                || outcome.removed > 0
                                || outcome.refreshed > 0
                                || outcome.malformed > 0
                            {
                                info!(
                                    added = outcome.added,
                                    removed = outcome.removed,
                                    refreshed = outcome.refreshed,
                                    skipped_expired = outcome.skipped_expired,
                                    malformed = outcome.malformed,
                                    "user_quarantine reconciled from disk"
                                );
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, "user_quarantine reload failed; keeping in-memory state");
                        }
                    }
                }

                // ----- 4. User-quota reconcile from disk -----
                //
                // Operators can hand-edit
                // /var/lib/proteus/user_quotas.jsonl to grant a
                // fresh allotment, change a cap_override, etc.
                // SIGHUP picks the edits up.
                if let Some(qt) = user_quotas_for_reload.as_ref() {
                    match qt.reload_from_disk() {
                        Ok(updates) if updates > 0 => {
                            info!(updates, "user_quotas reconciled from disk");
                        }
                        Ok(_) => {}
                        Err(e) => {
                            warn!(error = %e, "user_quotas reload failed; keeping in-memory state");
                        }
                    }
                }

                // sd_notify(READY=1) — flip systemd back to
                // "active". Surface a STATUS line summarizing the
                // outcome so `systemctl status` reflects the
                // reload result without needing to grep journalctl.
                // The summary reads the metric counters that the
                // section handlers above bumped.
                let m = &metrics_for_reload;
                use std::sync::atomic::Ordering as O;
                let fw_at = m.firewall_reload_attempts.load(O::Relaxed);
                let fw_ok = m.firewall_reload_succeeded.load(O::Relaxed);
                let rl_at = m.rate_limit_reload_attempts.load(O::Relaxed);
                let rl_ok = m.rate_limit_reload_succeeded.load(O::Relaxed);
                let any_fail = fw_at > fw_ok || rl_at > rl_ok;
                let summary = if any_fail {
                    format!(
                        "SIGHUP reload completed with FAILURES (firewall {fw_ok}/{fw_at}, \
                         rate_limit {rl_ok}/{rl_at}) — see journalctl for details"
                    )
                } else {
                    format!(
                        "ready (last SIGHUP succeeded: firewall {fw_ok}/{fw_at}, \
                         rate_limit {rl_ok}/{rl_at})"
                    )
                };
                let _ = proteus_sd_notify::notify_ready().await;
                let _ = proteus_sd_notify::notify_status(&summary).await;
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
            // Publish the shared stats Arc to the process-global
            // OnceLock so the /metrics live_blocks closure (set up
            // earlier in main, before this access_log spawn) can
            // emit the writer health + records-by-outcome series.
            proteus_server::process_access_log_stats::set(logger.stats());
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
        abuse_fires: Some(Arc::clone(&abuse_fires_buffer)),
        user_quarantine: user_quarantine_list.as_ref().map(Arc::clone),
        quarantine_on_byte_budget: cfg
            .user_quarantine
            .as_ref()
            .map(|q| q.on_kinds.iter().any(|k| k == "byte_budget"))
            .unwrap_or(false),
        outbound_filter: outbound_filter.clone(),
        dns_resolver_stats: Some(Arc::clone(&dns_resolver_stats)),
        pad_quantum: cfg.pad_quantum,
        // Reuse the same `tcp_keepalive_secs` knob the accept-loop
        // uses for client-facing sockets — operators who tuned it
        // for an aggressive-NAT environment expect symmetric
        // treatment on the upstream egress side too.
        tcp_keepalive_secs: cfg.tcp_keepalive_secs,
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
                // Hold a second ctx Arc for the per-session
                // closure so we can pull the per-user bandwidth
                // accumulator off it on each session completion.
                let ctx_beta_for_metrics = Arc::clone(&ctx);
                let on_session_beta =
                    move |session: proteus_transport_alpha::session::AlphaSession<
                        quinn::RecvStream,
                        quinn::SendStream,
                    >| {
                        let metrics = Arc::clone(&metrics_beta);
                        let relay_cfg = relay_cfg_beta.clone();
                        let ctx_pu = Arc::clone(&ctx_beta_for_metrics);
                        async move {
                            metrics
                                .sessions_accepted
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            metrics
                                .handshakes_succeeded
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            observe_handshake_latency(&metrics, session.handshake_duration);
                            // Per-user concurrent-session cap. On
                            // reject the session is torn down without
                            // paying the relay cost.
                            let _conn_guard = match check_per_user_conn_cap(
                                ctx_pu.per_user_conn_limiter().as_ref(),
                                session.user_id,
                            ) {
                                ConnCapDecision::Allow(g) => g,
                                ConnCapDecision::Reject { user_id, cap } => {
                                    warn!(
                                        user_id = %proteus_transport_alpha::per_user_bandwidth::render_user_id_pub(&user_id),
                                        cap,
                                        "β session rejected: user_id at per-user concurrent-session cap"
                                    );
                                    return;
                                }
                            };
                            // Hold the LIVE session metrics so the
                            // drop snapshot reflects final byte totals
                            // (snapshotting at enter would always
                            // merge zero — caught by the multi-user
                            // soak in 2026-05-18).
                            let session_metrics = Arc::clone(&session.metrics);
                            // Wire per-user bandwidth if both the
                            // accumulator AND the session's user_id
                            // are present — degrades gracefully to
                            // the back-compat enter() when either
                            // is missing.
                            let _guard = match (
                                ctx_pu.per_user_bandwidth().cloned(),
                                session.user_id,
                            ) {
                                (Some(pu), Some(uid)) => {
                                    proteus_transport_alpha::metrics::InFlightGuard::enter_with_per_user(
                                        Arc::clone(&metrics),
                                        session_metrics,
                                        pu,
                                        uid,
                                    )
                                }
                                _ => proteus_transport_alpha::metrics::InFlightGuard::enter(
                                    Arc::clone(&metrics),
                                    session_metrics,
                                ),
                            };
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
        let ctx_tcp_for_metrics = Arc::clone(&ctx);
        let on_session_tcp = move |session: proteus_transport_alpha::session::AlphaSession| {
            let metrics = Arc::clone(&metrics_tcp);
            let relay_cfg = relay_cfg_tcp.clone();
            let ctx_pu = Arc::clone(&ctx_tcp_for_metrics);
            async move {
                metrics
                    .sessions_accepted
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                metrics
                    .handshakes_succeeded
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                observe_handshake_latency(&metrics, session.handshake_duration);
                // Per-user concurrent-session cap.
                let _conn_guard = match check_per_user_conn_cap(
                    ctx_pu.per_user_conn_limiter().as_ref(),
                    session.user_id,
                ) {
                    ConnCapDecision::Allow(g) => g,
                    ConnCapDecision::Reject { user_id, cap } => {
                        warn!(
                            user_id = %proteus_transport_alpha::per_user_bandwidth::render_user_id_pub(&user_id),
                            cap,
                            "session rejected: user_id at per-user concurrent-session cap"
                        );
                        return;
                    }
                };
                // RAII guard: increments in_flight_sessions; decrements
                // AND merges per-session totals on drop, even if the
                // handler future panics. Wires per-user accounting
                // when both the accumulator + user_id are present.
                // Holds the LIVE Arc<SessionMetrics> so the drop-time
                // snapshot captures actual byte totals (not the
                // all-zero enter state).
                let session_metrics = Arc::clone(&session.metrics);
                let _guard = match (ctx_pu.per_user_bandwidth().cloned(), session.user_id) {
                    (Some(pu), Some(uid)) => {
                        proteus_transport_alpha::metrics::InFlightGuard::enter_with_per_user(
                            Arc::clone(&metrics),
                            session_metrics,
                            pu,
                            uid,
                        )
                    }
                    _ => proteus_transport_alpha::metrics::InFlightGuard::enter(
                        Arc::clone(&metrics),
                        session_metrics,
                    ),
                };
                if let Err(e) = relay::handle_session(session, relay_cfg).await {
                    warn!(error = %e, "session terminated");
                }
            }
        };
        match reloadable_acceptor.clone() {
            Some(acceptor) => {
                if dispatch_cfg.psk.is_some() {
                    // Path A enabled — use the gated accept loop.
                    // Closure body is identical to the legacy path
                    // below, only the TLS stream type differs
                    // (TlsStream<PrependedStream> instead of
                    // TlsStream<TcpStream>). We build only this
                    // closure in this arm so the closure-captured
                    // Arcs (metrics, ctx) aren't moved into a
                    // never-used legacy closure first.
                    let metrics_gate = Arc::clone(&metrics);
                    let relay_cfg_gate = relay_cfg.clone();
                    let ctx_gate_for_metrics = Arc::clone(&ctx);
                    let on_session_tls_gated =
                        move |session: proteus_transport_alpha::session::AlphaSession<
                            tokio::io::ReadHalf<proteus_transport_alpha::tls::GatedServerStream>,
                            tokio::io::WriteHalf<proteus_transport_alpha::tls::GatedServerStream>,
                        >| {
                            let metrics = Arc::clone(&metrics_gate);
                            let relay_cfg = relay_cfg_gate.clone();
                            let ctx_pu = Arc::clone(&ctx_gate_for_metrics);
                            async move {
                                metrics
                                    .sessions_accepted
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                metrics
                                    .handshakes_succeeded
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                observe_handshake_latency(&metrics, session.handshake_duration);
                                let _conn_guard = match check_per_user_conn_cap(
                                    ctx_pu.per_user_conn_limiter().as_ref(),
                                    session.user_id,
                                ) {
                                    ConnCapDecision::Allow(g) => g,
                                    ConnCapDecision::Reject { user_id, cap } => {
                                        warn!(
                                            user_id = %proteus_transport_alpha::per_user_bandwidth::render_user_id_pub(&user_id),
                                            cap,
                                            "Path-A TLS session rejected: user_id at per-user concurrent-session cap"
                                        );
                                        return;
                                    }
                                };
                                let session_metrics = Arc::clone(&session.metrics);
                                let _guard = match (
                                ctx_pu.per_user_bandwidth().cloned(),
                                session.user_id,
                            ) {
                                (Some(pu), Some(uid)) => {
                                    proteus_transport_alpha::metrics::InFlightGuard::enter_with_per_user(
                                        Arc::clone(&metrics),
                                        session_metrics,
                                        pu,
                                        uid,
                                    )
                                }
                                _ => proteus_transport_alpha::metrics::InFlightGuard::enter(
                                    Arc::clone(&metrics),
                                    session_metrics,
                                ),
                            };
                                if let Err(e) = relay::handle_session(session, relay_cfg).await {
                                    warn!(error = %e, "Path-A TLS session terminated");
                                }
                            }
                        };
                    Box::pin(server::serve_tls_reloadable_with_gate(
                        listener,
                        ctx,
                        acceptor,
                        Arc::clone(&dispatch_cfg),
                        on_session_tls_gated,
                    ))
                } else {
                    let metrics = Arc::clone(&metrics);
                    let relay_cfg_tls = relay_cfg.clone();
                    let ctx_tls_for_metrics = Arc::clone(&ctx);
                    let on_session_tls =
                        move |session: proteus_transport_alpha::session::AlphaSession<
                            tokio::io::ReadHalf<proteus_transport_alpha::tls::ServerStream>,
                            tokio::io::WriteHalf<proteus_transport_alpha::tls::ServerStream>,
                        >| {
                            let metrics = Arc::clone(&metrics);
                            let relay_cfg = relay_cfg_tls.clone();
                            let ctx_pu = Arc::clone(&ctx_tls_for_metrics);
                            async move {
                                metrics
                                    .sessions_accepted
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                metrics
                                    .handshakes_succeeded
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                observe_handshake_latency(&metrics, session.handshake_duration);
                                let _conn_guard = match check_per_user_conn_cap(
                                    ctx_pu.per_user_conn_limiter().as_ref(),
                                    session.user_id,
                                ) {
                                    ConnCapDecision::Allow(g) => g,
                                    ConnCapDecision::Reject { user_id, cap } => {
                                        warn!(
                                            user_id = %proteus_transport_alpha::per_user_bandwidth::render_user_id_pub(&user_id),
                                            cap,
                                            "TLS session rejected: user_id at per-user concurrent-session cap"
                                        );
                                        return;
                                    }
                                };
                                // Live Arc<SessionMetrics> — snapshotted at
                                // guard drop so the merge reflects the
                                // session's final byte totals.
                                let session_metrics = Arc::clone(&session.metrics);
                                let _guard = match (
                                    ctx_pu.per_user_bandwidth().cloned(),
                                    session.user_id,
                                ) {
                                    (Some(pu), Some(uid)) => {
                                        proteus_transport_alpha::metrics::InFlightGuard::enter_with_per_user(
                                            Arc::clone(&metrics),
                                            session_metrics,
                                            pu,
                                            uid,
                                        )
                                    }
                                    _ => proteus_transport_alpha::metrics::InFlightGuard::enter(
                                        Arc::clone(&metrics),
                                        session_metrics,
                                    ),
                                };
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
            // Tell systemd we're draining BEFORE the drain loop so
            // `TimeoutStopSec=` accounting starts from STOPPING=1.
            // Without this, systemd would consider us "exiting
            // normally" at process-end time only, and any drain
            // longer than the default TimeoutStopSec (90s) gets
            // SIGKILL'd mid-flight.
            let _ = proteus_sd_notify::notify_stopping().await;
            let _ = proteus_sd_notify::notify_status(&format!(
                "draining {} session(s)",
                metrics.in_flight_sessions.load(std::sync::atomic::Ordering::Relaxed)
            )).await;
            // Cancel the watchdog ping cycle. Once we're
            // draining, systemd shouldn't restart-on-timeout —
            // we're already supposed to be going away.
            watchdog_cancel.notify_one();
            info!(
                secs = drain_secs,
                in_flight = metrics.in_flight_sessions.load(std::sync::atomic::Ordering::Relaxed),
                "draining outstanding sessions, /readyz now reports 503"
            );

            // Wait for ALL in-flight sessions to drain — but bound
            // by drain_secs as a hard ceiling. Previously this was
            // an unconditional `tokio::time::sleep(drain_secs)`,
            // which had two operational problems:
            //
            //   1. If sessions finished in <drain_secs, the binary
            //      still slept the full window — slow rolling
            //      restarts, systemd TimeoutStopSec margin wasted.
            //   2. If sessions took >drain_secs, they were killed
            //      mid-flight without a chance to even log the
            //      truncation.
            //
            // Now we poll the in_flight_sessions counter on a tight
            // tick. As soon as it hits zero we exit (fast restart);
            // if drain_secs elapses with sessions still in flight,
            // we log the count and exit anyway (preserving the
            // hard upper-bound systemd expects via TimeoutStopSec).
            let drain_fut = async {
                loop {
                    let n = metrics
                        .in_flight_sessions
                        .load(std::sync::atomic::Ordering::Relaxed);
                    if n == 0 {
                        return;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            };
            match tokio::time::timeout(
                std::time::Duration::from_secs(drain_secs),
                drain_fut,
            )
            .await
            {
                Ok(()) => info!("drain complete (zero in-flight), exiting"),
                Err(_) => {
                    let still_running = metrics
                        .in_flight_sessions
                        .load(std::sync::atomic::Ordering::Relaxed);
                    warn!(
                        in_flight = still_running,
                        drain_secs,
                        "drain window elapsed with sessions still in flight; exiting anyway. \
                         Production deployment should bump drain_secs OR audit why sessions \
                         are not finishing within the configured window."
                    );
                }
            }

            // Final liveness flip — we are about to exit; any further
            // /healthz probe should see 503.
            metrics.alive.store(false, std::sync::atomic::Ordering::Relaxed);

            // Record this exit as CLEAN in the persistent restart
            // tracker. The next start sees `previous_run_unclean = 0`
            // and dashboards distinguish this restart from a panic/
            // OOM/segfault loop. Skipped when the operator hasn't
            // configured `restart_state_file:` (tracker is None).
            if let Some(rt) = restart_tracker.as_ref() {
                rt.mark_clean_shutdown();
            }

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
    // Build the PerfProfile from server.yaml β tunables. Defaults
    // match `PerfProfile::default()` (initial_mtu = 1350, no UDP
    // padding) — operators flip on `beta_pad_quic_to_mtu: true` in
    // production anti-censorship deployments.
    let mut perf = proteus_transport_beta::PerfProfile::default();
    if let Some(v) = cfg.beta_initial_mtu {
        perf.initial_mtu = v;
    }
    if let Some(v) = cfg.beta_minimum_mtu {
        perf.minimum_mtu = v;
    }
    if let Some(v) = cfg.beta_pad_quic_to_mtu {
        perf.pad_quic_datagrams_to_mtu = v;
    }
    if let Some(v) = cfg.beta_allow_spin_bit {
        perf.allow_spin_bit = v;
    }
    if let Some(v) = cfg.beta_ack_eliciting_threshold {
        perf.ack_eliciting_threshold = v;
    }
    if let Some(v) = cfg.beta_mtu_upper_bound {
        perf.mtu_upper_bound = v;
    }
    if cfg.beta_congestion.as_deref() == Some("brutal") {
        perf.congestion = proteus_transport_beta::CongestionKind::Brutal;
        perf.brutal_target_bps = cfg
            .beta_brutal_target_mbps
            .expect("validated: brutal target is required")
            .saturating_mul(1_000_000);
    }
    let endpoint = proteus_transport_beta::server::make_endpoint_with_perf(bind, chain, key, perf)
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

/// Outcome of [`check_per_user_conn_cap`]. Allow wraps the
/// RAII guard whose drop releases the slot; Reject carries the
/// user_id + cap so the caller can render the structured WARN log
/// without re-fetching state.
enum ConnCapDecision {
    /// Cap was not installed, or a slot was acquired. The Option
    /// inside the variant is `None` for the "limiter not installed"
    /// case and `Some(guard)` for the "acquired" case — both are
    /// handled uniformly by the caller (drop at session-end).
    Allow(Option<proteus_transport_alpha::per_user_conn_limit::PerUserConnGuard>),
    /// The user_id was already at the per-user cap. The caller MUST
    /// tear down the session WITHOUT routing to `cover_endpoint` —
    /// the user authenticated successfully; routing to cover would
    /// mis-leadingly imply auth-fail.
    Reject { user_id: [u8; 8], cap: usize },
}

/// Observe a handshake's wall-clock duration into the histogram on `ServerMetrics`. No-op when the duration field isn't populated (legacy in-memory test sessions).
fn observe_handshake_latency(
    metrics: &proteus_transport_alpha::metrics::ServerMetrics,
    handshake_duration: Option<std::time::Duration>,
) {
    if let Some(d) = handshake_duration {
        metrics.handshake_duration_seconds.observe(d);
    }
}

/// Check the per-user concurrent-session cap. Three-valued return:
///   - limiter not installed (None) → Allow(None)
///   - session has no user_id (e.g. pre-allowlist) → Allow(None)
///     (the limiter is gated on having a user_id; without one, this
///     cap has nothing to attribute against and falls through)
///   - acquired → Allow(Some(guard))
///   - rejected → Reject { user_id, cap }
fn check_per_user_conn_cap(
    limiter: Option<
        &std::sync::Arc<proteus_transport_alpha::per_user_conn_limit::PerUserConnLimiter>,
    >,
    user_id: Option<[u8; 8]>,
) -> ConnCapDecision {
    let (Some(limiter), Some(uid)) = (limiter, user_id) else {
        return ConnCapDecision::Allow(None);
    };
    match limiter.try_acquire(uid) {
        proteus_transport_alpha::per_user_conn_limit::AcquireOutcome::Acquired(g) => {
            ConnCapDecision::Allow(Some(g))
        }
        proteus_transport_alpha::per_user_conn_limit::AcquireOutcome::Rejected { current } => {
            ConnCapDecision::Reject {
                user_id: uid,
                cap: current,
            }
        }
    }
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
