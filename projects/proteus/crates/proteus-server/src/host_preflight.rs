//! `proteus-server preflight check-host` — offline host-posture audit.
//!
//! ## Why this exists
//!
//! `preflight check-ip-reputation` covers the *IP* axis of "is this
//! VPS a good place to deploy Proteus", but the *host* axis is a
//! separate failure mode operators trip on after a clean apt-install:
//!
//! - **File permissions on private keys**: `ml-kem.sk`, `x25519.sk`,
//!   and the TLS `privkey.pem` mode 0644 instead of 0600 means any
//!   local user on a shared VPS reads the long-term identity keys.
//!   The binary doesn't *check* the mode at startup (rustls / our key
//!   loader read whatever's on disk), so the operator can silently
//!   deploy with world-readable PQ keys.
//! - **`fs.file-max` / ulimit `nofile`**: the systemd unit sets
//!   `LimitNOFILE=1048576` but the operator might run from a tmux
//!   shell with the distro default 1024. A few thousand concurrent
//!   sessions and the accept loop EMFILEs — visible only as
//!   "connections being silently rejected" without a clear cause.
//! - **`net.core.rmem_max` / `wmem_max`**: β QUIC's 64 MiB stream
//!   window depends on the kernel accepting `setsockopt(SO_RCVBUF)`
//!   above the default ~200 KiB. Ubuntu 22.04 ships with 212992;
//!   above that the kernel silently clamps and BBR can't fill the
//!   path. Operators see "β throughput is half of α" with no log
//!   line explaining why.
//! - **TCP congestion control**: BBR availability for the OS-side
//!   TCP stack matters for α's underlying TLS connections feeding
//!   high-BDP paths. Default `cubic` is fine; flagging the
//!   "available + not selected" case as INFO lets operators flip it.
//! - **`/dev/urandom` available**: ring's CSPRNG falls back to
//!   `getrandom(2)`, which fails on stripped containers. Catch the
//!   broken jail at preflight, not at the first handshake.
//! - **Disk free on state dir**: the per-IP rate-limit map + auto-
//!   deny list don't persist to disk, but the `nonce_window_state`
//!   file (when enabled) does. < 100 MiB free is a CRIT for any
//!   long-lived deploy because the state file rotates.
//! - **Clock skew vs. NTP**: Proteus's anti-replay window has a 90 s
//!   skew tolerance. If `chronyd` / `systemd-timesyncd` is broken
//!   and the wall clock is 5 min off, every fresh handshake fails
//!   with a misleading "replay" verdict.
//!
//! All checks are **read-only** — no sysctl writes, no chmod, no
//! state mutation. Reports findings; the operator fixes.
//!
//! ## Cross-platform behaviour
//!
//! Designed for **Linux production deployment**. On macOS (developer
//! laptops), Linux-only checks (`/proc/sys/...`, `/dev/urandom` path
//! semantics, BBR sysctl) report `Pass` with an "(skipped on macOS)"
//! qualifier rather than `Fail`. Test fixtures run on both. This
//! means a macOS operator running the preflight on their dev box
//! sees only the cross-platform findings (key file modes, disk free),
//! exactly as intended.

use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::ip_reputation::Severity;

/// One finding in the host-posture report.
#[derive(Debug, Clone)]
pub struct HostFinding {
    /// Short check name (`key_file_modes`, `nofile_ulimit`, ...).
    pub check: String,
    /// Severity classification — Pass/Warn/Fail (matches the IP-reputation
    /// preflight's `Severity` enum so the CLI's summary line is symmetric).
    pub severity: Severity,
    /// Human-readable explanation including the observed value and
    /// (for Warn/Fail) the recommended fix.
    pub message: String,
}

impl HostFinding {
    fn pass(check: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            check: check.into(),
            severity: Severity::Pass,
            message: message.into(),
        }
    }
    fn warn(check: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            check: check.into(),
            severity: Severity::Warn,
            message: message.into(),
        }
    }
    fn fail(check: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            check: check.into(),
            severity: Severity::Fail,
            message: message.into(),
        }
    }
}

/// Aggregate report.
#[derive(Debug, Clone, Default)]
pub struct HostReport {
    pub findings: Vec<HostFinding>,
}

impl HostReport {
    pub fn push(&mut self, f: HostFinding) {
        self.findings.push(f);
    }

    /// Exit-code-relevant: true iff any finding is `Severity::Fail`.
    #[must_use]
    pub fn has_failures(&self) -> bool {
        self.findings.iter().any(|f| f.severity == Severity::Fail)
    }

    /// `(passes, warns, fails)` counts for the summary line.
    #[must_use]
    pub fn counts(&self) -> (usize, usize, usize) {
        let (mut p, mut w, mut f) = (0, 0, 0);
        for x in &self.findings {
            match x.severity {
                Severity::Pass => p += 1,
                Severity::Warn => w += 1,
                Severity::Fail => f += 1,
            }
        }
        (p, w, f)
    }
}

impl fmt::Display for HostReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for x in &self.findings {
            writeln!(
                f,
                "  {sev:<4} [{check}] {msg}",
                sev = x.severity,
                check = x.check,
                msg = x.message,
            )?;
        }
        let (p, w, fa) = self.counts();
        writeln!(f, "\nsummary: {p} pass, {w} warn, {fa} fail")
    }
}

/// Input bundle. Mirrors `PreflightInput` for consistency.
#[derive(Debug, Default)]
pub struct HostPreflightInput {
    /// Path to YAML config (used to extract key file paths +
    /// nonce-window state file path for mode + disk-free checks).
    /// Optional — when absent, key-file checks are skipped.
    pub config_path: Option<PathBuf>,
    /// Override the `proc_root` (default `/proc`) — test-fixture
    /// hook so unit tests can drop a synthetic procfs in a tmpdir.
    pub proc_root_override: Option<PathBuf>,
    /// Override the `state_dir` (default: dir of config) — test
    /// hook to point disk-free at a known volume.
    pub state_dir_override: Option<PathBuf>,
}

/// Run every host-posture check; assemble a [`HostReport`].
pub fn run(input: HostPreflightInput) -> HostReport {
    let mut r = HostReport::default();

    // Key-file mode check — only when a config is available (the
    // key file paths come from the YAML).
    if let Some(cfg_path) = input.config_path.as_ref() {
        check_key_file_modes(cfg_path, &mut r);
    } else {
        r.push(HostFinding::pass(
            "key_file_modes",
            "skipped — no --config supplied (re-run with --config to audit \
             /etc/proteus/*.sk and tls/privkey.pem modes)",
        ));
    }

    // Linux-only sysctl/proc checks. On macOS / non-Linux these
    // become PASS-with-"(skipped on $os)" so the summary doesn't
    // confuse dev-laptop users.
    let proc_root = input
        .proc_root_override
        .clone()
        .unwrap_or_else(|| PathBuf::from("/proc"));
    check_nofile_ulimit(&mut r);
    check_so_rmem_wmem_max(&proc_root, &mut r);
    check_tcp_congestion_control(&proc_root, &mut r);
    check_urandom_available(&mut r);
    check_clock_sync(&mut r);

    // Disk-free check uses state_dir override or dir of config.
    let state_dir = input
        .state_dir_override
        .clone()
        .or_else(|| {
            input
                .config_path
                .as_ref()
                .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        })
        .unwrap_or_else(|| PathBuf::from("."));
    check_disk_free(&state_dir, &mut r);

    r
}

// ────────────────────────────────────────────────────────────────
// Individual checks
// ────────────────────────────────────────────────────────────────

/// Verify every key file referenced by the config is mode 0600 (read+
/// write by owner only). World-readable PQ secret keys on a shared
/// VPS is the worst kind of silent compromise.
fn check_key_file_modes(cfg_path: &Path, r: &mut HostReport) {
    let text = match std::fs::read_to_string(cfg_path) {
        Ok(t) => t,
        Err(e) => {
            r.push(HostFinding::fail(
                "key_file_modes",
                format!("could not read config {}: {e}", cfg_path.display()),
            ));
            return;
        }
    };

    // Pull every file-path-looking value out of the YAML keys block.
    // We don't `serde_yaml::from_str::<ServerConfig>` here because
    // that fails on a half-edited file (missing client_allowlist
    // etc.) and we want the preflight to still surface the
    // permissions issue. A line-grep over `^  key_name: "./path"`
    // is "wrong" in pathological YAML but correct for the schema
    // operators actually ship.
    let mut candidates: Vec<(String, PathBuf)> = Vec::new();
    let interesting_keys = [
        "mlkem_pk",
        "mlkem_sk",
        "x25519_pk",
        "x25519_sk",
        "ed25519_pk",
        "ed25519_sk",
        "cert_chain",
        "private_key",
        "metrics_token_file",
    ];
    for line in text.lines() {
        let trimmed = line.trim_start();
        for key in &interesting_keys {
            let needle = format!("{key}:");
            if let Some(rest) = trimmed.strip_prefix(&needle) {
                let val = rest.trim().trim_matches('"').trim_matches('\'').to_string();
                if !val.is_empty() {
                    // Resolve relative paths against the config's dir.
                    let base = cfg_path.parent().unwrap_or_else(|| Path::new("."));
                    let resolved = if Path::new(&val).is_absolute() {
                        PathBuf::from(&val)
                    } else {
                        base.join(&val)
                    };
                    candidates.push((key.to_string(), resolved));
                }
            }
        }
    }

    if candidates.is_empty() {
        r.push(HostFinding::warn(
            "key_file_modes",
            "no key-file paths found in config — check that keys.* and \
             tls.* blocks are populated (this preflight expects the \
             standard schema)",
        ));
        return;
    }

    // For each candidate: stat, classify by Unix mode bits.
    let mut total_checked = 0usize;
    let mut violations = 0usize;
    for (key, path) in &candidates {
        match key_file_mode(path) {
            Ok(KeyFileVerdict::Mode0600) => total_checked += 1,
            Ok(KeyFileVerdict::ModePublicSecret { mode }) => {
                violations += 1;
                r.push(HostFinding::fail(
                    "key_file_modes",
                    format!(
                        "SECRET key file {} has mode {mode:#o} — world or group \
                         readable. PQ identity exposure. Fix: `chmod 0600 {}`",
                        path.display(),
                        path.display()
                    ),
                ));
            }
            Ok(KeyFileVerdict::ModePublicArtifact { mode }) => {
                total_checked += 1;
                // Public certs / PKs are intentionally world-readable; mode
                // 0644 is fine. We don't flag.
                let _ = mode; // explicit "we considered it"
            }
            Ok(KeyFileVerdict::Missing) => {
                violations += 1;
                r.push(HostFinding::fail(
                    "key_file_modes",
                    format!(
                        "key file {} ({key}) does not exist — config will \
                         fail to load at startup. Run `proteus-server keygen` \
                         or fix the path in the config",
                        path.display()
                    ),
                ));
            }
            Ok(KeyFileVerdict::NotAFile) => {
                r.push(HostFinding::warn(
                    "key_file_modes",
                    format!(
                        "{} ({key}) exists but is not a regular file (symlink \
                         to nonexistent target? directory?) — manual review",
                        path.display()
                    ),
                ));
            }
            Err(e) => {
                r.push(HostFinding::warn(
                    "key_file_modes",
                    format!("could not stat {}: {e}", path.display()),
                ));
            }
        }
    }
    if violations == 0 {
        r.push(HostFinding::pass(
            "key_file_modes",
            format!(
                "{total_checked} key file{plural} mode-checked — secrets are \
                 0600, public artifacts are 0644 (acceptable)",
                plural = if total_checked == 1 { "" } else { "s" }
            ),
        ));
    }
}

enum KeyFileVerdict {
    /// Secret key with mode 0600 — the expected, safe state.
    Mode0600,
    /// Secret key with overly-permissive mode (any group/other read bit set).
    ModePublicSecret { mode: u32 },
    /// Public artifact (cert, pk, metrics token) — mode is allowed
    /// to be 0644 / world-readable; we record but don't warn.
    ModePublicArtifact { mode: u32 },
    /// File doesn't exist.
    Missing,
    /// Path exists but isn't a regular file.
    NotAFile,
}

fn key_file_mode(path: &Path) -> std::io::Result<KeyFileVerdict> {
    if !path.exists() {
        return Ok(KeyFileVerdict::Missing);
    }
    let meta = std::fs::metadata(path)?;
    if !meta.is_file() {
        return Ok(KeyFileVerdict::NotAFile);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        let is_secret = is_secret_key_path(path);
        if is_secret {
            // For secrets: anything but 0600 is too loose. We accept
            // 0400 (read-only owner, the strictest) and 0600.
            if mode == 0o600 || mode == 0o400 {
                Ok(KeyFileVerdict::Mode0600)
            } else {
                Ok(KeyFileVerdict::ModePublicSecret { mode })
            }
        } else {
            Ok(KeyFileVerdict::ModePublicArtifact { mode })
        }
    }
    #[cfg(not(unix))]
    {
        // Windows / WASM — no Unix mode bits. Return "public artifact"
        // so the check passes silently rather than spuriously failing.
        let _ = meta;
        Ok(KeyFileVerdict::ModePublicArtifact { mode: 0 })
    }
}

/// Decide whether a key-file path holds a SECRET (must be 0600) or
/// a public artifact (cert chain, PK, token — 0644 is fine).
///
/// Decision is by filename suffix / contained substring — the YAML
/// schema names secrets with `_sk` or `private_key` or `_token`,
/// and public artifacts with `_pk` or `cert_chain`.
fn is_secret_key_path(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    name.contains(".sk")
        || name.contains("_sk")
        || name.contains("sk.")
        || name == "privkey.pem"
        || name.contains("private")
        || name.contains("token")
}

/// Check the process's RLIMIT_NOFILE soft limit. systemd unit sets
/// 1048576; running from a shell often inherits 1024 from PAM.
fn check_nofile_ulimit(r: &mut HostReport) {
    #[cfg(unix)]
    {
        let (soft, hard) = match get_rlimit_nofile() {
            Ok(t) => t,
            Err(e) => {
                r.push(HostFinding::warn(
                    "nofile_ulimit",
                    format!("getrlimit(RLIMIT_NOFILE) failed: {e}"),
                ));
                return;
            }
        };
        if soft >= 65536 {
            r.push(HostFinding::pass(
                "nofile_ulimit",
                format!(
                    "RLIMIT_NOFILE soft={soft} hard={hard} — comfortably \
                     above the 65k Proteus needs for a few thousand \
                     concurrent sessions"
                ),
            ));
        } else if soft >= 4096 {
            r.push(HostFinding::warn(
                "nofile_ulimit",
                format!(
                    "RLIMIT_NOFILE soft={soft} hard={hard} — sufficient for \
                     small deploys; raise to 65536+ for any deploy expecting \
                     >2k concurrent users. systemd unit ships `LimitNOFILE=1048576`."
                ),
            ));
        } else {
            r.push(HostFinding::fail(
                "nofile_ulimit",
                format!(
                    "RLIMIT_NOFILE soft={soft} — at this limit the accept loop \
                     will EMFILE under any load. Run from systemd (sets 1048576) \
                     or `ulimit -n 65536` before launching."
                ),
            ));
        }
    }
    #[cfg(not(unix))]
    {
        r.push(HostFinding::pass("nofile_ulimit", "skipped on non-Unix"));
    }
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn get_rlimit_nofile() -> std::io::Result<(u64, u64)> {
    // SAFETY: getrlimit is a standard POSIX syscall; we pass a properly
    // sized rlimit struct and read the integer fields back.
    unsafe {
        let mut rl: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) == 0 {
            Ok((rl.rlim_cur as u64, rl.rlim_max as u64))
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}

/// Linux sysctl: `net.core.rmem_max` and `wmem_max`. β QUIC's BBR
/// can't fill high-BDP paths if these are at the Ubuntu 22.04 default
/// 212992 (~200 KiB). Recommend ≥ 16 MiB.
fn check_so_rmem_wmem_max(proc_root: &Path, r: &mut HostReport) {
    if !is_linux() {
        r.push(HostFinding::pass(
            "so_rmem_wmem_max",
            "skipped — Linux-only (no procfs sysctl)",
        ));
        return;
    }
    let rmem = read_sysctl(proc_root, "net/core/rmem_max").ok();
    let wmem = read_sysctl(proc_root, "net/core/wmem_max").ok();
    match (rmem, wmem) {
        (Some(rm), Some(wm)) => {
            const TARGET: u64 = 16 * 1024 * 1024;
            if rm >= TARGET && wm >= TARGET {
                r.push(HostFinding::pass(
                    "so_rmem_wmem_max",
                    format!(
                        "net.core.rmem_max={rm}, wmem_max={wm} — ≥16 MiB; \
                         β QUIC BBR can saturate high-BDP paths"
                    ),
                ));
            } else {
                r.push(HostFinding::warn(
                    "so_rmem_wmem_max",
                    format!(
                        "net.core.rmem_max={rm}, wmem_max={wm} — below 16 MiB \
                         target. β QUIC's 64 MiB stream window will silently \
                         clamp. Fix: `sysctl -w net.core.rmem_max=16777216 \
                         net.core.wmem_max=16777216` (persist in /etc/sysctl.d/)"
                    ),
                ));
            }
        }
        _ => {
            r.push(HostFinding::warn(
                "so_rmem_wmem_max",
                "could not read net.core.rmem_max / wmem_max — procfs \
                 unavailable or non-standard layout",
            ));
        }
    }
}

/// Linux: report which TCP congestion controls are loaded and which
/// is the system default. BBR is INFO-level: not required, but useful
/// if available.
fn check_tcp_congestion_control(proc_root: &Path, r: &mut HostReport) {
    if !is_linux() {
        r.push(HostFinding::pass(
            "tcp_congestion_control",
            "skipped — Linux-only",
        ));
        return;
    }
    let avail =
        std::fs::read_to_string(proc_root.join("sys/net/ipv4/tcp_available_congestion_control"))
            .ok()
            .map(|s| s.trim().to_string());
    let current = std::fs::read_to_string(proc_root.join("sys/net/ipv4/tcp_congestion_control"))
        .ok()
        .map(|s| s.trim().to_string());
    match (avail, current) {
        (Some(a), Some(c)) => {
            let bbr_loaded = a.split_whitespace().any(|x| x == "bbr");
            if c == "bbr" {
                r.push(HostFinding::pass(
                    "tcp_congestion_control",
                    format!(
                        "tcp_congestion_control={c} (system default, BBR active) \
                         — α TLS over high-BDP paths gets BBR's pacing"
                    ),
                ));
            } else if bbr_loaded {
                r.push(HostFinding::warn(
                    "tcp_congestion_control",
                    format!(
                        "tcp_congestion_control={c} (BBR available but not selected). \
                         For high-BDP intercontinental paths α will hold less \
                         throughput than it could. Fix: `sysctl -w \
                         net.ipv4.tcp_congestion_control=bbr` (persist in \
                         /etc/sysctl.d/). Available: [{a}]"
                    ),
                ));
            } else {
                r.push(HostFinding::warn(
                    "tcp_congestion_control",
                    format!(
                        "tcp_congestion_control={c}; BBR module not loaded \
                         (available: [{a}]). On modern kernels: \
                         `modprobe tcp_bbr` then set the sysctl above. β \
                         QUIC uses its own BBR via quinn, unaffected."
                    ),
                ));
            }
        }
        _ => {
            r.push(HostFinding::warn(
                "tcp_congestion_control",
                "could not read /proc/sys/net/ipv4/tcp_congestion_control",
            ));
        }
    }
}

/// Verify `/dev/urandom` is openable. ring's CSPRNG ultimately calls
/// `getrandom(2)`, but stripped containers (`FROM scratch` without
/// `--device /dev/random`) sometimes don't expose either.
fn check_urandom_available(r: &mut HostReport) {
    let path = Path::new("/dev/urandom");
    if path.exists() {
        // Try a 1-byte read to surface permission/device-not-ready.
        match std::fs::File::open(path) {
            Ok(mut f) => {
                use std::io::Read;
                let mut buf = [0u8; 1];
                match f.read_exact(&mut buf) {
                    Ok(_) => r.push(HostFinding::pass(
                        "urandom",
                        "/dev/urandom readable — RNG path available",
                    )),
                    Err(e) => r.push(HostFinding::fail(
                        "urandom",
                        format!(
                            "/dev/urandom exists but read failed: {e}. ring's \
                             CSPRNG will fail at first handshake."
                        ),
                    )),
                }
            }
            Err(e) => r.push(HostFinding::fail(
                "urandom",
                format!(
                    "/dev/urandom cannot be opened: {e}. Likely a stripped \
                     container — mount `--device /dev/urandom` or use a \
                     distro base image."
                ),
            )),
        }
    } else {
        r.push(HostFinding::fail(
            "urandom",
            "/dev/urandom does not exist. ring's CSPRNG cannot initialize.",
        ));
    }
}

/// Wall-clock skew check. We can't actually verify NTP sync without
/// querying a time server (would leak operator metadata), so the
/// check is: "is the wall clock within a sane range of the build-
/// time epoch we baked in?" CRIT if it's earlier than the binary's
/// build epoch by more than a few days (clock badly wrong),
/// WARN if no-clock-sync indicator file present.
fn check_clock_sync(r: &mut HostReport) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // We can't pin a build-time epoch without a build script; instead
    // pin a known-historical lower bound: this codebase started 2026,
    // so any wall-clock < 2026-01-01 means the host clock is wrong.
    const PROTEUS_REPO_EPOCH: u64 = 1_735_689_600; // 2025-01-01 UTC, very conservative lower bound
    if now < PROTEUS_REPO_EPOCH {
        r.push(HostFinding::fail(
            "clock_sync",
            format!(
                "wall clock = {now} (< 2025-01-01 epoch). NTP almost \
                 certainly broken. Proteus's 90 s anti-replay skew window \
                 means every handshake will FAIL with a misleading \
                 'replay' verdict. Fix: `timedatectl status` and ensure \
                 `chronyd` or `systemd-timesyncd` is active."
            ),
        ));
        return;
    }
    // Linux: check `/run/systemd/timesync/synchronized` (systemd-timesyncd)
    // or `/var/lib/chrony/drift` (chronyd) as best-effort sync evidence.
    let sd_synced = Path::new("/run/systemd/timesync/synchronized").exists();
    let chrony_active = Path::new("/var/lib/chrony/drift").exists()
        || Path::new("/var/lib/chrony/chrony.drift").exists();
    if sd_synced {
        r.push(HostFinding::pass(
            "clock_sync",
            "systemd-timesyncd has synchronized (touch /run/systemd/timesync/\
             synchronized present)",
        ));
    } else if chrony_active {
        r.push(HostFinding::pass(
            "clock_sync",
            "chronyd appears active (drift file present); manual `chronyc \
             tracking` confirms current state",
        ));
    } else if cfg!(target_os = "linux") {
        r.push(HostFinding::warn(
            "clock_sync",
            "no systemd-timesyncd or chronyd sync indicator found. Cannot \
             rule out clock skew. Run `timedatectl status` to verify; \
             without NTP the 90 s replay window will reject legitimate \
             clients.",
        ));
    } else {
        // Non-Linux: just confirm the wall clock is plausible.
        r.push(HostFinding::pass(
            "clock_sync",
            "skipped sync-indicator check (non-Linux); wall clock looks \
             plausible (≥ 2025-01-01)",
        ));
    }
}

/// Disk free on the state directory. < 100 MiB free fails because
/// the nonce_window state file (if configured) needs headroom to
/// rotate.
fn check_disk_free(state_dir: &Path, r: &mut HostReport) {
    match disk_free_bytes(state_dir) {
        Ok(free) => {
            const MIN_OK: u64 = 100 * 1024 * 1024;
            const TARGET_OK: u64 = 1024 * 1024 * 1024;
            if free >= TARGET_OK {
                r.push(HostFinding::pass(
                    "disk_free",
                    format!(
                        "{} has {} MiB free — comfortable headroom for \
                         nonce-window state, journald logs, certbot renewals",
                        state_dir.display(),
                        free / (1024 * 1024)
                    ),
                ));
            } else if free >= MIN_OK {
                r.push(HostFinding::warn(
                    "disk_free",
                    format!(
                        "{} has only {} MiB free. Sufficient for current \
                         state, but a few days of journald logs + a cert \
                         renewal will exhaust it. Provision more.",
                        state_dir.display(),
                        free / (1024 * 1024)
                    ),
                ));
            } else {
                r.push(HostFinding::fail(
                    "disk_free",
                    format!(
                        "{} has only {} bytes free. State file rotation \
                         WILL fail; certbot renewals will fail; journald \
                         will rotate-and-drop logs. Do not deploy here.",
                        state_dir.display(),
                        free,
                    ),
                ));
            }
        }
        Err(e) => r.push(HostFinding::warn(
            "disk_free",
            format!("could not statfs {}: {e}", state_dir.display()),
        )),
    }
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn disk_free_bytes(path: &Path) -> std::io::Result<u64> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let cpath = CString::new(path.as_os_str().as_bytes()).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("path NUL: {e}"))
    })?;
    // SAFETY: statvfs is a POSIX syscall; the buffer is properly sized.
    unsafe {
        let mut s: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(cpath.as_ptr(), &mut s) == 0 {
            Ok((s.f_bavail as u64).saturating_mul(s.f_frsize as u64))
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}

#[cfg(not(unix))]
fn disk_free_bytes(_path: &Path) -> std::io::Result<u64> {
    // Best-effort fallback; on non-Unix the check still surfaces a
    // PASS so the rest of the report is comparable.
    Ok(u64::MAX)
}

fn read_sysctl(proc_root: &Path, rel: &str) -> std::io::Result<u64> {
    let p = proc_root.join("sys").join(rel);
    let s = std::fs::read_to_string(&p)?;
    let val: u64 = s.split_whitespace().next().unwrap_or("0").parse().map_err(
        |e: std::num::ParseIntError| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
        },
    )?;
    Ok(val)
}

fn is_linux() -> bool {
    cfg!(target_os = "linux")
}

/// CLI entry. Writes the report to stdout and returns exit-code
/// (0 on PASS+WARN-only, 1 on any FAIL).
pub fn cli_run(input: HostPreflightInput) -> std::io::Result<i32> {
    let report = run(input);
    let stdout = std::io::stdout();
    let mut h = stdout.lock();
    write!(h, "{report}")?;
    Ok(if report.has_failures() { 1 } else { 0 })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(suffix: &str) -> PathBuf {
        let base = std::env::var("CARGO_TARGET_TMPDIR").unwrap_or_else(|_| "/tmp".to_string());
        let p = PathBuf::from(format!(
            "{base}/proteus-host-preflight-{suffix}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn report_summary_counts_correctly() {
        let mut r = HostReport::default();
        r.push(HostFinding::pass("a", "ok"));
        r.push(HostFinding::warn("b", "meh"));
        r.push(HostFinding::warn("c", "meh"));
        r.push(HostFinding::fail("d", "bad"));
        assert_eq!(r.counts(), (1, 2, 1));
        assert!(r.has_failures());
    }

    #[test]
    fn empty_input_runs_some_default_checks_and_does_not_panic() {
        // Without a config we skip key-file checks. The other checks
        // (urandom, disk_free, ulimit, clock) still run.
        let report = run(HostPreflightInput::default());
        // At minimum: urandom + ulimit + disk_free are platform-portable.
        // We don't assert exact PASS/FAIL since the runner's machine
        // determines those, but we DO assert that the suite produced
        // at least 4 findings (proves we ran more than one check).
        assert!(
            report.findings.len() >= 4,
            "expected ≥4 findings, got: {:?}",
            report.findings
        );
    }

    #[test]
    fn cli_run_returns_exit_1_when_any_fail() {
        // Inject a synthetic "fail" by pointing state_dir at a path
        // that doesn't exist (statvfs fails → WARN, not FAIL). To
        // force FAIL deterministically, point key_file_modes at a
        // config with a missing key file.
        let dir = tmp("missing-key");
        let cfg = dir.join("server.yaml");
        std::fs::write(
            &cfg,
            "listen_alpha: \"127.0.0.1:8443\"\nkeys:\n  mlkem_sk: ./does-not-exist.sk\n",
        )
        .unwrap();
        let input = HostPreflightInput {
            config_path: Some(cfg),
            ..Default::default()
        };
        let report = run(input);
        assert!(
            report.has_failures(),
            "missing key file must FAIL: {:?}",
            report.findings
        );
    }

    #[cfg(unix)]
    #[test]
    fn secret_key_with_world_readable_mode_fails() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp("perms");
        let cfg = dir.join("server.yaml");
        let sk = dir.join("test.sk");
        std::fs::write(&sk, b"fake-secret-bytes").unwrap();
        // Write the file 0644 (world-readable secret).
        std::fs::set_permissions(&sk, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::write(
            &cfg,
            format!(
                "listen_alpha: \"127.0.0.1:8443\"\nkeys:\n  mlkem_sk: \"{}\"\n",
                sk.display()
            ),
        )
        .unwrap();
        let report = run(HostPreflightInput {
            config_path: Some(cfg),
            ..Default::default()
        });
        let mode_fail = report
            .findings
            .iter()
            .find(|f| f.check == "key_file_modes" && f.severity == Severity::Fail)
            .expect("expected a key_file_modes FAIL");
        assert!(
            mode_fail.message.contains("world or group readable"),
            "fail message should explain why: {}",
            mode_fail.message
        );
    }

    #[cfg(unix)]
    #[test]
    fn secret_key_with_0600_mode_passes() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp("0600");
        let cfg = dir.join("server.yaml");
        let sk = dir.join("test.sk");
        std::fs::write(&sk, b"fake-secret-bytes").unwrap();
        std::fs::set_permissions(&sk, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(
            &cfg,
            format!(
                "listen_alpha: \"127.0.0.1:8443\"\nkeys:\n  mlkem_sk: \"{}\"\n",
                sk.display()
            ),
        )
        .unwrap();
        let report = run(HostPreflightInput {
            config_path: Some(cfg),
            ..Default::default()
        });
        // No FAIL in key_file_modes.
        let has_fail = report
            .findings
            .iter()
            .any(|f| f.check == "key_file_modes" && f.severity == Severity::Fail);
        assert!(
            !has_fail,
            "0600 secret should not FAIL: {:?}",
            report.findings
        );
    }

    #[test]
    fn public_key_artifact_with_0644_is_not_flagged() {
        // A `.pk` file with mode 0644 is fine (public material).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir = tmp("pk-mode");
            let cfg = dir.join("server.yaml");
            let pk = dir.join("test.pk");
            std::fs::write(&pk, b"fake-public-bytes").unwrap();
            std::fs::set_permissions(&pk, std::fs::Permissions::from_mode(0o644)).unwrap();
            std::fs::write(
                &cfg,
                format!(
                    "listen_alpha: \"127.0.0.1:8443\"\nkeys:\n  mlkem_pk: \"{}\"\n",
                    pk.display()
                ),
            )
            .unwrap();
            let report = run(HostPreflightInput {
                config_path: Some(cfg),
                ..Default::default()
            });
            // No FAIL on key_file_modes for a 0644 public key.
            let has_fail = report
                .findings
                .iter()
                .any(|f| f.check == "key_file_modes" && f.severity == Severity::Fail);
            assert!(
                !has_fail,
                "0644 PUBLIC key must not FAIL: {:?}",
                report.findings
            );
        }
    }

    #[test]
    fn synthetic_proc_root_with_high_rmem_passes_socket_buffer_check() {
        // Drop a fake /proc tree showing 16 MiB+ socket buffers and
        // verify the check classifies as PASS.
        if !cfg!(target_os = "linux") {
            // On non-Linux the check is skipped regardless of override.
            return;
        }
        let dir = tmp("proc-rmem-ok");
        let sys = dir.join("sys/net/core");
        std::fs::create_dir_all(&sys).unwrap();
        std::fs::write(sys.join("rmem_max"), "16777216\n").unwrap();
        std::fs::write(sys.join("wmem_max"), "16777216\n").unwrap();
        let report = run(HostPreflightInput {
            proc_root_override: Some(dir),
            ..Default::default()
        });
        let f = report
            .findings
            .iter()
            .find(|f| f.check == "so_rmem_wmem_max")
            .expect("so_rmem_wmem_max finding expected");
        assert_eq!(f.severity, Severity::Pass, "16 MiB rmem must PASS: {f:?}");
    }

    #[test]
    fn synthetic_proc_root_with_low_rmem_warns_about_quic_clamp() {
        if !cfg!(target_os = "linux") {
            return;
        }
        let dir = tmp("proc-rmem-low");
        let sys = dir.join("sys/net/core");
        std::fs::create_dir_all(&sys).unwrap();
        // Ubuntu 22.04 default
        std::fs::write(sys.join("rmem_max"), "212992\n").unwrap();
        std::fs::write(sys.join("wmem_max"), "212992\n").unwrap();
        let report = run(HostPreflightInput {
            proc_root_override: Some(dir),
            ..Default::default()
        });
        let f = report
            .findings
            .iter()
            .find(|f| f.check == "so_rmem_wmem_max")
            .expect("so_rmem_wmem_max finding expected");
        assert_eq!(f.severity, Severity::Warn);
        assert!(
            f.message.contains("clamp"),
            "warn must explain QUIC clamp: {f:?}"
        );
    }

    #[test]
    fn is_secret_key_path_classifies_known_filenames() {
        assert!(is_secret_key_path(Path::new("foo.sk")));
        assert!(is_secret_key_path(Path::new("mlkem.sk")));
        assert!(is_secret_key_path(Path::new("privkey.pem")));
        assert!(is_secret_key_path(Path::new("metrics_token.txt")));
        assert!(!is_secret_key_path(Path::new("foo.pk")));
        assert!(!is_secret_key_path(Path::new("ed25519.pk")));
        assert!(!is_secret_key_path(Path::new("fullchain.pem")));
    }
}
