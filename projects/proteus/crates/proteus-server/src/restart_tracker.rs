//! Persistent restart history — make systemd-restart loops visible.
//!
//! ## Why this exists
//!
//! When proteus-server crashes (panic+abort, OOM kill, segfault
//! inside a dep, RUST_PANIC_ABORT=1 hot-path panic), systemd
//! `Restart=on-failure` faithfully relaunches the binary. The new
//! process starts clean — `proteus_panics_total = 0`,
//! `proteus_process_uptime_seconds = small`, `/healthz` green.
//!
//! From the dashboard, a box that's been up cleanly for a week
//! and a box that's crash-looping once every 30 seconds look
//! **identical**: both green, both fresh. The operator finds out
//! only when the user complains, or when journalctl is grepped
//! manually for "started session".
//!
//! This module persists a tiny piece of state across restarts —
//! a JSON file under `state_dir` recording:
//!
//!   1. The total number of starts since the state file was
//!      created (`restart_count`).
//!   2. The Unix timestamp of the FIRST start ever (`first_start_unix`).
//!   3. The Unix timestamp of the most-recent CLEAN shutdown
//!      (`last_clean_shutdown_unix`, 0 if never).
//!   4. The Unix timestamp of the previous start
//!      (`previous_start_unix`, 0 on first-ever run).
//!   5. A short reason string explaining how the previous run
//!      ended, when the binary can determine it
//!      (`previous_end_reason` — `clean`, `unclean`, or `unknown`).
//!
//! On every startup the module:
//!   * Reads the prior file (creates one if absent).
//!   * Notices the previous run's exit was UNCLEAN if its
//!     `last_clean_shutdown_unix < previous_start_unix` — i.e.
//!     the binary started but never wrote a clean-shutdown marker.
//!   * Increments `restart_count` and rewrites the file.
//!   * Exposes the whole state vector via `/metrics`:
//!       - `proteus_restarts_total` (counter)
//!       - `proteus_first_start_unix_seconds` (gauge)
//!       - `proteus_last_clean_shutdown_unix_seconds` (gauge,
//!         0 when none)
//!       - `proteus_previous_run_unclean` (0/1 gauge)
//!
//! On graceful shutdown (SIGTERM caught by the existing drain
//! task) the binary calls `mark_clean_shutdown()` which writes
//! the current `now()` into `last_clean_shutdown_unix`. Operators
//! alert on:
//!
//!   * `rate(proteus_restarts_total[1h]) > 1` — restart-loop bug
//!   * `proteus_previous_run_unclean == 1` AND fresh start
//!     within the last 5 min — single crash within the alert
//!     window, worth investigating even if the loop didn't
//!     develop
//!
//! ## Why a separate file, not the journal
//!
//! `journalctl -u proteus-server` already has every start/stop
//! line, but parsing it requires either operator-side
//! `journalctl --output=json | jq ...` or pulling the systemd
//! API. A 200-byte JSON file the binary owns is simpler, doesn't
//! depend on systemd at all (works for `tmux`-launched
//! deployments + container restarts where systemd is absent),
//! and the existing /metrics scrape path delivers it to the
//! dashboard without any external tooling.
//!
//! ## Concurrency + atomic write
//!
//! Writes use tempfile + `rename(2)` — same atomic-replacement
//! pattern the existing `user_quarantine_state.jsonl` persistence
//! uses. No other process writes this file (the binary holds the
//! state-dir directory by convention), so no advisory locking is
//! needed. A partial write that gets `kill -9`'d mid-rename
//! leaves the OLD file intact; the worst-case is the next start
//! sees stale counters by 1.
//!
//! ## What this is NOT
//!
//! - **Not a crash-log shipper.** This file only counts; if you
//!   want backtraces and panic messages, that's already in the
//!   journal via `proteus-panic-hook` (which emits a structured
//!   tracing event before the process aborts).
//! - **Not an exit-cause classifier.** We can detect "previous
//!   run didn't mark clean shutdown" but we can't tell apart
//!   panic-abort, OOM kill, segfault, or `kill -9`. All three
//!   show up as `previous_run_unclean = 1`.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

/// In-process snapshot of the restart-tracker state. Built once
/// at startup, then handed (as `Arc<RestartTracker>`) to the
/// metrics layer for /metrics rendering. The Arc lets graceful-
/// shutdown code in `main()` keep a reference so it can call
/// `mark_clean_shutdown` BEFORE the process exits.
#[derive(Debug)]
pub struct RestartTracker {
    /// Where the JSON state file lives. We keep it so
    /// `mark_clean_shutdown` knows where to atomically write
    /// without re-deriving the path.
    path: PathBuf,
    /// Cumulative restart count since the file was first created.
    /// Equal to 1 on the very first ever start.
    restart_count: u64,
    /// First-ever startup time (preserved across restarts).
    first_start_unix: u64,
    /// Unix time of the previous CLEAN shutdown, or 0 if there
    /// hasn't been one. Updated by `mark_clean_shutdown` on the
    /// current run.
    last_clean_shutdown_unix: AtomicU64,
    /// Did the previous run exit cleanly? Detected at startup;
    /// stays constant for the lifetime of this process.
    previous_run_unclean: bool,
    /// Unix time of the current start (≈ process start). Stored
    /// so it can be re-persisted on graceful shutdown without
    /// re-querying the clock.
    current_start_unix: u64,
}

/// JSON schema we persist. `serde` would be a heavier dep than
/// this state file warrants; we use a hand-rolled minimal
/// formatter (4 numeric fields + one short string) and a
/// minimal parser. Future-proof: unknown JSON keys are ignored
/// on read.
#[derive(Debug, Default)]
struct StateFile {
    restart_count: u64,
    first_start_unix: u64,
    last_clean_shutdown_unix: u64,
    previous_start_unix: u64,
    /// Always one of `clean` / `unclean` / `unknown`. We don't
    /// strongly type this — it's only displayed by /diagnose.
    previous_end_reason: String,
}

impl RestartTracker {
    /// Initialize the tracker. Reads (or creates) the state file
    /// at `path`, increments the counter, persists the bump, and
    /// returns the populated tracker.
    ///
    /// Errors are folded into the Tracker as a "synthetic" first
    /// start (counter=1, first_start=now, previous_unclean=false) +
    /// a warn-level log line — restart tracking is observability,
    /// not safety-critical, so I/O failures must not block server
    /// startup.
    pub fn init(path: PathBuf) -> Arc<Self> {
        let now = now_unix();
        let prior = load(&path).unwrap_or_default();

        // Detect "previous run didn't mark clean shutdown".
        // True when there WAS a previous start AND the last clean
        // shutdown is older than that previous start. First-ever
        // run (prior.restart_count == 0) → false (no previous run).
        let previous_run_unclean =
            prior.restart_count > 0 && prior.last_clean_shutdown_unix < prior.previous_start_unix;

        let new_count = prior.restart_count.saturating_add(1);
        let first_start_unix = if prior.first_start_unix == 0 {
            now
        } else {
            prior.first_start_unix
        };

        // Persist the bumped counters immediately. If this run
        // crashes before mark_clean_shutdown, the NEXT run will
        // see previous_start_unix=now, last_clean=prior, and
        // correctly classify this run as unclean.
        let bumped = StateFile {
            restart_count: new_count,
            first_start_unix,
            last_clean_shutdown_unix: prior.last_clean_shutdown_unix,
            previous_start_unix: now,
            previous_end_reason: if previous_run_unclean {
                "unclean".to_string()
            } else if prior.restart_count == 0 {
                "first_start".to_string()
            } else {
                "clean".to_string()
            },
        };
        if let Err(e) = save(&path, &bumped) {
            tracing::warn!(
                target: "proteus_server::restart_tracker",
                path = ?path,
                error = %e,
                "could not persist restart-tracker state — running with in-memory state only"
            );
        }
        if previous_run_unclean {
            tracing::warn!(
                target: "proteus_server::restart_tracker",
                restart_count = new_count,
                previous_start_unix = prior.previous_start_unix,
                last_clean_shutdown_unix = prior.last_clean_shutdown_unix,
                "previous run exited UNCLEANLY (panic-abort, OOM kill, segfault, or kill -9) — \
                 check journalctl for proteus_panic events around the previous start"
            );
        } else {
            tracing::info!(
                target: "proteus_server::restart_tracker",
                restart_count = new_count,
                first_start_unix,
                "restart-tracker initialized"
            );
        }

        Arc::new(Self {
            path,
            restart_count: new_count,
            first_start_unix,
            last_clean_shutdown_unix: AtomicU64::new(prior.last_clean_shutdown_unix),
            previous_run_unclean,
            current_start_unix: now,
        })
    }

    /// Record that the current process is shutting down cleanly.
    /// Called from the SIGTERM / drain handler BEFORE the process
    /// exits. Re-persists the state file with
    /// `last_clean_shutdown_unix = now()`.
    pub fn mark_clean_shutdown(&self) {
        let now = now_unix();
        self.last_clean_shutdown_unix.store(now, Ordering::Relaxed);
        let to_write = StateFile {
            restart_count: self.restart_count,
            first_start_unix: self.first_start_unix,
            last_clean_shutdown_unix: now,
            previous_start_unix: self.current_start_unix,
            previous_end_reason: "clean".to_string(),
        };
        if let Err(e) = save(&self.path, &to_write) {
            tracing::warn!(
                target: "proteus_server::restart_tracker",
                error = %e,
                "could not persist clean-shutdown marker — next start will misclassify as unclean"
            );
        }
    }

    /// Current restart count (1-indexed: first ever start = 1).
    #[must_use]
    pub fn restart_count(&self) -> u64 {
        self.restart_count
    }

    /// First-ever start timestamp.
    #[must_use]
    pub fn first_start_unix(&self) -> u64 {
        self.first_start_unix
    }

    /// Most-recent clean shutdown timestamp (or 0).
    #[must_use]
    pub fn last_clean_shutdown_unix(&self) -> u64 {
        self.last_clean_shutdown_unix.load(Ordering::Relaxed)
    }

    /// Did the previous run exit uncleanly?
    #[must_use]
    pub fn previous_run_unclean(&self) -> bool {
        self.previous_run_unclean
    }

    /// Render the Prometheus block. Always emits all four series
    /// so dashboards don't see gauges flickering present/absent.
    #[must_use]
    pub fn prometheus(&self) -> String {
        format!(
            "# HELP proteus_restarts_total Cumulative process starts since the restart-tracker state file was first created. Alert on rate(...[1h]) > 1 = restart loop.\n\
             # TYPE proteus_restarts_total counter\n\
             proteus_restarts_total {restart_count}\n\
             # HELP proteus_first_start_unix_seconds Unix timestamp of the FIRST-ever process start (preserved across restarts).\n\
             # TYPE proteus_first_start_unix_seconds gauge\n\
             proteus_first_start_unix_seconds {first_start_unix}\n\
             # HELP proteus_last_clean_shutdown_unix_seconds Unix timestamp of the most-recent CLEAN shutdown (SIGTERM caught + drain ran). 0 = no clean shutdown recorded yet.\n\
             # TYPE proteus_last_clean_shutdown_unix_seconds gauge\n\
             proteus_last_clean_shutdown_unix_seconds {last_clean}\n\
             # HELP proteus_previous_run_unclean 1 if the previous process exited uncleanly (panic-abort, OOM kill, segfault, kill -9). 0 = previous run shut down cleanly or this is the first-ever start.\n\
             # TYPE proteus_previous_run_unclean gauge\n\
             proteus_previous_run_unclean {previous_unclean}\n",
            restart_count = self.restart_count,
            first_start_unix = self.first_start_unix,
            last_clean = self.last_clean_shutdown_unix(),
            previous_unclean = u8::from(self.previous_run_unclean),
        )
    }
}

/// Current wall-clock seconds since epoch. Safe wrapper that
/// returns 0 on the impossible-but-handled case of clock < 1970.
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Load the state file. Returns `Ok(default)` (counter=0) when
/// the file doesn't exist — that's the canonical first-ever-start
/// signal.
fn load(path: &Path) -> Result<StateFile, std::io::Error> {
    if !path.exists() {
        return Ok(StateFile::default());
    }
    let body = std::fs::read_to_string(path)?;
    Ok(parse(&body))
}

/// Atomic write via tempfile + rename. Operator can `cat` the
/// file at any time — it's always a well-formed JSON object.
fn save(path: &Path, s: &StateFile) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, serialize(s).as_bytes())?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Minimal JSON serializer — keys ordered for stable diffs in
/// `git status` / operator review.
fn serialize(s: &StateFile) -> String {
    // Escape the only string field. Reason values come from us
    // and never contain quotes/backslashes, but we escape
    // defensively in case a future revision allows operator-
    // supplied text.
    let safe_reason = s
        .previous_end_reason
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    format!(
        "{{\n  \"restart_count\": {},\n  \"first_start_unix\": {},\n  \"last_clean_shutdown_unix\": {},\n  \"previous_start_unix\": {},\n  \"previous_end_reason\": \"{}\"\n}}\n",
        s.restart_count, s.first_start_unix, s.last_clean_shutdown_unix, s.previous_start_unix, safe_reason
    )
}

/// Minimal JSON parser — looks for our exact keys, ignores
/// everything else. Returns default for any unparseable input
/// (so a corrupt file becomes a "synthetic first-ever start"
/// rather than a startup-blocker).
fn parse(body: &str) -> StateFile {
    let mut s = StateFile::default();
    // We don't pull in serde_json for ~5 fields. A simple line-
    // grep + value extraction works because we control both
    // sides of the format. The format is one-key-per-line in
    // the canonical write path.
    for line in body.lines() {
        let line = line.trim().trim_end_matches(',');
        if let Some(v) = extract_u64(line, "\"restart_count\":") {
            s.restart_count = v;
        }
        if let Some(v) = extract_u64(line, "\"first_start_unix\":") {
            s.first_start_unix = v;
        }
        if let Some(v) = extract_u64(line, "\"last_clean_shutdown_unix\":") {
            s.last_clean_shutdown_unix = v;
        }
        if let Some(v) = extract_u64(line, "\"previous_start_unix\":") {
            s.previous_start_unix = v;
        }
        if let Some(v) = extract_quoted(line, "\"previous_end_reason\":") {
            s.previous_end_reason = v;
        }
    }
    s
}

fn extract_u64(line: &str, key: &str) -> Option<u64> {
    let rest = line.strip_prefix(key)?.trim();
    rest.parse().ok()
}

fn extract_quoted(line: &str, key: &str) -> Option<String> {
    let rest = line.strip_prefix(key)?.trim();
    let inner = rest.strip_prefix('"')?;
    let end = inner.find('"')?;
    Some(inner[..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(suffix: &str) -> PathBuf {
        let base = std::env::var("CARGO_TARGET_TMPDIR").unwrap_or_else(|_| "/tmp".to_string());
        let p = PathBuf::from(format!(
            "{base}/proteus-restart-tracker-{suffix}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn first_ever_start_initializes_counter_to_one_and_clean_classification() {
        let p = tmp_path("first-start");
        let tr = RestartTracker::init(p.clone());
        assert_eq!(tr.restart_count(), 1);
        assert!(tr.first_start_unix() > 0);
        assert_eq!(tr.last_clean_shutdown_unix(), 0);
        assert!(
            !tr.previous_run_unclean(),
            "first-ever start should not be flagged as unclean"
        );
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn clean_shutdown_then_restart_classified_as_clean() {
        let p = tmp_path("clean-restart");
        // First run.
        let tr1 = RestartTracker::init(p.clone());
        tr1.mark_clean_shutdown();
        drop(tr1);
        // Second run.
        let tr2 = RestartTracker::init(p.clone());
        assert_eq!(tr2.restart_count(), 2);
        assert!(
            !tr2.previous_run_unclean(),
            "previous run was marked clean — should NOT classify as unclean"
        );
        assert!(tr2.last_clean_shutdown_unix() > 0);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn restart_without_clean_marker_classified_as_unclean() {
        let p = tmp_path("unclean-restart");
        // First run — never call mark_clean_shutdown (simulates
        // panic-abort / OOM kill).
        let tr1 = RestartTracker::init(p.clone());
        // Force a tiny delay so previous_start < new_start; init
        // captures `now` and we want the new init to capture a
        // strictly-later `now`.
        std::thread::sleep(std::time::Duration::from_millis(2));
        drop(tr1);
        // Second run.
        let tr2 = RestartTracker::init(p.clone());
        assert_eq!(tr2.restart_count(), 2);
        assert!(
            tr2.previous_run_unclean(),
            "first run never marked clean — second run must detect unclean previous exit"
        );
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn three_uncleans_in_a_row_still_classifies_each_restart_correctly() {
        let p = tmp_path("triple-unclean");
        let tr1 = RestartTracker::init(p.clone());
        drop(tr1);
        std::thread::sleep(std::time::Duration::from_millis(2));
        let tr2 = RestartTracker::init(p.clone());
        assert!(tr2.previous_run_unclean());
        drop(tr2);
        std::thread::sleep(std::time::Duration::from_millis(2));
        let tr3 = RestartTracker::init(p.clone());
        assert!(tr3.previous_run_unclean());
        assert_eq!(tr3.restart_count(), 3);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn first_start_unix_preserved_across_restarts() {
        let p = tmp_path("first-start-preserved");
        let tr1 = RestartTracker::init(p.clone());
        let first = tr1.first_start_unix();
        tr1.mark_clean_shutdown();
        drop(tr1);
        // Small sleep so the second init sees a STRICTLY-later
        // wall clock — verifies the first_start value is NOT
        // overwritten on the second init.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let tr2 = RestartTracker::init(p.clone());
        assert_eq!(
            tr2.first_start_unix(),
            first,
            "first_start_unix must be preserved across restarts"
        );
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn prometheus_always_emits_all_four_series() {
        let p = tmp_path("prom-shape");
        let tr = RestartTracker::init(p.clone());
        let body = tr.prometheus();
        for needle in [
            "proteus_restarts_total",
            "proteus_first_start_unix_seconds",
            "proteus_last_clean_shutdown_unix_seconds",
            "proteus_previous_run_unclean",
            "# TYPE proteus_restarts_total counter",
        ] {
            assert!(body.contains(needle), "missing {needle} in:\n{body}");
        }
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn corrupt_state_file_does_not_block_startup() {
        let p = tmp_path("corrupt-file");
        std::fs::write(&p, b"!!! NOT JSON !!!\nrandom garbage\n").unwrap();
        let tr = RestartTracker::init(p.clone());
        // Corrupt-file parse returns default (counter=0); init
        // bumps to 1 and treats as first-ever start.
        assert_eq!(tr.restart_count(), 1);
        assert!(!tr.previous_run_unclean());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn round_trip_serializer_preserves_all_fields() {
        let original = StateFile {
            restart_count: 42,
            first_start_unix: 1_700_000_000,
            last_clean_shutdown_unix: 1_700_001_000,
            previous_start_unix: 1_700_000_900,
            previous_end_reason: "clean".to_string(),
        };
        let s = serialize(&original);
        let round = parse(&s);
        assert_eq!(round.restart_count, 42);
        assert_eq!(round.first_start_unix, 1_700_000_000);
        assert_eq!(round.last_clean_shutdown_unix, 1_700_001_000);
        assert_eq!(round.previous_start_unix, 1_700_000_900);
        assert_eq!(round.previous_end_reason, "clean");
    }

    #[test]
    fn missing_parent_dir_is_created_by_save() {
        let base = std::env::var("CARGO_TARGET_TMPDIR").unwrap_or_else(|_| "/tmp".to_string());
        let dir = PathBuf::from(format!(
            "{base}/proteus-restart-tracker-nested-{}/sub/dir",
            std::process::id()
        ));
        let p = dir.join("state.json");
        let _ = std::fs::remove_dir_all(&dir);
        let tr = RestartTracker::init(p.clone());
        assert_eq!(tr.restart_count(), 1);
        assert!(p.exists(), "state file should have been created");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mark_clean_shutdown_updates_in_memory_value_and_disk() {
        let p = tmp_path("clean-update");
        let tr = RestartTracker::init(p.clone());
        assert_eq!(tr.last_clean_shutdown_unix(), 0);
        tr.mark_clean_shutdown();
        let val = tr.last_clean_shutdown_unix();
        assert!(val > 0);
        // The on-disk file should also reflect the update.
        let on_disk = parse(&std::fs::read_to_string(&p).unwrap());
        assert_eq!(on_disk.last_clean_shutdown_unix, val);
        let _ = std::fs::remove_file(&p);
    }
}
