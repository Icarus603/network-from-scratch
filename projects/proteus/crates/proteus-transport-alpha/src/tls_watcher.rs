//! File-mtime-driven TLS cert auto-reload.
//!
//! ## Why this exists
//!
//! Operators using non-Let's-Encrypt cert issuers (corporate CA,
//! internal PKI, manual rotations) have no way for Proteus to KNOW
//! when the cert file on disk has been updated. Today the cert
//! reload requires a manual SIGHUP. If the operator's deploy
//! script forgets that step, the binary keeps serving the old cert
//! until expiry — silently.
//!
//! The Let's-Encrypt path is fine: certbot's `deploy-hook` runs
//! `systemctl kill --signal=HUP proteus-server` and the existing
//! [`crate::tls::ReloadableAcceptor::reload_with_expiry`] picks up
//! the fresh chain. Everyone else needs a different trip-wire.
//!
//! ## What this does
//!
//! 1. Records the cert + key file's `mtime` at startup.
//! 2. Every N seconds, `stat()` both paths.
//! 3. If either mtime advanced, attempt a reload via
//!    `ReloadableAcceptor::reload_with_expiry`.
//! 4. Surface counters for operators: `mtime_changes_observed`,
//!    `auto_reload_attempts`, `auto_reload_succeeded`,
//!    `auto_reload_failed`.
//!
//! ## Why mtime not inotify/kqueue
//!
//! Two reasons:
//!
//! 1. **Portability.** Proteus runs on Linux (production) and
//!    macOS (dev). `inotify` is Linux-only; `kqueue` is BSD/macOS.
//!    A periodic `stat()` works identically on both and costs
//!    microseconds per cycle.
//! 2. **Atomicity preservation.** Most operator cert-deploy
//!    scripts already use temp-file-then-rename so the cert
//!    appears atomically. `stat()` AFTER the rename sees the new
//!    mtime; `inotify` would race with the rename and we'd have
//!    to handle `IN_MOVED_TO` events specially. The simpler
//!    `stat()` pattern just works.
//!
//! ## Failure modes
//!
//! - **Cert file disappeared** (operator deleted it mid-deploy)
//!   → `stat()` fails, counter bumps `auto_reload_failed`, the
//!   current cert keeps serving traffic. Operator alerted via
//!   `failed > 0` rate-alert.
//! - **New cert is malformed** (truncated PEM, wrong key) →
//!   `load_cert_chain` / `load_private_key` fails, counter bumps
//!   `auto_reload_failed`, the current cert keeps serving traffic.
//! - **mtime touched but content unchanged** (operator ran
//!   `touch certfile`) → reload fires, succeeds, counter bumps
//!   `auto_reload_succeeded`. Operationally identical to a
//!   no-op reload; not worth optimizing.
//!
//! In every failure mode, the running binary keeps serving the
//! existing cert. Operators get a counter signal AND a structured
//! log line.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::SystemTime;

/// File-mtime tracker for the TLS cert + key pair.
///
/// Build once at startup (records initial mtimes). Call
/// [`Self::check_for_change`] periodically to detect operator-
/// driven rotations.
pub struct CertFileWatcher {
    cert_path: PathBuf,
    key_path: PathBuf,
    /// Last-observed cert mtime as Unix seconds. `i64::MIN` =
    /// "stat failed on initial read" (file missing at startup —
    /// the binary almost certainly aborted earlier in the cert-
    /// load path, but we keep the watcher in a degraded mode so
    /// it surfaces the recovery if the file ever reappears).
    cert_mtime: Mutex<i64>,
    /// Last-observed key mtime. Same semantics as `cert_mtime`.
    key_mtime: Mutex<i64>,
    /// Cumulative count of mtime changes observed (cert OR key).
    /// Bumps on every check that sees a change vs. the previous
    /// observation. Distinct from auto_reload_attempts because
    /// a single mtime-change triggers one reload attempt.
    pub mtime_changes_observed: AtomicU64,
    /// Cumulative count of auto-reload attempts (i.e. mtime
    /// changes that fired a reload call). Should equal
    /// mtime_changes_observed in normal operation; divergence
    /// would indicate a bug.
    pub auto_reload_attempts: AtomicU64,
    /// Auto-reloads that completed successfully (acceptor
    /// swapped + cert parsed).
    pub auto_reload_succeeded: AtomicU64,
    /// Auto-reloads that failed at some point (stat / file read /
    /// cert parse / acceptor build). The acceptor stays at the
    /// previous good cert.
    pub auto_reload_failed: AtomicU64,
}

impl CertFileWatcher {
    /// Build a watcher with initial mtimes read from disk.
    ///
    /// Read failures are stored as `i64::MIN` so the first
    /// successful stat AFTER deploy registers as a "change" and
    /// triggers a reload — that's the correct behavior for the
    /// edge case where the file was missing at boot but appeared
    /// later.
    #[must_use]
    pub fn new(cert_path: PathBuf, key_path: PathBuf) -> Self {
        let cert_mtime = file_mtime_unix(&cert_path).unwrap_or(i64::MIN);
        let key_mtime = file_mtime_unix(&key_path).unwrap_or(i64::MIN);
        Self {
            cert_path,
            key_path,
            cert_mtime: Mutex::new(cert_mtime),
            key_mtime: Mutex::new(key_mtime),
            mtime_changes_observed: AtomicU64::new(0),
            auto_reload_attempts: AtomicU64::new(0),
            auto_reload_succeeded: AtomicU64::new(0),
            auto_reload_failed: AtomicU64::new(0),
        }
    }

    /// Check both paths' current mtimes against the last
    /// observation. Returns `true` iff either changed.
    ///
    /// Read-only: callers use the return value to decide whether
    /// to trigger a reload. [`Self::check_and_record`] does the
    /// same check AND updates the recorded mtimes (so the next
    /// check picks up only further changes).
    #[must_use]
    pub fn changed(&self) -> bool {
        let cert_now = file_mtime_unix(&self.cert_path).unwrap_or(i64::MIN);
        let key_now = file_mtime_unix(&self.key_path).unwrap_or(i64::MIN);
        // Iter-25: poisoned-lock recovery. Background task —
        // not a per-connection hot path — but consistency
        // with the iter-25 sweep keeps the cert-reload watcher
        // alive even if a prior reload panicked. Mtimes are
        // single i64 values; partial-write poison can't leave
        // them in a malformed state.
        let last_cert = *self.cert_mtime.lock().unwrap_or_else(|p| p.into_inner());
        let last_key = *self.key_mtime.lock().unwrap_or_else(|p| p.into_inner());
        cert_now != last_cert || key_now != last_key
    }

    /// Check + record. Returns `Some((new_cert_mtime,
    /// new_key_mtime))` when a change was observed AND the
    /// internal state was updated; `None` when nothing changed.
    ///
    /// The caller (typically the background task in `main.rs`)
    /// uses the return value to decide whether to fire a reload.
    /// We update the recorded mtimes BEFORE the reload fires so
    /// a slow reload doesn't cause repeated retries on the same
    /// observed change.
    pub fn check_and_record(&self) -> Option<(i64, i64)> {
        let cert_now = file_mtime_unix(&self.cert_path).unwrap_or(i64::MIN);
        let key_now = file_mtime_unix(&self.key_path).unwrap_or(i64::MIN);
        // Iter-25: same poisoned-lock recovery as `changed`.
        let mut last_cert = self.cert_mtime.lock().unwrap_or_else(|p| p.into_inner());
        let mut last_key = self.key_mtime.lock().unwrap_or_else(|p| p.into_inner());
        if cert_now == *last_cert && key_now == *last_key {
            return None;
        }
        *last_cert = cert_now;
        *last_key = key_now;
        self.mtime_changes_observed.fetch_add(1, Ordering::Relaxed);
        Some((cert_now, key_now))
    }

    /// Bump the attempt counter. Called by the reload task right
    /// before invoking the cert-load + acceptor-build chain.
    pub fn record_attempt(&self) {
        self.auto_reload_attempts.fetch_add(1, Ordering::Relaxed);
    }

    /// Bump the success counter.
    pub fn record_success(&self) {
        self.auto_reload_succeeded.fetch_add(1, Ordering::Relaxed);
    }

    /// Bump the failure counter.
    pub fn record_failure(&self) {
        self.auto_reload_failed.fetch_add(1, Ordering::Relaxed);
    }

    /// Read accessor — used by `/metrics`.
    #[must_use]
    pub fn cert_path(&self) -> &std::path::Path {
        &self.cert_path
    }

    /// Read accessor — used by `/metrics`.
    #[must_use]
    pub fn key_path(&self) -> &std::path::Path {
        &self.key_path
    }

    /// Emit the four Prometheus counters for this watcher. The
    /// counter names use the `proteus_tls_cert_watcher_*` prefix
    /// so they don't collide with the existing
    /// `proteus_tls_reload_*` counters on `ReloadableAcceptor`
    /// (which count SIGHUP-driven manual reloads).
    #[must_use]
    pub fn prometheus(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(512);
        let _ = writeln!(
            s,
            "# HELP proteus_tls_cert_watcher_mtime_changes_observed_total Cumulative cert/key file-mtime changes the watcher noticed (= auto-reload triggers)."
        );
        let _ = writeln!(
            s,
            "# TYPE proteus_tls_cert_watcher_mtime_changes_observed_total counter"
        );
        let _ = writeln!(
            s,
            "proteus_tls_cert_watcher_mtime_changes_observed_total {}",
            self.mtime_changes_observed.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            s,
            "# HELP proteus_tls_cert_watcher_auto_reload_attempts_total Auto-reload attempts triggered by mtime changes."
        );
        let _ = writeln!(
            s,
            "# TYPE proteus_tls_cert_watcher_auto_reload_attempts_total counter"
        );
        let _ = writeln!(
            s,
            "proteus_tls_cert_watcher_auto_reload_attempts_total {}",
            self.auto_reload_attempts.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            s,
            "# HELP proteus_tls_cert_watcher_auto_reload_succeeded_total Auto-reloads that swapped the acceptor + parsed the new chain."
        );
        let _ = writeln!(
            s,
            "# TYPE proteus_tls_cert_watcher_auto_reload_succeeded_total counter"
        );
        let _ = writeln!(
            s,
            "proteus_tls_cert_watcher_auto_reload_succeeded_total {}",
            self.auto_reload_succeeded.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            s,
            "# HELP proteus_tls_cert_watcher_auto_reload_failed_total Auto-reloads that failed (stat / read / parse / build). Alert on rate > 0."
        );
        let _ = writeln!(
            s,
            "# TYPE proteus_tls_cert_watcher_auto_reload_failed_total counter"
        );
        let _ = writeln!(
            s,
            "proteus_tls_cert_watcher_auto_reload_failed_total {}",
            self.auto_reload_failed.load(Ordering::Relaxed)
        );
        s
    }
}

/// Read the file's modification time as Unix seconds. Returns
/// None on stat failure (file missing, permission denied, etc.)
/// — the caller treats `i64::MIN` as the sentinel.
fn file_mtime_unix(path: &std::path::Path) -> Option<i64> {
    let meta = std::fs::metadata(path).ok()?;
    let mtime = meta.modified().ok()?;
    let unix = mtime.duration_since(SystemTime::UNIX_EPOCH).ok()?.as_secs();
    i64::try_from(unix).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmp_path(suffix: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "proteus_tls_watcher_test_{}_{}",
            std::process::id(),
            suffix
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn write_file(path: &std::path::Path, content: &[u8]) {
        let mut f = std::fs::File::create(path).expect("create");
        f.write_all(content).expect("write");
    }

    #[test]
    fn new_records_initial_mtimes_and_changed_is_false() {
        let cert = tmp_path("c1.pem");
        let key = tmp_path("k1.pem");
        write_file(&cert, b"cert v1");
        write_file(&key, b"key v1");
        let w = CertFileWatcher::new(cert.clone(), key.clone());
        // Just-built — no change since construction.
        assert!(!w.changed());
        assert!(w.check_and_record().is_none());
        let _ = std::fs::remove_file(&cert);
        let _ = std::fs::remove_file(&key);
    }

    #[test]
    fn mtime_change_is_detected() {
        let cert = tmp_path("c2.pem");
        let key = tmp_path("k2.pem");
        write_file(&cert, b"cert v1");
        write_file(&key, b"key v1");
        let w = CertFileWatcher::new(cert.clone(), key.clone());
        // Wait > 1 second so the filesystem's mtime granularity
        // (typically 1s on macOS, 1ns on Linux but rounded to s
        // by SystemTime) shows a different mtime.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        write_file(&cert, b"cert v2");
        assert!(w.changed());
        let r = w.check_and_record();
        assert!(r.is_some(), "must report change");
        assert_eq!(w.mtime_changes_observed.load(Ordering::Relaxed), 1);
        // Second check: no further change → None.
        assert!(w.check_and_record().is_none());
        assert_eq!(w.mtime_changes_observed.load(Ordering::Relaxed), 1);
        let _ = std::fs::remove_file(&cert);
        let _ = std::fs::remove_file(&key);
    }

    #[test]
    fn key_change_is_detected_independently_of_cert() {
        let cert = tmp_path("c3.pem");
        let key = tmp_path("k3.pem");
        write_file(&cert, b"cert v1");
        write_file(&key, b"key v1");
        let w = CertFileWatcher::new(cert.clone(), key.clone());
        std::thread::sleep(std::time::Duration::from_millis(1100));
        // Only the key changed.
        write_file(&key, b"key v2");
        assert!(w.changed());
        let r = w.check_and_record();
        assert!(r.is_some());
        let _ = std::fs::remove_file(&cert);
        let _ = std::fs::remove_file(&key);
    }

    #[test]
    fn missing_file_at_construction_records_sentinel_then_recovers() {
        let cert = tmp_path("c4.pem");
        let key = tmp_path("k4.pem");
        // Don't create cert yet.
        write_file(&key, b"key v1");
        let w = CertFileWatcher::new(cert.clone(), key.clone());
        // Initial mtime for cert = sentinel.
        assert_eq!(*w.cert_mtime.lock().unwrap(), i64::MIN);
        // Operator writes the cert — first observation flips
        // the sentinel and reports a change.
        write_file(&cert, b"cert v1");
        let r = w.check_and_record();
        assert!(
            r.is_some(),
            "appearance of missing file must register as change"
        );
        let _ = std::fs::remove_file(&cert);
        let _ = std::fs::remove_file(&key);
    }

    #[test]
    fn check_and_record_advances_state_for_next_call() {
        let cert = tmp_path("c5.pem");
        let key = tmp_path("k5.pem");
        write_file(&cert, b"a");
        write_file(&key, b"b");
        let w = CertFileWatcher::new(cert.clone(), key.clone());
        std::thread::sleep(std::time::Duration::from_millis(1100));
        write_file(&cert, b"a2");
        assert!(w.check_and_record().is_some());
        // Same file, no further touch → None.
        assert!(w.check_and_record().is_none());
        let _ = std::fs::remove_file(&cert);
        let _ = std::fs::remove_file(&key);
    }

    #[test]
    fn record_attempt_success_failure_bumps_counters_independently() {
        let cert = tmp_path("c6.pem");
        let key = tmp_path("k6.pem");
        write_file(&cert, b"a");
        write_file(&key, b"b");
        let w = CertFileWatcher::new(cert.clone(), key.clone());
        w.record_attempt();
        w.record_success();
        w.record_attempt();
        w.record_failure();
        assert_eq!(w.auto_reload_attempts.load(Ordering::Relaxed), 2);
        assert_eq!(w.auto_reload_succeeded.load(Ordering::Relaxed), 1);
        assert_eq!(w.auto_reload_failed.load(Ordering::Relaxed), 1);
        let _ = std::fs::remove_file(&cert);
        let _ = std::fs::remove_file(&key);
    }

    #[test]
    fn prometheus_emits_all_four_counters() {
        let cert = tmp_path("c7.pem");
        let key = tmp_path("k7.pem");
        write_file(&cert, b"a");
        write_file(&key, b"b");
        let w = CertFileWatcher::new(cert.clone(), key.clone());
        let s = w.prometheus();
        for name in [
            "proteus_tls_cert_watcher_mtime_changes_observed_total",
            "proteus_tls_cert_watcher_auto_reload_attempts_total",
            "proteus_tls_cert_watcher_auto_reload_succeeded_total",
            "proteus_tls_cert_watcher_auto_reload_failed_total",
        ] {
            assert!(s.contains(name), "missing {name}:\n{s}");
            assert!(s.contains(&format!("# TYPE {name} counter")));
        }
        let _ = std::fs::remove_file(&cert);
        let _ = std::fs::remove_file(&key);
    }
}
