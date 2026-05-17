//! Per-user data **quota** tracker with period reset.
//!
//! ## Why this exists (vs. the existing per-user surfaces)
//!
//! Proteus already ships three per-user defenses:
//!
//!   - `max_session_bytes` — per-session cap, fires once per session.
//!   - `per_user_bandwidth_rate_detector` — sustained-rate alerts,
//!     fires when MB/s crosses a threshold.
//!   - `user_quarantine` — bans after abuse-fire events.
//!
//! None of them bound the **cumulative** bytes a user moves over a
//! period. A patient attacker with a stolen credential who stays
//! under any single-session cap AND any sustained-rate threshold can
//! quietly drain TBs over weeks. Operators noticed when alice did
//! 200 MB/s for 10 seconds; they did NOT notice when alice did
//! 1 MB/s every second for 30 days = 2.6 TB.
//!
//! Every commercial VPN has period-based quotas — Mullvad's free
//! tier is 5 GB total; Cloudflare WARP is 1 GB/month on free;
//! enterprise VPN admins set per-user monthly caps. Proteus needs
//! the same.
//!
//! ## Design
//!
//! - One bucket per user_id; `(used_bytes, period_started_at)`.
//! - Operator sets a default per-period byte cap + optional per-user
//!   overrides. `cap=0` means "unlimited" (back-compat default).
//! - Period rolls over at `period_started_at + period_secs`. On
//!   rollover, `used_bytes` resets to 0 and `period_started_at`
//!   advances by `period_secs`.
//! - `record(user_id, bytes)` adds bytes (called from the same
//!   session-close hook that records into `PerUserBandwidth`).
//! - `is_over_quota(user_id)` returns the post-handshake admission
//!   answer — true means "reject this handshake; the user has burned
//!   their quota for the period".
//! - Persistence: same JSONL pattern as `user_quarantine`. Survives
//!   restarts so quotas can't be reset by bouncing the process.
//!   SIGHUP reload from disk for live operator override (grant
//!   alice a fresh allotment without waiting for period rollover).
//!
//! ## Why per-user-id, not per-IP
//!
//! Same rationale as everywhere else in the abuse-defense pipeline:
//! a stolen credential pivoted across residential IPs defeats per-IP
//! enforcement. Per-user-id attacks what's actually leaked.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// One row in the operator-visible snapshot. Sorted by
/// `used_bytes` descending in `active_snapshot` so the heaviest
/// users surface first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveQuota {
    /// Rendered user_id (printable ASCII or `hex:…`).
    pub user_id: String,
    /// Bytes the user has consumed in the current period.
    pub used_bytes: u64,
    /// Operator-set cap for this user (default OR override). 0 =
    /// unlimited.
    pub cap_bytes: u64,
    /// Seconds remaining until period rollover for this user.
    pub remaining_period_secs: u64,
    /// True when `used_bytes >= cap_bytes && cap_bytes > 0`.
    pub over_quota: bool,
}

#[derive(Debug, Clone, Copy)]
struct UserBucket {
    used_bytes: u64,
    period_started_at: Instant,
    /// Operator-supplied per-user cap override. None = use default.
    cap_override: Option<u64>,
}

/// Per-user quota tracker. Cheap to share via `Arc`.
pub struct PerUserQuotaTracker {
    /// Rolling-window period length (e.g. 30 days = 2_592_000 secs).
    period: Duration,
    /// Default per-period byte cap for any user without an override.
    /// 0 = unlimited.
    default_cap_bytes: u64,
    /// Hard cap on map size. Beyond this, additional users are
    /// tracked in a single overflow bucket — same pattern as
    /// `per_user_bandwidth.rs::PerUserBandwidth`. Memory bound >
    /// per-user accounting perfection under attack.
    max_entries: usize,
    inner: Mutex<HashMap<[u8; 8], UserBucket>>,
    overflow: Mutex<UserBucket>,
    persistence_path: Mutex<Option<PathBuf>>,
    /// Cumulative `record()` calls that took a user across their
    /// cap (i.e. transitioned from under-quota to over-quota).
    /// Counter — operators alert on `rate(...) > 0` to spot quota
    /// busts.
    over_quota_transitions_total: AtomicU64,
    /// Cumulative `is_over_quota()` hits — handshakes blocked at
    /// the admission gate because the user was over quota. The
    /// "did the quota actually save us bytes?" counter.
    over_quota_admission_blocks_total: AtomicU64,
    persist_attempts_total: AtomicU64,
    persist_failed_total: AtomicU64,
    loaded_from_disk: AtomicU64,
    reload_attempts_total: AtomicU64,
    reload_failed_total: AtomicU64,
    /// Cumulative period rollovers across all tracked users. Each
    /// individual user's period resets when its bucket ages past
    /// `period`; this counter counts every such reset.
    period_rollovers_total: AtomicU64,
}

impl PerUserQuotaTracker {
    /// Build a fresh tracker. `default_cap_bytes=0` means "no
    /// default cap" — every user is unlimited unless they have
    /// an override.
    ///
    /// Recommended production values:
    ///   - `period_secs = 2_592_000` (30 days) — calendar-month
    ///     proxy; sensible for VPN-for-friends.
    ///   - `default_cap_bytes = 100 GiB` for a typical home-VPN
    ///     setup; unlimited (0) for full-trust deployments.
    #[must_use]
    pub fn new(period: Duration, default_cap_bytes: u64, max_entries: usize) -> Self {
        Self {
            period,
            default_cap_bytes,
            max_entries,
            inner: Mutex::new(HashMap::new()),
            overflow: Mutex::new(UserBucket {
                used_bytes: 0,
                period_started_at: Instant::now(),
                cap_override: None,
            }),
            persistence_path: Mutex::new(None),
            over_quota_transitions_total: AtomicU64::new(0),
            over_quota_admission_blocks_total: AtomicU64::new(0),
            persist_attempts_total: AtomicU64::new(0),
            persist_failed_total: AtomicU64::new(0),
            loaded_from_disk: AtomicU64::new(0),
            reload_attempts_total: AtomicU64::new(0),
            reload_failed_total: AtomicU64::new(0),
            period_rollovers_total: AtomicU64::new(0),
        }
    }

    /// Builder: install an optional disk-persistence path.
    #[must_use]
    pub fn with_persistence(self, path: PathBuf) -> Self {
        *self
            .persistence_path
            .lock()
            .expect("persistence_path poisoned") = Some(path);
        self
    }

    /// Set a per-user cap override. Persists immediately when
    /// persistence is wired. `cap_bytes=0` means "explicitly
    /// unlimited" (overrides the operator's default). Used by the
    /// startup wiring to apply YAML-supplied `overrides:`.
    pub fn set_user_cap(&self, user_id: [u8; 8], cap_bytes: u64) {
        let mut g = self.inner.lock().expect("inner lock poisoned");
        let bucket = g.entry(user_id).or_insert_with(|| UserBucket {
            used_bytes: 0,
            period_started_at: Instant::now(),
            cap_override: None,
        });
        bucket.cap_override = Some(cap_bytes);
        drop(g);
        let _ = self.persist();
    }

    /// Record `bytes` consumed by `user_id`. Returns the
    /// `(used_after, cap)` pair so callers can do their own logic
    /// (e.g. close a session that just blew its quota mid-stream).
    pub fn record(&self, user_id: [u8; 8], bytes: u64) -> (u64, u64) {
        self.record_at(user_id, bytes, Instant::now())
    }

    /// Test-friendly: explicit `now` parameter.
    pub fn record_at(&self, user_id: [u8; 8], bytes: u64, now: Instant) -> (u64, u64) {
        if bytes == 0 {
            // No-op short-circuit; don't even take the lock for
            // empty handshakes / heartbeats.
            return self.peek_state(&user_id);
        }
        let bucket = self.acquire_bucket(user_id, now);
        // `bucket` is a clone; the mutation goes through
        // re-acquire so we don't deadlock.
        let cap = bucket.cap_override.unwrap_or(self.default_cap_bytes);
        let was_under = bucket.used_bytes < cap || cap == 0;
        let mut new_used = bucket.used_bytes.saturating_add(bytes);
        // Apply changes under the lock.
        let used_after = {
            let mut g = self.inner.lock().expect("inner lock poisoned");
            // Re-fetch under the lock — record_at can race with
            // another record_at on the same user, but additions
            // are commutative so we just take whichever current
            // value exists and add ours.
            if let Some(b) = g.get_mut(&user_id) {
                self.maybe_roll_period(b, now);
                b.used_bytes = b.used_bytes.saturating_add(bytes);
                new_used = b.used_bytes;
                b.used_bytes
            } else {
                // Lost the race AND we just dropped past cap;
                // route through overflow.
                let mut og = self.overflow.lock().expect("overflow lock poisoned");
                self.maybe_roll_period(&mut og, now);
                og.used_bytes = og.used_bytes.saturating_add(bytes);
                og.used_bytes
            }
        };
        let is_over_now = cap > 0 && used_after >= cap;
        if was_under && is_over_now {
            self.over_quota_transitions_total
                .fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                user_id = %crate::per_user_bandwidth::render_user_id_pub(&user_id),
                used_bytes = used_after,
                cap_bytes = cap,
                "user_quota: user crossed over-quota threshold"
            );
        }
        // Persist on every transition AND on every ~64MB increment
        // AND on first-record-for-this-user. The first-record
        // trigger ensures even tiny accounting (e.g. test scenarios
        // or low-traffic users) gets durably written without
        // forcing one disk write per session-close on a busy server.
        // Race-tolerant because the file is monotonic — the latest
        // write captures the latest sum.
        let prev_used = bucket.used_bytes;
        let first_record_for_user = prev_used == 0 && new_used > 0;
        let crossed_64mb_boundary = new_used / (64 * 1024 * 1024) != prev_used / (64 * 1024 * 1024);
        let should_persist =
            (was_under && is_over_now) || crossed_64mb_boundary || first_record_for_user;
        if should_persist {
            let _ = self.persist();
        }
        (used_after, cap)
    }

    fn acquire_bucket(&self, user_id: [u8; 8], now: Instant) -> UserBucket {
        let mut g = self.inner.lock().expect("inner lock poisoned");
        if let Some(b) = g.get_mut(&user_id) {
            self.maybe_roll_period(b, now);
            return *b;
        }
        if g.len() >= self.max_entries {
            let mut og = self.overflow.lock().expect("overflow lock poisoned");
            self.maybe_roll_period(&mut og, now);
            return *og;
        }
        let b = UserBucket {
            used_bytes: 0,
            period_started_at: now,
            cap_override: None,
        };
        g.insert(user_id, b);
        b
    }

    fn maybe_roll_period(&self, bucket: &mut UserBucket, now: Instant) {
        if now >= bucket.period_started_at + self.period {
            // Period rolled over — reset.
            bucket.used_bytes = 0;
            // Snap to the most recent period boundary so the
            // rollover cadence stays regular (vs. drifting on
            // every late record).
            let elapsed = now.duration_since(bucket.period_started_at);
            let periods_elapsed = elapsed.as_secs() / self.period.as_secs().max(1);
            bucket.period_started_at += self.period * (periods_elapsed.max(1) as u32);
            self.period_rollovers_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn peek_state(&self, user_id: &[u8; 8]) -> (u64, u64) {
        let g = self.inner.lock().expect("inner lock poisoned");
        match g.get(user_id) {
            Some(b) => (
                b.used_bytes,
                b.cap_override.unwrap_or(self.default_cap_bytes),
            ),
            None => (0, self.default_cap_bytes),
        }
    }

    /// True when the user is currently over their quota. Called by
    /// the post-handshake admission gate; bumps
    /// `over_quota_admission_blocks_total` on hit.
    pub fn is_over_quota(&self, user_id: &[u8; 8]) -> bool {
        self.is_over_quota_at(user_id, Instant::now())
    }

    /// Test-friendly variant with explicit `now`.
    pub fn is_over_quota_at(&self, user_id: &[u8; 8], now: Instant) -> bool {
        let g = self.inner.lock().expect("inner lock poisoned");
        let Some(b) = g.get(user_id) else {
            return false;
        };
        // Apply period rollover semantics WITHOUT mutating — the
        // bucket would be rolled by the next record_at, but we
        // want is_over_quota to be honest right now.
        let effective_used = if now >= b.period_started_at + self.period {
            0
        } else {
            b.used_bytes
        };
        let cap = b.cap_override.unwrap_or(self.default_cap_bytes);
        let over = cap > 0 && effective_used >= cap;
        if over {
            self.over_quota_admission_blocks_total
                .fetch_add(1, Ordering::Relaxed);
        }
        over
    }

    /// Operator override: reset a user's period counter to zero
    /// immediately. Used to grant a fresh allotment without
    /// waiting for the natural period rollover (e.g. operator
    /// vouches for alice; gives her another 100 GB right now).
    /// Returns true if the user had a bucket to reset.
    pub fn reset_user(&self, user_id: &[u8; 8]) -> bool {
        let now = Instant::now();
        let reset = {
            let mut g = self.inner.lock().expect("inner lock poisoned");
            if let Some(b) = g.get_mut(user_id) {
                b.used_bytes = 0;
                b.period_started_at = now;
                true
            } else {
                false
            }
        };
        if reset {
            tracing::info!(
                user_id = %crate::per_user_bandwidth::render_user_id_pub(user_id),
                "user_quota: manual reset (operator override)"
            );
            let _ = self.persist();
        }
        reset
    }

    /// Snapshot active users for `/diagnose` + the admin CLI.
    /// Sorted by `used_bytes` descending (heaviest first) so the
    /// table surfaces the operator's likely-investigate targets at
    /// the top. Returns at most `limit` rows.
    #[must_use]
    pub fn active_snapshot(&self, limit: usize) -> Vec<ActiveQuota> {
        self.active_snapshot_at(limit, Instant::now())
    }

    /// Test-friendly snapshot.
    #[must_use]
    pub fn active_snapshot_at(&self, limit: usize, now: Instant) -> Vec<ActiveQuota> {
        let g = self.inner.lock().expect("inner lock poisoned");
        let mut out: Vec<ActiveQuota> = g
            .iter()
            .map(|(uid, b)| {
                let cap = b.cap_override.unwrap_or(self.default_cap_bytes);
                let effective_used = if now >= b.period_started_at + self.period {
                    0
                } else {
                    b.used_bytes
                };
                let remaining_period_secs = if now >= b.period_started_at + self.period {
                    self.period.as_secs()
                } else {
                    ((b.period_started_at + self.period) - now).as_secs()
                };
                ActiveQuota {
                    user_id: crate::per_user_bandwidth::render_user_id_pub(uid),
                    used_bytes: effective_used,
                    cap_bytes: cap,
                    remaining_period_secs,
                    over_quota: cap > 0 && effective_used >= cap,
                }
            })
            .collect();
        out.sort_by_key(|b| std::cmp::Reverse(b.used_bytes));
        out.truncate(limit);
        out
    }

    /// Operator-readable text table for `/diagnose`. Mirrors the
    /// `user_quarantine.rs::diagnose_table` shape so operators see
    /// the two surfaces side-by-side without re-learning columns.
    #[must_use]
    pub fn diagnose_table(&self, _now_unix_seconds: u64) -> String {
        let snap = self.active_snapshot(64);
        if snap.is_empty() {
            return String::from("USER QUOTA: (no tracked users)\n");
        }
        use std::fmt::Write as _;
        let mut s = String::with_capacity(384);
        let _ = writeln!(s, "USER QUOTA ({} tracked, heaviest first):", snap.len());
        let _ = writeln!(
            s,
            "  {:>14}  {:>14}  {:>10}  {:<8}  user_id",
            "used_bytes", "cap_bytes", "period_s", "over?"
        );
        for q in &snap {
            let _ = writeln!(
                s,
                "  {:>14}  {:>14}  {:>10}  {:<8}  {}",
                q.used_bytes,
                if q.cap_bytes == 0 {
                    "unlimited".to_string()
                } else {
                    q.cap_bytes.to_string()
                },
                q.remaining_period_secs,
                if q.over_quota { "yes" } else { "no" },
                q.user_id
            );
        }
        s
    }

    /// Distinct users currently being tracked.
    #[must_use]
    pub fn tracked_users(&self) -> usize {
        self.inner.lock().expect("inner lock poisoned").len()
    }

    /// Configured period length.
    #[must_use]
    pub fn period(&self) -> Duration {
        self.period
    }

    /// Configured default cap.
    #[must_use]
    pub fn default_cap_bytes(&self) -> u64 {
        self.default_cap_bytes
    }

    /// Cumulative counters (for `/metrics`).
    #[must_use]
    pub fn over_quota_transitions_total(&self) -> u64 {
        self.over_quota_transitions_total.load(Ordering::Relaxed)
    }
    #[must_use]
    pub fn over_quota_admission_blocks_total(&self) -> u64 {
        self.over_quota_admission_blocks_total
            .load(Ordering::Relaxed)
    }
    #[must_use]
    pub fn persist_attempts_total(&self) -> u64 {
        self.persist_attempts_total.load(Ordering::Relaxed)
    }
    #[must_use]
    pub fn persist_failed_total(&self) -> u64 {
        self.persist_failed_total.load(Ordering::Relaxed)
    }
    #[must_use]
    pub fn loaded_from_disk(&self) -> u64 {
        self.loaded_from_disk.load(Ordering::Relaxed)
    }
    #[must_use]
    pub fn reload_attempts_total(&self) -> u64 {
        self.reload_attempts_total.load(Ordering::Relaxed)
    }
    #[must_use]
    pub fn reload_failed_total(&self) -> u64 {
        self.reload_failed_total.load(Ordering::Relaxed)
    }
    #[must_use]
    pub fn period_rollovers_total(&self) -> u64 {
        self.period_rollovers_total.load(Ordering::Relaxed)
    }

    /// Atomic disk persist (temp file + rename — POSIX-atomic).
    pub fn persist(&self) -> std::io::Result<()> {
        self.persist_attempts_total.fetch_add(1, Ordering::Relaxed);
        let path = {
            let g = self
                .persistence_path
                .lock()
                .expect("persistence_path poisoned");
            match g.as_ref() {
                Some(p) => p.clone(),
                None => return Ok(()),
            }
        };
        let now_instant = Instant::now();
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        let entries: Vec<(String, u64, Option<u64>, u64)> = {
            let g = self.inner.lock().expect("inner lock poisoned");
            g.iter()
                .map(|(uid, b)| {
                    // Convert period_started_at (Instant) to a
                    // wall-clock unix timestamp via the
                    // anchor-now-in-both-clocks trick.
                    let started_unix = if now_instant >= b.period_started_at {
                        now_unix.saturating_sub(
                            now_instant.duration_since(b.period_started_at).as_secs(),
                        )
                    } else {
                        now_unix
                    };
                    (
                        crate::per_user_bandwidth::render_user_id_pub(uid),
                        b.used_bytes,
                        b.cap_override,
                        started_unix,
                    )
                })
                .collect()
        };
        let mut body = String::with_capacity(96 + entries.len() * 96);
        body.push_str(r#"{"kind":"header","schema_version":1,"format":"proteus_user_quota_v1"}"#);
        body.push('\n');
        for (uid_render, used, cap_override, started_unix) in &entries {
            let cap_field = match cap_override {
                Some(c) => format!(r#","cap_override":{c}"#),
                None => String::new(),
            };
            body.push_str(&format!(
                r#"{{"user_id":"{uid_render}","used_bytes":{used},"period_started_unix":{started_unix}{cap_field}}}"#
            ));
            body.push('\n');
        }
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let tmp = {
            let stem = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "user_quota.jsonl".to_string());
            parent.join(format!(".{}.{}.tmp", stem, std::process::id()))
        };
        if let Err(e) = std::fs::write(&tmp, body.as_bytes()) {
            self.persist_failed_total.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(path = ?tmp, error = %e, "user_quota: temp write failed");
            return Err(e);
        }
        if let Err(e) = std::fs::rename(&tmp, &path) {
            self.persist_failed_total.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(from = ?tmp, to = ?path, error = %e, "user_quota: atomic rename failed");
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        Ok(())
    }

    /// Load a previously-persisted file. Same shape as
    /// `user_quarantine::load_from_disk`. On any error, returns
    /// an empty tracker — operators get a working binary, not a
    /// startup-fail; the bumped `persist_failed_total` counter
    /// surfaces the issue.
    #[must_use]
    pub fn load_from_disk(
        path: PathBuf,
        period: Duration,
        default_cap_bytes: u64,
        max_entries: usize,
    ) -> Self {
        let tracker =
            Self::new(period, default_cap_bytes, max_entries).with_persistence(path.clone());
        let raw = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    tracing::info!(path = ?path, "user_quota: no persistence file yet (fresh start)");
                } else {
                    tracing::warn!(path = ?path, error = %e, "user_quota: load failed; starting empty");
                    tracker.persist_failed_total.fetch_add(1, Ordering::Relaxed);
                }
                return tracker;
            }
        };
        let now_instant = Instant::now();
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        let mut g = tracker.inner.lock().expect("inner lock poisoned");
        let mut loaded = 0u64;
        for (lineno, line) in raw.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.starts_with(r#"{"kind":"header""#) {
                continue;
            }
            match parse_entry_line(line) {
                Ok(parsed) => {
                    // Convert period_started_unix back to Instant.
                    let started_at = if parsed.period_started_unix <= now_unix {
                        let elapsed = Duration::from_secs(now_unix - parsed.period_started_unix);
                        now_instant.checked_sub(elapsed).unwrap_or(now_instant)
                    } else {
                        // Clock skew: a "future" started-at lands as "now".
                        now_instant
                    };
                    // Skip if the period has already rolled over on disk —
                    // restoring zero-used + a stale start is wasteful.
                    if now_instant >= started_at + period {
                        continue;
                    }
                    g.insert(
                        parsed.user_id,
                        UserBucket {
                            used_bytes: parsed.used_bytes,
                            period_started_at: started_at,
                            cap_override: parsed.cap_override,
                        },
                    );
                    loaded += 1;
                    if g.len() >= max_entries {
                        tracing::warn!("user_quota: load hit max_entries cap; truncating");
                        break;
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        path = ?path,
                        lineno = lineno + 1,
                        error = %e,
                        "user_quota: skipping unparseable line"
                    );
                }
            }
        }
        drop(g);
        tracker.loaded_from_disk.store(loaded, Ordering::Relaxed);
        tracing::info!(path = ?path, loaded, "user_quota: restored from disk");
        tracker
    }

    /// Reconcile in-memory with the on-disk file. SIGHUP path.
    /// File is canonical for cap_overrides + persisted
    /// used_bytes; in-memory wins ONLY for entries newer than
    /// the file (record_at calls since last persist).
    ///
    /// Simpler than `user_quarantine`'s reconcile: quotas don't
    /// have a tear-down notion. The reload just applies overrides
    /// from the file (operator added/removed overrides) and
    /// merges used_bytes by taking the max.
    pub fn reload_from_disk(&self) -> std::io::Result<u64> {
        self.reload_attempts_total.fetch_add(1, Ordering::Relaxed);
        let path = {
            let g = self
                .persistence_path
                .lock()
                .expect("persistence_path poisoned");
            match g.as_ref() {
                Some(p) => p.clone(),
                None => return Ok(0),
            }
        };
        let raw = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::info!(path = ?path, "user_quota reload: file missing, no-op");
                return Ok(0);
            }
            Err(e) => {
                self.reload_failed_total.fetch_add(1, Ordering::Relaxed);
                return Err(e);
            }
        };
        let now_instant = Instant::now();
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        let mut updates = 0u64;
        let mut g = self.inner.lock().expect("inner lock poisoned");
        for line in raw.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.starts_with(r#"{"kind":"header""#) {
                continue;
            }
            let Ok(parsed) = parse_entry_line(line) else {
                continue;
            };
            let started_at = if parsed.period_started_unix <= now_unix {
                let elapsed = Duration::from_secs(now_unix - parsed.period_started_unix);
                now_instant.checked_sub(elapsed).unwrap_or(now_instant)
            } else {
                now_instant
            };
            if now_instant >= started_at + self.period {
                continue;
            }
            let entry = g.entry(parsed.user_id).or_insert_with(|| UserBucket {
                used_bytes: 0,
                period_started_at: started_at,
                cap_override: parsed.cap_override,
            });
            // Take the MAX of file vs memory for used_bytes — if
            // the in-memory side has recorded MORE bytes since
            // last persist, those are authoritative; we shouldn't
            // accept a file edit that lowers the count (operator
            // who wants to RESET should use reset_user instead).
            let new_used = entry.used_bytes.max(parsed.used_bytes);
            let new_cap = parsed.cap_override;
            if new_used != entry.used_bytes || new_cap != entry.cap_override {
                entry.used_bytes = new_used;
                entry.cap_override = new_cap;
                updates += 1;
            }
        }
        drop(g);
        let _ = self.persist();
        tracing::info!(path = ?path, updates, "user_quota: reconciled with disk");
        Ok(updates)
    }

    /// Emit Prometheus exposition. 12 series total.
    #[must_use]
    pub fn prometheus(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(1024);
        let _ = writeln!(
            s,
            "# HELP proteus_user_quota_period_seconds Configured period length over which the quota resets."
        );
        let _ = writeln!(s, "# TYPE proteus_user_quota_period_seconds gauge");
        let _ = writeln!(
            s,
            "proteus_user_quota_period_seconds {}",
            self.period.as_secs()
        );
        let _ = writeln!(
            s,
            "# HELP proteus_user_quota_default_cap_bytes Default per-period byte cap. 0 = unlimited."
        );
        let _ = writeln!(s, "# TYPE proteus_user_quota_default_cap_bytes gauge");
        let _ = writeln!(
            s,
            "proteus_user_quota_default_cap_bytes {}",
            self.default_cap_bytes
        );
        let _ = writeln!(
            s,
            "# HELP proteus_user_quota_tracked_users Distinct user_ids currently tracked."
        );
        let _ = writeln!(s, "# TYPE proteus_user_quota_tracked_users gauge");
        let _ = writeln!(
            s,
            "proteus_user_quota_tracked_users {}",
            self.tracked_users()
        );
        let _ = writeln!(
            s,
            "# HELP proteus_user_quota_over_quota_transitions_total Records that took a user from under-quota to over-quota in the current period."
        );
        let _ = writeln!(
            s,
            "# TYPE proteus_user_quota_over_quota_transitions_total counter"
        );
        let _ = writeln!(
            s,
            "proteus_user_quota_over_quota_transitions_total {}",
            self.over_quota_transitions_total()
        );
        let _ = writeln!(
            s,
            "# HELP proteus_user_quota_admission_blocks_total Handshakes rejected at admission because the user_id was over quota."
        );
        let _ = writeln!(
            s,
            "# TYPE proteus_user_quota_admission_blocks_total counter"
        );
        let _ = writeln!(
            s,
            "proteus_user_quota_admission_blocks_total {}",
            self.over_quota_admission_blocks_total()
        );
        let _ = writeln!(
            s,
            "# HELP proteus_user_quota_period_rollovers_total Cumulative per-user period rollovers across all tracked users."
        );
        let _ = writeln!(
            s,
            "# TYPE proteus_user_quota_period_rollovers_total counter"
        );
        let _ = writeln!(
            s,
            "proteus_user_quota_period_rollovers_total {}",
            self.period_rollovers_total()
        );
        let _ = writeln!(
            s,
            "# HELP proteus_user_quota_persist_attempts_total Disk persistence write attempts."
        );
        let _ = writeln!(
            s,
            "# TYPE proteus_user_quota_persist_attempts_total counter"
        );
        let _ = writeln!(
            s,
            "proteus_user_quota_persist_attempts_total {}",
            self.persist_attempts_total()
        );
        let _ = writeln!(
            s,
            "# HELP proteus_user_quota_persist_failed_total Disk persistence write failures."
        );
        let _ = writeln!(s, "# TYPE proteus_user_quota_persist_failed_total counter");
        let _ = writeln!(
            s,
            "proteus_user_quota_persist_failed_total {}",
            self.persist_failed_total()
        );
        let _ = writeln!(
            s,
            "# HELP proteus_user_quota_loaded_from_disk Entries restored on startup."
        );
        let _ = writeln!(s, "# TYPE proteus_user_quota_loaded_from_disk gauge");
        let _ = writeln!(
            s,
            "proteus_user_quota_loaded_from_disk {}",
            self.loaded_from_disk()
        );
        let _ = writeln!(
            s,
            "# HELP proteus_user_quota_reload_attempts_total SIGHUP-driven reload attempts."
        );
        let _ = writeln!(s, "# TYPE proteus_user_quota_reload_attempts_total counter");
        let _ = writeln!(
            s,
            "proteus_user_quota_reload_attempts_total {}",
            self.reload_attempts_total()
        );
        let _ = writeln!(
            s,
            "# HELP proteus_user_quota_reload_failed_total SIGHUP-driven reloads that returned an I/O error."
        );
        let _ = writeln!(s, "# TYPE proteus_user_quota_reload_failed_total counter");
        let _ = writeln!(
            s,
            "proteus_user_quota_reload_failed_total {}",
            self.reload_failed_total()
        );
        s
    }
}

struct ParsedEntry {
    user_id: [u8; 8],
    used_bytes: u64,
    period_started_unix: u64,
    cap_override: Option<u64>,
}

fn parse_entry_line(line: &str) -> Result<ParsedEntry, String> {
    let user_id =
        extract_string_field(line, "user_id").ok_or_else(|| "missing user_id".to_string())?;
    let used_bytes =
        extract_u64_field(line, "used_bytes").ok_or_else(|| "missing used_bytes".to_string())?;
    let period_started_unix = extract_u64_field(line, "period_started_unix")
        .ok_or_else(|| "missing period_started_unix".to_string())?;
    let cap_override = extract_u64_field(line, "cap_override");
    let user_id = decode_user_id(&user_id)?;
    Ok(ParsedEntry {
        user_id,
        used_bytes,
        period_started_unix,
        cap_override,
    })
}

fn extract_string_field(s: &str, name: &str) -> Option<String> {
    let needle = format!(r#""{name}":""#);
    let start = s.find(&needle)? + needle.len();
    let rest = &s[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn extract_u64_field(s: &str, name: &str) -> Option<u64> {
    let needle = format!(r#""{name}":"#);
    let start = s.find(&needle)? + needle.len();
    let rest = &s[start..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

fn decode_user_id(s: &str) -> Result<[u8; 8], String> {
    if let Some(hex) = s.strip_prefix("hex:") {
        if hex.len() != 16 {
            return Err(format!("hex user_id length: {}", hex.len()));
        }
        let mut out = [0u8; 8];
        for i in 0..8 {
            out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                .map_err(|e| format!("hex decode byte {i}: {e}"))?;
        }
        return Ok(out);
    }
    let bytes = s.as_bytes();
    if bytes.len() > 8 {
        return Err(format!("printable user_id > 8 bytes: {}", bytes.len()));
    }
    let mut out = [0u8; 8];
    out[..bytes.len()].copy_from_slice(bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    fn tmpfile(suffix: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "proteus_quota_test_{}_{}.jsonl",
            std::process::id(),
            suffix
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn record_accumulates_bytes_per_user() {
        let q = PerUserQuotaTracker::new(secs(3600), 0, 4096);
        q.record(*b"alice001", 1000);
        q.record(*b"alice001", 2500);
        q.record(*b"bob00002", 500);
        let snap = q.active_snapshot(64);
        let alice = snap.iter().find(|e| e.user_id == "alice001").unwrap();
        let bob = snap.iter().find(|e| e.user_id == "bob00002").unwrap();
        assert_eq!(alice.used_bytes, 3500);
        assert_eq!(bob.used_bytes, 500);
    }

    #[test]
    fn default_cap_zero_means_unlimited() {
        let q = PerUserQuotaTracker::new(secs(3600), 0, 4096);
        q.record(*b"alice001", u64::MAX / 2);
        assert!(!q.is_over_quota(b"alice001"));
        assert_eq!(q.over_quota_transitions_total(), 0);
    }

    #[test]
    fn user_goes_over_quota_when_cap_crossed() {
        let q = PerUserQuotaTracker::new(secs(3600), 1000, 4096);
        // Below cap.
        let (used, cap) = q.record(*b"alice001", 600);
        assert_eq!((used, cap), (600, 1000));
        assert!(!q.is_over_quota(b"alice001"));
        // Crosses cap.
        let (used, cap) = q.record(*b"alice001", 500);
        assert_eq!((used, cap), (1100, 1000));
        assert!(q.is_over_quota(b"alice001"));
        assert_eq!(q.over_quota_transitions_total(), 1);
        // Subsequent record: STILL over but doesn't bump
        // transitions counter again.
        q.record(*b"alice001", 100);
        assert_eq!(q.over_quota_transitions_total(), 1);
    }

    #[test]
    fn per_user_override_takes_precedence_over_default() {
        let q = PerUserQuotaTracker::new(secs(3600), 1000, 4096);
        q.set_user_cap(*b"alice001", 5000); // override: 5000
        q.record(*b"alice001", 4000);
        assert!(!q.is_over_quota(b"alice001")); // under 5000 (override)
        q.record(*b"alice001", 1500);
        assert!(q.is_over_quota(b"alice001")); // crosses 5000

        // Bob has no override → uses default 1000.
        q.record(*b"bob00002", 1500);
        assert!(q.is_over_quota(b"bob00002"));
    }

    #[test]
    fn explicit_zero_override_means_unlimited_for_that_user() {
        let q = PerUserQuotaTracker::new(secs(3600), 1000, 4096);
        q.set_user_cap(*b"alice001", 0); // explicitly unlimited
        q.record(*b"alice001", 1_000_000_000); // 1 GB
        assert!(!q.is_over_quota(b"alice001"));
    }

    #[test]
    fn period_rollover_resets_used_bytes() {
        let q = PerUserQuotaTracker::new(secs(60), 1000, 4096);
        let t0 = Instant::now();
        q.record_at(*b"alice001", 1500, t0);
        assert!(q.is_over_quota_at(b"alice001", t0));
        // Past the period — should reset.
        let later = t0 + secs(120);
        let (used, _) = q.record_at(*b"alice001", 500, later);
        assert_eq!(
            used, 500,
            "period rollover must reset used_bytes (got {used})"
        );
        assert!(!q.is_over_quota_at(b"alice001", later));
        assert!(q.period_rollovers_total() >= 1);
    }

    #[test]
    fn reset_user_zeroes_immediately() {
        let q = PerUserQuotaTracker::new(secs(3600), 1000, 4096);
        q.record(*b"alice001", 2000);
        assert!(q.is_over_quota(b"alice001"));
        let reset = q.reset_user(b"alice001");
        assert!(reset);
        assert!(!q.is_over_quota(b"alice001"));
    }

    #[test]
    fn reset_user_returns_false_for_unknown_user() {
        let q = PerUserQuotaTracker::new(secs(60), 1000, 4096);
        assert!(!q.reset_user(b"nobody00"));
    }

    #[test]
    fn admission_blocks_counter_bumps_on_is_over_quota_hit() {
        let q = PerUserQuotaTracker::new(secs(3600), 1000, 4096);
        q.record(*b"alice001", 2000);
        // Miss — bob isn't over.
        assert!(!q.is_over_quota(b"bob00002"));
        assert_eq!(q.over_quota_admission_blocks_total(), 0);
        // Hit.
        assert!(q.is_over_quota(b"alice001"));
        assert_eq!(q.over_quota_admission_blocks_total(), 1);
        assert!(q.is_over_quota(b"alice001"));
        assert_eq!(q.over_quota_admission_blocks_total(), 2);
    }

    #[test]
    fn persist_writes_jsonl_with_header_and_entries() {
        let path = tmpfile("persist");
        let q = PerUserQuotaTracker::new(secs(3600), 1000, 4096).with_persistence(path.clone());
        q.set_user_cap(*b"alice001", 5000);
        q.record(*b"alice001", 100);
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains(r#""kind":"header""#));
        assert!(body.contains(r#""user_id":"alice001""#));
        assert!(body.contains(r#""cap_override":5000"#));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_from_disk_restores_used_bytes_and_overrides() {
        let path = tmpfile("load_round");
        {
            let q1 =
                PerUserQuotaTracker::new(secs(3600), 1000, 4096).with_persistence(path.clone());
            q1.set_user_cap(*b"alice001", 5000);
            q1.record(*b"alice001", 4500);
            q1.record(*b"bob00002", 800);
        }
        let q2 = PerUserQuotaTracker::load_from_disk(path.clone(), secs(3600), 1000, 4096);
        assert!(q2.loaded_from_disk() >= 2);
        let snap = q2.active_snapshot(64);
        let alice = snap.iter().find(|e| e.user_id == "alice001").unwrap();
        let bob = snap.iter().find(|e| e.user_id == "bob00002").unwrap();
        assert_eq!(alice.used_bytes, 4500);
        assert_eq!(alice.cap_bytes, 5000); // override survives
        assert_eq!(bob.used_bytes, 800);
        assert_eq!(bob.cap_bytes, 1000); // default applies
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_from_disk_handles_missing_file_as_fresh_start() {
        let path = tmpfile("missing");
        let q = PerUserQuotaTracker::load_from_disk(path, secs(3600), 1000, 4096);
        assert_eq!(q.loaded_from_disk(), 0);
        assert_eq!(q.persist_failed_total(), 0);
    }

    #[test]
    fn load_from_disk_skips_period_rolled_entries() {
        let path = tmpfile("expired");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Period started 2 hours ago, period is 1 hour → expired.
        let body = format!(
            "{}\n{}\n",
            r#"{"kind":"header","schema_version":1}"#,
            format_args!(
                r#"{{"user_id":"stale001","used_bytes":500,"period_started_unix":{}}}"#,
                now - 7200
            )
        );
        std::fs::write(&path, body).unwrap();
        let q = PerUserQuotaTracker::load_from_disk(path.clone(), secs(3600), 1000, 4096);
        assert_eq!(q.loaded_from_disk(), 0, "stale period must be skipped");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn reload_from_disk_takes_max_used_bytes() {
        let path = tmpfile("reload_max");
        let q = PerUserQuotaTracker::new(secs(3600), 1000, 4096).with_persistence(path.clone());
        q.record(*b"alice001", 5000);
        // Operator hand-edits the file to LOWER alice's used_bytes
        // — the in-memory value MUST win (we don't let edits
        // reset usage; that's what reset_user is for).
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let body = format!(
            "{}\n{}\n",
            r#"{"kind":"header","schema_version":1}"#,
            format_args!(
                r#"{{"user_id":"alice001","used_bytes":1,"period_started_unix":{}}}"#,
                now
            )
        );
        std::fs::write(&path, body).unwrap();
        let _ = q.reload_from_disk().unwrap();
        let snap = q.active_snapshot(64);
        let alice = snap.iter().find(|e| e.user_id == "alice001").unwrap();
        assert_eq!(
            alice.used_bytes, 5000,
            "memory must win for higher used_bytes"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn reload_from_disk_picks_up_new_overrides() {
        let path = tmpfile("reload_override");
        let q = PerUserQuotaTracker::new(secs(3600), 1000, 4096).with_persistence(path.clone());
        q.record(*b"alice001", 500);
        // Hand-edit: grant alice a cap_override of 10_000.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let body = format!(
            "{}\n{}\n",
            r#"{"kind":"header","schema_version":1}"#,
            format_args!(
                r#"{{"user_id":"alice001","used_bytes":500,"period_started_unix":{},"cap_override":10000}}"#,
                now
            )
        );
        std::fs::write(&path, body).unwrap();
        let updates = q.reload_from_disk().unwrap();
        assert!(updates >= 1);
        let snap = q.active_snapshot(64);
        let alice = snap.iter().find(|e| e.user_id == "alice001").unwrap();
        assert_eq!(alice.cap_bytes, 10000);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn prometheus_emits_all_series() {
        let q = PerUserQuotaTracker::new(secs(3600), 1000, 4096);
        let s = q.prometheus();
        for name in [
            "proteus_user_quota_period_seconds",
            "proteus_user_quota_default_cap_bytes",
            "proteus_user_quota_tracked_users",
            "proteus_user_quota_over_quota_transitions_total",
            "proteus_user_quota_admission_blocks_total",
            "proteus_user_quota_period_rollovers_total",
            "proteus_user_quota_persist_attempts_total",
            "proteus_user_quota_persist_failed_total",
            "proteus_user_quota_loaded_from_disk",
            "proteus_user_quota_reload_attempts_total",
            "proteus_user_quota_reload_failed_total",
        ] {
            assert!(s.contains(name), "missing {name}:\n{s}");
        }
    }

    #[test]
    fn diagnose_table_renders_heaviest_first() {
        let q = PerUserQuotaTracker::new(secs(3600), 10_000, 4096);
        q.record(*b"alice001", 100);
        q.record(*b"bob00002", 9000);
        q.record(*b"carol003", 3000);
        let s = q.diagnose_table(0);
        let bob_pos = s.find("bob00002").unwrap();
        let carol_pos = s.find("carol003").unwrap();
        let alice_pos = s.find("alice001").unwrap();
        assert!(bob_pos < carol_pos, "bob (9000) before carol (3000)");
        assert!(carol_pos < alice_pos, "carol (3000) before alice (100)");
    }

    #[test]
    fn diagnose_table_renders_empty_when_no_users() {
        let q = PerUserQuotaTracker::new(secs(3600), 1000, 4096);
        let s = q.diagnose_table(0);
        assert!(s.contains("(no tracked users)"));
    }

    #[test]
    fn concurrent_record_keeps_counter_invariants() {
        use std::sync::Arc;
        let q = Arc::new(PerUserQuotaTracker::new(secs(3600), 100_000, 4096));
        let mut handles = Vec::new();
        for _ in 0..16 {
            let q = Arc::clone(&q);
            handles.push(std::thread::spawn(move || {
                for _ in 0..100 {
                    q.record(*b"alice001", 10);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let snap = q.active_snapshot(64);
        let alice = snap.iter().find(|e| e.user_id == "alice001").unwrap();
        // 16 × 100 × 10 = 16_000 bytes
        assert_eq!(alice.used_bytes, 16_000);
    }

    #[test]
    fn user_id_hex_form_roundtrips_through_persistence() {
        let path = tmpfile("hex");
        let weird = [0xff_u8, 0x00, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56];
        {
            let q = PerUserQuotaTracker::new(secs(3600), 1000, 4096).with_persistence(path.clone());
            q.record(weird, 700);
        }
        let q2 = PerUserQuotaTracker::load_from_disk(path.clone(), secs(3600), 1000, 4096);
        assert_eq!(q2.loaded_from_disk(), 1);
        let snap = q2.active_snapshot(64);
        assert_eq!(snap[0].used_bytes, 700);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn reload_with_no_persistence_path_is_noop_but_bumps_attempts() {
        let q = PerUserQuotaTracker::new(secs(3600), 1000, 4096);
        let updates = q.reload_from_disk().unwrap();
        assert_eq!(updates, 0);
        assert_eq!(q.reload_attempts_total(), 1);
    }
}
