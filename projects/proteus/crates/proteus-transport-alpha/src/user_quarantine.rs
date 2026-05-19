//! TTL-bounded auto-quarantine list for `user_id`s that have
//! repeatedly tripped abuse detectors.
//!
//! ## What this closes
//!
//! Without this, the three abuse detectors (byte_budget,
//! rate_limit, per_user_bandwidth_rate) are observation-only:
//!
//!   1. Detector fires → WARN log line + counter bump + recent-
//!      fires ring push.
//!   2. **Server keeps accepting the same user_id's handshakes**
//!      for hours, even though we just told the operator "alice001
//!      is exfiltrating data".
//!   3. Operator sees the alert (eventually), manually rotates the
//!      credential, restarts the server.
//!
//! Step 2 is the gap. Operators sleep; attackers don't. The
//! canonical Proteus operator running a personal VPN doesn't
//! check `journalctl` every 60 seconds — they'd find out tomorrow.
//! By then alice001's stolen credential has moved gigabytes.
//!
//! The IP-based [`crate::auto_deny::AutoDenyList`] closes the
//! analogous loop for source-IP /24 prefixes flagged by the probe-
//! anomaly detector. This module is its **per-user** sibling: when
//! a `user_id` accumulates N abuse fires in M minutes (operator-
//! configured), it lands in a TTL-bounded quarantine map. New
//! handshakes from that user_id are rejected immediately at the
//! post-handshake admission gate — before the relay opens any
//! upstream connection. The entry expires after the TTL, so
//! transient false positives self-heal without operator
//! intervention.
//!
//! ## Why this is per-user-id, not per-IP
//!
//! The IP-based `auto_deny` only helps when the abuse comes from a
//! single source IP. A stolen credential being used across a
//! botnet of residential IPs (the modern threat model) defeats
//! per-IP enforcement. Per-user-id enforcement attacks the credential
//! itself, which is what's actually leaked.
//!
//! ## Why an in-binary policy layer
//!
//! Same rationale as `auto_deny.rs`:
//!   - Auto-mutating the allowlist via SIGHUP-shaped paths confuses
//!     operator-edited and auto-managed entries.
//!   - Calling out to external systems (revocation lists, OAuth
//!     introspection) is non-portable and out of scope for the
//!     single-VPS operator.
//!   - The in-binary list is bounded, observable via /metrics +
//!     /diagnose, and TTL-expiring (no permanent state to forget
//!     about).
//!
//! ## Threading
//!
//! Single `Mutex<HashMap<[u8;8], QuarantineEntry>>`. Lookups happen
//! on every authenticated handshake (post-handshake admission gate
//! — already a low rate compared to the data-plane hot path).
//! Inserts happen only on abuse fires (cold path — one per burst
//! per user_id). Vacuum runs amortized inside lookups when the map
//! is non-empty and we haven't vacuumed in `VACUUM_INTERVAL`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::Notify;

/// How often the in-memory map gets vacuumed of expired entries.
/// Mirrors `auto_deny.rs::VACUUM_INTERVAL` — keeps the cost
/// amortized regardless of lookup rate.
const VACUUM_INTERVAL: Duration = Duration::from_secs(30);

/// Outcome of [`UserQuarantineList::reload_from_disk`] — surfaced
/// so the SIGHUP handler can structured-log "we added N, removed
/// M, refreshed K entries during reconciliation".
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ReloadOutcome {
    /// Entries that were in the file but not in memory → newly
    /// inserted. Tears down any in-flight sessions for these
    /// user_ids (file-driven new bans).
    pub added: u64,
    /// Entries that were in memory but not in the file → removed.
    /// Does NOT tear down — see [`UserQuarantineList::unquarantine`].
    pub removed: u64,
    /// Entries in both, where the file's `expires_at` or
    /// `triggered_by` differed from memory → updated in place.
    pub refreshed: u64,
    /// Entries skipped because they were already expired on disk
    /// (wall-clock filter).
    pub skipped_expired: u64,
    /// Unparseable lines in the file. Should be 0 in normal
    /// operation; non-zero means the operator edit produced a
    /// malformed line (the rest of the file is still applied; the
    /// bad line is skipped + logged).
    pub malformed: u64,
}

/// One row in the quarantine snapshot — what `/metrics` + `admin
/// status` need to render about a currently-quarantined user_id.
/// Sorted by `expires_in_secs` ascending in `active_snapshot`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveQuarantine {
    /// Operator-readable user_id string (printable ASCII verbatim,
    /// or `hex:<16hexchars>` fallback for non-printable). Uses the
    /// same renderer as the per-user bandwidth labels so operators
    /// can cross-reference the two surfaces.
    pub user_id: String,
    /// Seconds remaining before this entry expires + heals.
    pub expires_in_secs: u64,
    /// The detector kind that ultimately caused this quarantine —
    /// surfaced so operators know whether to investigate the user's
    /// behavior (rate_limit) vs. their credential being leaked
    /// (per_user_bandwidth_rate).
    pub triggered_by: String,
}

#[derive(Debug, Clone, Copy)]
struct QuarantineEntry {
    /// Absolute deadline; entry expires when `Instant::now() >= expires_at`.
    expires_at: Instant,
    /// Detector kind that caused the most recent (re)insertion.
    /// On repeat insertion (same user_id quarantined again before
    /// the entry expired), we refresh both `expires_at` AND
    /// `triggered_by` so the operator sees the freshest signal.
    triggered_by_kind: &'static str,
}

/// TTL-bounded auto-quarantine list. Cheap to share via `Arc`
/// across the abuse-fire push sites (relay, server, per-user
/// bandwidth drop hook) AND the post-handshake admission gate.
pub struct UserQuarantineList {
    /// TTL applied to every freshly-inserted entry. Refreshes on
    /// repeat insertion (re-quarantining a still-quarantined user
    /// resets the clock — the user keeps tripping detectors, the
    /// quarantine should stay).
    ttl: Duration,
    /// Hard cap on map size. New inserts beyond the cap are dropped
    /// (with `refused_inserts_total` bumped) so an attacker can't
    /// pivot from "exfil one credential" to "OOM the quarantine
    /// map by tripping detectors with thousands of fake user_ids".
    /// Recommended production value: at most the operator's
    /// `client_allowlist` size + ~10% headroom for pre-auth fires
    /// (which are bounded separately by the fire detectors).
    max_entries: usize,
    inner: Mutex<HashMap<[u8; 8], QuarantineEntry>>,
    /// Per-user cancellation notifiers for IN-FLIGHT sessions.
    /// Each entry is a `Weak<Notify>` so the registry doesn't keep
    /// session-cancel handles alive past session end — the
    /// session's Arc<Notify> drops when the handler exits, the
    /// Weak becomes invalid, and the next `tear_down_user` /
    /// `register_session` call vacuums it.
    ///
    /// `tear_down_user(uid)` (called on quarantine insert) walks
    /// this Vec, upgrades each weak, calls `notify_waiters()` to
    /// wake EVERY in-flight session for that user_id at once —
    /// so the attacker mid-burst stops exfiltrating immediately,
    /// not "when their session times out".
    session_notifiers: Mutex<HashMap<[u8; 8], Vec<Weak<Notify>>>>,
    /// Last time the vacuum walked the map. Updated under the
    /// inner mutex; ensures we don't do a full O(N) walk on every
    /// lookup.
    last_vacuum: Mutex<Instant>,
    /// Cumulative inserts (counter for `/metrics`). Includes
    /// refreshes — operators alert on `rate(...) > 0` to spot
    /// fresh quarantines.
    inserted_total: std::sync::atomic::AtomicU64,
    /// Inserts refused because `max_entries` was reached.
    refused_inserts_total: std::sync::atomic::AtomicU64,
    /// Lookups that hit a quarantined entry — i.e. successful
    /// blocks of in-progress abuse. The "did the quarantine
    /// actually save us?" counter operators care about most.
    quarantine_hits_total: std::sync::atomic::AtomicU64,
    /// Cumulative count of IN-FLIGHT sessions that were torn down
    /// because their user_id was newly quarantined. Distinct from
    /// `quarantine_hits_total` (which counts NEW handshakes
    /// blocked at admission). Operators alert on this to confirm
    /// the tear-down path actually fired — the "we caught a
    /// mid-burst exfiltrator" counter.
    sessions_torn_down_total: std::sync::atomic::AtomicU64,
    /// Optional persistence path.
    ///
    /// When set, every successful `insert` (fresh or refresh) calls
    /// `persist()` to write the current map to disk as JSON Lines,
    /// atomically via temp-file + rename. On startup, the binary
    /// calls [`Self::load_from_disk`] to seed the in-memory map
    /// from the file — so a banned user_id STAYS banned across
    /// process restarts (systemd restart, OOM kill, operator
    /// deploy).
    ///
    /// Without persistence, a stolen credential gets a fresh attack
    /// window of `ttl` minutes every time the binary restarts —
    /// the operator's biggest pain point for long-lived
    /// deployments. The IP-based auto_deny.rs has the same gap,
    /// but its TTL is typically tighter (probe detection refires
    /// fast) so the gap matters less.
    persistence_path: Mutex<Option<PathBuf>>,
    /// Cumulative count of successful disk writes. Bumped after
    /// each `persist()` that completes (rename succeeds). The
    /// matching `_failed_total` below catches errors. Together
    /// they let operators alert on `attempts > succeeded` —
    /// silent-write-failure visibility, same shape as the
    /// SIGHUP-reload counters on ServerMetrics.
    persist_attempts_total: std::sync::atomic::AtomicU64,
    persist_failed_total: std::sync::atomic::AtomicU64,
    /// Cumulative entries loaded from disk at startup via
    /// `load_from_disk`. Bumped during the load, surfaced as a
    /// gauge so operators see "we restored N entries on startup"
    /// without grepping logs.
    loaded_from_disk: std::sync::atomic::AtomicU64,
    /// Cumulative operator-driven manual unquarantine calls
    /// (`unquarantine` returning true). Bumped per successful
    /// removal. Operators read this on dashboards to confirm a
    /// false-positive unblock took effect.
    manual_unquarantines_total: std::sync::atomic::AtomicU64,
    /// Cumulative SIGHUP-driven reload calls (`reload_from_disk`).
    /// Bumped on every invocation, regardless of outcome — pairs
    /// with `reload_failed_total` so operators alert on
    /// `attempts > succeeded` for silent reload failures (same
    /// shape as the SIGHUP-reload counters on `ServerMetrics`).
    reload_attempts_total: std::sync::atomic::AtomicU64,
    /// Cumulative SIGHUP-driven reloads that returned an I/O error.
    /// In normal operation this stays 0; a non-zero rate is a
    /// strong signal that the operator's hand-edit produced an
    /// unreadable file (permission flip, truncation, etc.).
    reload_failed_total: std::sync::atomic::AtomicU64,
}

impl UserQuarantineList {
    /// Build a new quarantine list. `ttl=0` is treated as "wired
    /// but disabled" — every `insert` is a no-op; every `check`
    /// returns `Allowed`. Matches the slot pattern of every other
    /// detector knob in the binary.
    ///
    /// Recommended production values:
    ///   - `ttl = 10 minutes` for personal-VPN-for-friends (long
    ///     enough to interrupt an attacker, short enough for
    ///     legitimate users to retry after a false positive).
    ///   - `ttl = 60 minutes` for stricter deployments where the
    ///     operator wants a human in the loop before lifting.
    ///   - `max_entries = 4096` mirrors the per-user bandwidth /
    ///     conn-limit defaults.
    #[must_use]
    pub fn new(ttl: Duration, max_entries: usize) -> Self {
        Self {
            ttl,
            max_entries,
            inner: Mutex::new(HashMap::new()),
            session_notifiers: Mutex::new(HashMap::new()),
            last_vacuum: Mutex::new(Instant::now()),
            inserted_total: std::sync::atomic::AtomicU64::new(0),
            refused_inserts_total: std::sync::atomic::AtomicU64::new(0),
            quarantine_hits_total: std::sync::atomic::AtomicU64::new(0),
            sessions_torn_down_total: std::sync::atomic::AtomicU64::new(0),
            persistence_path: Mutex::new(None),
            persist_attempts_total: std::sync::atomic::AtomicU64::new(0),
            persist_failed_total: std::sync::atomic::AtomicU64::new(0),
            loaded_from_disk: std::sync::atomic::AtomicU64::new(0),
            manual_unquarantines_total: std::sync::atomic::AtomicU64::new(0),
            reload_attempts_total: std::sync::atomic::AtomicU64::new(0),
            reload_failed_total: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Builder: enable on-insert persistence to the given file
    /// path. Every successful insert (fresh or refresh) writes the
    /// current map to disk atomically (temp file + rename). Pair
    /// with [`Self::load_from_disk`] at startup to seed the
    /// in-memory map from a previous run.
    ///
    /// File format: JSON Lines, one entry per row, with a
    /// versioned header on the first line. Operator-readable +
    /// hand-editable for emergency unbans.
    #[must_use]
    pub fn with_persistence(self, path: PathBuf) -> Self {
        {
            let mut g = self
                .persistence_path
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            *g = Some(path);
        }
        self
    }

    /// Cumulative persist attempts (counter).
    #[must_use]
    pub fn persist_attempts_total(&self) -> u64 {
        self.persist_attempts_total
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Cumulative persist failures (counter).
    #[must_use]
    pub fn persist_failed_total(&self) -> u64 {
        self.persist_failed_total
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Count of entries restored from disk on startup (gauge —
    /// set once during `load_from_disk`).
    #[must_use]
    pub fn loaded_from_disk(&self) -> u64 {
        self.loaded_from_disk
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Load a previously-persisted list from `path`. Filters out
    /// already-expired entries (vs. wall-clock now). On any I/O
    /// or parse error, logs the error and returns an empty list
    /// at the configured TTL/max — operators get a working
    /// quarantine, not a startup-fail. The bumped
    /// `persist_failed_total` counter surfaces the issue without
    /// blocking the binary.
    ///
    /// `path` is ALSO stored on the returned instance, so
    /// subsequent inserts persist back to the same file (no need
    /// for the caller to chain `with_persistence` separately).
    #[must_use]
    pub fn load_from_disk(path: PathBuf, ttl: Duration, max_entries: usize) -> Self {
        let list = Self::new(ttl, max_entries).with_persistence(path.clone());
        let raw = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    // Fresh start — file doesn't exist yet. Not
                    // an error; just an empty restore.
                    tracing::info!(
                        path = ?path,
                        "user_quarantine: no persistence file yet (fresh start)"
                    );
                } else {
                    tracing::warn!(
                        path = ?path,
                        error = %e,
                        "user_quarantine: read persistence file failed; starting empty"
                    );
                    list.persist_failed_total
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                return list;
            }
        };
        let now_instant = Instant::now();
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        let mut loaded = 0u64;
        let mut skipped_expired = 0u64;
        let mut g = list.inner.lock().unwrap_or_else(|p| p.into_inner());
        for (lineno, line) in raw.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // Header line — version sentinel. Tolerate absence
            // (legacy files) and unknown-but-present (forward
            // compat).
            if line.starts_with(r#"{"kind":"header""#) {
                continue;
            }
            match parse_entry_line(line) {
                Ok((uid, expires_unix, triggered_by)) => {
                    if expires_unix <= now_unix {
                        skipped_expired += 1;
                        continue;
                    }
                    let remaining = Duration::from_secs(expires_unix - now_unix);
                    let expires_at = now_instant + remaining;
                    g.insert(
                        uid,
                        QuarantineEntry {
                            expires_at,
                            triggered_by_kind: triggered_by,
                        },
                    );
                    loaded += 1;
                    if g.len() >= max_entries {
                        tracing::warn!(
                            "user_quarantine: load hit max_entries cap ({max_entries}); truncating restore"
                        );
                        break;
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        path = ?path,
                        lineno = lineno + 1,
                        error = %e,
                        "user_quarantine: skipping unparseable persistence line"
                    );
                }
            }
        }
        drop(g);
        list.loaded_from_disk
            .store(loaded, std::sync::atomic::Ordering::Relaxed);
        tracing::info!(
            path = ?path,
            loaded,
            skipped_expired,
            "user_quarantine: restored state from disk"
        );
        list
    }

    /// Write the current map to disk atomically. Called
    /// automatically inside `insert_at` when persistence is wired.
    /// Operators rarely need to call this directly — exposed for
    /// tests + a future `admin quarantine snapshot` CLI.
    pub fn persist(&self) -> std::io::Result<()> {
        self.persist_attempts_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = {
            let g = self
                .persistence_path
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            match g.as_ref() {
                Some(p) => p.clone(),
                None => return Ok(()), // no-op when persistence not wired
            }
        };
        // Snapshot the map outside the disk I/O so the inner
        // mutex isn't held across a potentially-slow fsync.
        let now_instant = Instant::now();
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        let entries: Vec<(String, u64, &'static str)> = {
            let g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            g.iter()
                .filter_map(|(uid, e)| {
                    if e.expires_at <= now_instant {
                        return None;
                    }
                    let remaining = (e.expires_at - now_instant).as_secs();
                    let expires_unix = now_unix.saturating_add(remaining);
                    Some((
                        crate::per_user_bandwidth::render_user_id_pub(uid),
                        expires_unix,
                        e.triggered_by_kind,
                    ))
                })
                .collect()
        };
        let mut body = String::with_capacity(96 + entries.len() * 80);
        body.push_str(
            r#"{"kind":"header","schema_version":1,"format":"proteus_user_quarantine_v1"}"#,
        );
        body.push('\n');
        for (uid_render, expires_unix, triggered_by) in &entries {
            // user_id rendering already escapes `"` and `\`; the
            // `triggered_by` label is a static enum string from
            // AbuseFireKind::as_label() so it's safe verbatim.
            body.push_str(&format!(
                r#"{{"user_id":"{uid_render}","expires_unix_seconds":{expires_unix},"triggered_by":"{triggered_by}"}}"#
            ));
            body.push('\n');
        }
        // Atomic write: write to a temp file in the same directory
        // (so rename is on the same filesystem), fsync, rename. On
        // any error, bump the failure counter — but DON'T panic;
        // the in-memory map is still authoritative.
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let mut tmp = parent.join(format!(
            ".proteus_user_quarantine.{}.tmp",
            std::process::id()
        ));
        if let Some(file_name) = path.file_name() {
            tmp = parent.join(format!(
                ".{}.{}.tmp",
                file_name.to_string_lossy(),
                std::process::id()
            ));
        }
        if let Err(e) = std::fs::write(&tmp, body.as_bytes()) {
            self.persist_failed_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::warn!(path = ?tmp, error = %e, "user_quarantine: temp write failed");
            return Err(e);
        }
        // Iter-148: fsync + chmod 0600 before rename. Same
        // rationale as user_quota::persist — POSIX rename is
        // atomic at the directory-entry layer but NOT at the
        // data-page layer; the quarantine state contains
        // operator-chosen user_id strings which on a multi-tenant
        // host are PII; both fixes pay only on the persist path.
        match std::fs::File::open(&tmp) {
            Ok(f) => {
                if let Err(e) = f.sync_all() {
                    tracing::warn!(path = ?tmp, error = %e, "user_quarantine: tmp fsync failed (non-fatal)");
                }
            }
            Err(e) => {
                tracing::warn!(path = ?tmp, error = %e, "user_quarantine: re-open for fsync failed (non-fatal)");
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)) {
                tracing::warn!(path = ?tmp, error = %e, "user_quarantine: chmod 0600 failed (non-fatal)");
            }
        }
        if let Err(e) = std::fs::rename(&tmp, &path) {
            self.persist_failed_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::warn!(
                from = ?tmp,
                to = ?path,
                error = %e,
                "user_quarantine: atomic rename failed"
            );
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        if let Ok(parent_f) = std::fs::File::open(parent) {
            let _ = parent_f.sync_all();
        }
        Ok(())
    }

    /// Register a new in-flight session for `user_id`. Returns an
    /// `Arc<Notify>` the session's pump loop should `.notified()`
    /// on alongside its normal `recv_record()`. When the user_id
    /// is quarantined, the notify fires for ALL in-flight sessions
    /// for that user_id at once — closing the "mid-burst exfil
    /// keeps running until idle timeout" gap.
    ///
    /// Callers MUST drop the returned Arc when the session ends so
    /// the registry's Weak handles vacuum on the next walk.
    ///
    /// **Idempotent / lock-free fast path**: each call appends one
    /// fresh `Arc<Notify>` per session (sessions for the same
    /// user_id get DIFFERENT Arcs — they share the user_id key in
    /// the map, but each session holds its own notify so cleanup
    /// is one-to-one).
    #[must_use]
    pub fn register_session(&self, user_id: [u8; 8]) -> Arc<Notify> {
        let notify = Arc::new(Notify::new());
        let mut g = self
            .session_notifiers
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let entry = g.entry(user_id).or_default();
        // Vacuum dead weaks for this user_id while we hold the
        // lock — keeps the per-user Vec bounded by the actual
        // in-flight session count.
        entry.retain(|w| w.strong_count() > 0);
        entry.push(Arc::downgrade(&notify));
        notify
    }

    /// Wake all in-flight sessions for `user_id` so they tear down
    /// immediately. Returns the count of sessions notified
    /// (= the count of live `Arc<Notify>` strong-refs we upgraded).
    /// Bumps `sessions_torn_down_total` by that count.
    ///
    /// Called automatically inside [`Self::insert_at`] on a fresh
    /// quarantine insert (i.e. one we accepted, not refused). Can
    /// also be called directly by operator tooling for an
    /// emergency manual ban.
    pub fn tear_down_user(&self, user_id: &[u8; 8]) -> usize {
        let mut g = self
            .session_notifiers
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let Some(entry) = g.get_mut(user_id) else {
            return 0;
        };
        let mut woken = 0usize;
        entry.retain(|w| {
            if let Some(n) = w.upgrade() {
                // notify_waiters() wakes every awaiter currently
                // parked on .notified(); the session's select!
                // branch then drops the read futures and runs
                // its access-log + Drop cleanup.
                n.notify_waiters();
                woken += 1;
                true
            } else {
                false
            }
        });
        // If every session has now dropped, remove the empty Vec
        // so the map shrinks back to bounded.
        if entry.is_empty() {
            g.remove(user_id);
        }
        self.sessions_torn_down_total
            .fetch_add(woken as u64, std::sync::atomic::Ordering::Relaxed);
        woken
    }

    /// Cumulative count of sessions torn down by `tear_down_user`.
    #[must_use]
    pub fn sessions_torn_down_total(&self) -> u64 {
        self.sessions_torn_down_total
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Manually clear `user_id`'s quarantine entry — the operator
    /// override path for false positives.
    ///
    /// Returns `true` if there was an entry to remove. Persists
    /// the new state immediately so the unban survives the next
    /// process restart. Does NOT bump any error counters — this is
    /// an operator-driven event, not a fault.
    ///
    /// **Does NOT tear down sessions.** When the operator unbans a
    /// user, any sessions that user MIGHT have open (typically
    /// none, since the quarantine had been blocking them) should
    /// continue normally. The tear-down path is only for new bans,
    /// not new unbans.
    pub fn unquarantine(&self, user_id: &[u8; 8]) -> bool {
        let removed = {
            let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            g.remove(user_id).is_some()
        };
        if removed {
            self.manual_unquarantines_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            // Surfaced so operators can grep journald to confirm
            // the unban took effect.
            tracing::info!(
                user_id = %crate::per_user_bandwidth::render_user_id_pub(user_id),
                "user_quarantine: manual unquarantine (operator override)"
            );
            // Persist the new state. Failure is logged inside
            // persist() and bumps persist_failed_total; we don't
            // surface it here because the in-memory unban
            // succeeded (which is what the operator asked for).
            let _ = self.persist();
        }
        removed
    }

    /// Cumulative manual unquarantine calls (counter).
    #[must_use]
    pub fn manual_unquarantines_total(&self) -> u64 {
        self.manual_unquarantines_total
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Cumulative SIGHUP-driven reload attempts (counter).
    #[must_use]
    pub fn reload_attempts_total(&self) -> u64 {
        self.reload_attempts_total
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Cumulative SIGHUP-driven reload failures (counter).
    #[must_use]
    pub fn reload_failed_total(&self) -> u64 {
        self.reload_failed_total
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Reconcile the in-memory map against the on-disk persistence
    /// file. Used by the SIGHUP handler so operators can hand-edit
    /// the file (add an emergency ban, lift a false-positive,
    /// extend a TTL) and have the running process pick up the
    /// changes WITHOUT a restart.
    ///
    /// Semantics:
    ///   - File entry not in memory → INSERT + tear down sessions
    ///     (operator added a fresh ban).
    ///   - Memory entry not in file → REMOVE (operator lifted the
    ///     ban; existing sessions, if any, are NOT torn down —
    ///     they were the targets of the lift).
    ///   - Entry in both with different `expires_at` /
    ///     `triggered_by` → UPDATE in place. Tear down sessions
    ///     ONLY when the expiry moved FORWARD (operator extended
    ///     the ban — re-arm the enforcement). Don't tear down on
    ///     shortened expiry (operator wants the ban to end sooner;
    ///     no reason to be aggressive).
    ///   - Expired entries in the file are skipped.
    ///
    /// Returns the reconciliation outcome. The SIGHUP handler
    /// uses it to bump observability counters + emit a structured
    /// info log so operators see what landed.
    ///
    /// When no persistence path is wired, returns
    /// `Ok(ReloadOutcome::default())` — a no-op the SIGHUP handler
    /// can issue safely on every signal.
    pub fn reload_from_disk(&self) -> std::io::Result<ReloadOutcome> {
        self.reload_attempts_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = {
            let g = self
                .persistence_path
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            match g.as_ref() {
                Some(p) => p.clone(),
                None => return Ok(ReloadOutcome::default()),
            }
        };
        // Read + parse the file outside the inner lock so we don't
        // hold the map lock across the I/O. This is safe because
        // the canonical state during reconciliation is the file
        // contents — any concurrent insert will be re-applied on
        // the NEXT persist (or its own write will land first; the
        // map is monotonic in the sense that lost-write races are
        // resolved at next reconcile).
        let raw = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Missing file = "no quarantines on disk" = remove
                // every in-memory entry. Operator deleted the
                // file to lift all bans.
                let removed = {
                    let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
                    let n = g.len() as u64;
                    g.clear();
                    n
                };
                tracing::info!(
                    path = ?path,
                    removed,
                    "user_quarantine: reload found missing file → cleared {removed} in-memory entries"
                );
                let _ = self.persist();
                return Ok(ReloadOutcome {
                    removed,
                    ..ReloadOutcome::default()
                });
            }
            Err(e) => {
                self.reload_failed_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Err(e);
            }
        };
        let now_instant = Instant::now();
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        // Build the new desired state from the file.
        let mut desired: HashMap<[u8; 8], (Instant, &'static str)> = HashMap::new();
        let mut skipped_expired = 0u64;
        let mut malformed = 0u64;
        for line in raw.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.starts_with(r#"{"kind":"header""#) {
                continue;
            }
            match parse_entry_line(line) {
                Ok((uid, expires_unix, triggered_by)) => {
                    if expires_unix <= now_unix {
                        skipped_expired += 1;
                        continue;
                    }
                    let remaining = Duration::from_secs(expires_unix - now_unix);
                    desired.insert(uid, (now_instant + remaining, triggered_by));
                }
                Err(_) => {
                    malformed += 1;
                }
            }
        }
        let (added, removed, refreshed, to_tear_down) = {
            let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            let mut added = 0u64;
            let mut refreshed = 0u64;
            let mut to_tear_down: Vec<[u8; 8]> = Vec::new();
            // Cap-check before inserting new entries — if the
            // file holds more entries than max_entries, truncate
            // (operator gets a WARN at the call site).
            let mut current_in_file = desired.len();
            for (uid, (new_expires, new_triggered_by)) in &desired {
                if let Some(existing) = g.get_mut(uid) {
                    let expires_advanced = *new_expires > existing.expires_at;
                    if *new_expires != existing.expires_at
                        || existing.triggered_by_kind != *new_triggered_by
                    {
                        existing.expires_at = *new_expires;
                        existing.triggered_by_kind = *new_triggered_by;
                        refreshed += 1;
                        if expires_advanced {
                            to_tear_down.push(*uid);
                        }
                    }
                } else {
                    if g.len() >= self.max_entries {
                        // Honor the cap — drop additional entries
                        // silently here, the loop body completes
                        // for already-counted ones.
                        current_in_file = current_in_file.saturating_sub(1);
                        continue;
                    }
                    g.insert(
                        *uid,
                        QuarantineEntry {
                            expires_at: *new_expires,
                            triggered_by_kind: new_triggered_by,
                        },
                    );
                    added += 1;
                    to_tear_down.push(*uid);
                }
            }
            // Removes: anything in memory but not in desired.
            let to_remove: Vec<[u8; 8]> = g
                .keys()
                .filter(|k| !desired.contains_key(*k))
                .copied()
                .collect();
            let removed = to_remove.len() as u64;
            for k in &to_remove {
                g.remove(k);
            }
            let _ = current_in_file; // surface for future logging
            (added, removed, refreshed, to_tear_down)
        };
        // Tear down sessions for new + extended bans. Do this
        // OUTSIDE the inner lock to keep the data-plane responsive.
        for uid in &to_tear_down {
            self.tear_down_user(uid);
        }
        let outcome = ReloadOutcome {
            added,
            removed,
            refreshed,
            skipped_expired,
            malformed,
        };
        tracing::info!(
            path = ?path,
            added = outcome.added,
            removed = outcome.removed,
            refreshed = outcome.refreshed,
            skipped_expired = outcome.skipped_expired,
            malformed = outcome.malformed,
            "user_quarantine: reconciled in-memory map against disk file"
        );
        // Persist the reconciled state — covers the
        // expired-skip case (the file may have rows we filtered
        // out as expired; a re-persist drops them from disk too).
        let _ = self.persist();
        Ok(outcome)
    }

    /// Configured TTL.
    #[must_use]
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Configured max entries.
    #[must_use]
    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// True when the quarantine is wired but inert (`ttl == 0`).
    /// Operators get the gauge surface for SIGHUP-swap workflows
    /// but no user is ever quarantined.
    #[must_use]
    pub fn is_disabled(&self) -> bool {
        self.ttl.is_zero()
    }

    /// Insert (or refresh) a quarantine entry for `user_id`.
    /// `triggered_by` is the abuse-fire kind label (e.g.
    /// `"per_user_bandwidth_rate"`); surfaced in the `/diagnose`
    /// table so operators see WHY the user was quarantined.
    ///
    /// Returns `true` if the entry was newly inserted OR refreshed
    /// (count climbed past 0 OR the deadline moved forward); returns
    /// `false` if the insert was refused (disabled OR cap reached
    /// for a brand-new user_id). Callers use the bool to bump
    /// a structured-log surface.
    pub fn insert(&self, user_id: [u8; 8], triggered_by: &'static str) -> bool {
        self.insert_at(user_id, triggered_by, Instant::now())
    }

    /// Test-friendly: same as [`Self::insert`] but with explicit
    /// `now` instead of `Instant::now()`. Allows unit tests to
    /// exercise TTL semantics deterministically.
    pub fn insert_at(&self, user_id: [u8; 8], triggered_by: &'static str, now: Instant) -> bool {
        if self.ttl.is_zero() {
            return false;
        }
        let expires_at = now + self.ttl;
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if g.contains_key(&user_id) {
            // Refresh: bump the deadline and update the trigger so
            // the most recent detector kind is what's surfaced.
            let entry = g.get_mut(&user_id).unwrap();
            entry.expires_at = expires_at;
            entry.triggered_by_kind = triggered_by;
            self.inserted_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            // Drop the inner lock BEFORE notifying — tear_down_user
            // takes session_notifiers, and holding both at once
            // would invite lock-ordering trouble for future paths.
            drop(g);
            // Refresh-insert ALSO tears down: an attacker who's
            // already quarantined but still has long-running
            // sessions up needs them killed, not just blocked
            // from opening new ones.
            self.tear_down_user(&user_id);
            // Persist refresh — the bumped expiry is the freshest
            // signal and must survive a restart.
            let _ = self.persist();
            return true;
        }
        if g.len() >= self.max_entries {
            self.refused_inserts_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return false;
        }
        g.insert(
            user_id,
            QuarantineEntry {
                expires_at,
                triggered_by_kind: triggered_by,
            },
        );
        self.inserted_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        drop(g);
        // Fresh insert: wake every in-flight session for this
        // user_id. The mid-burst exfiltrator is now dead in the
        // water — they don't get to finish their current upload
        // before the quarantine takes effect.
        self.tear_down_user(&user_id);
        // Persist the fresh insert so the ban survives a process
        // restart (the gap this whole iteration closes).
        let _ = self.persist();
        true
    }

    /// Check whether `user_id` is currently quarantined. Returns
    /// `Some(seconds_remaining)` if quarantined, `None` if allowed
    /// (no entry, OR entry expired).
    ///
    /// Always runs the amortized vacuum first so a long-idle map
    /// with one expired entry doesn't stay reporting "quarantined"
    /// forever. The vacuum cost is bounded because (a) it only
    /// fires once per `VACUUM_INTERVAL`, (b) the map is bounded
    /// by `max_entries`.
    ///
    /// Bumps `quarantine_hits_total` on every positive hit — the
    /// "did the quarantine actually save us?" counter.
    pub fn check(&self, user_id: &[u8; 8]) -> Option<u64> {
        self.check_at(user_id, Instant::now())
    }

    /// Test-friendly: same as [`Self::check`] but with explicit `now`.
    pub fn check_at(&self, user_id: &[u8; 8], now: Instant) -> Option<u64> {
        if self.ttl.is_zero() {
            return None;
        }
        self.maybe_vacuum(now);
        let g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let entry = g.get(user_id)?;
        if entry.expires_at <= now {
            // Entry expired but the vacuum hasn't run yet OR our
            // window had a stale entry — treat as allowed. The
            // next vacuum (or next insert past the cap) cleans up.
            return None;
        }
        let remaining = entry.expires_at - now;
        self.quarantine_hits_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Some(remaining.as_secs())
    }

    fn maybe_vacuum(&self, now: Instant) {
        let mut last = self.last_vacuum.lock().unwrap_or_else(|p| p.into_inner());
        if now.duration_since(*last) < VACUUM_INTERVAL {
            return;
        }
        *last = now;
        drop(last); // release before taking inner lock
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        g.retain(|_, entry| entry.expires_at > now);
    }

    /// Snapshot active entries for `/diagnose` + `admin status`.
    /// Sorted by `expires_in_secs` ascending (soonest-to-clear
    /// first, matches `auto_deny.rs::active_snapshot` convention).
    /// Returns at most `limit` entries.
    #[must_use]
    pub fn active_snapshot(&self, limit: usize) -> Vec<ActiveQuarantine> {
        self.active_snapshot_at(limit, Instant::now())
    }

    /// Test-friendly snapshot variant taking explicit `now`.
    #[must_use]
    pub fn active_snapshot_at(&self, limit: usize, now: Instant) -> Vec<ActiveQuarantine> {
        let g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let mut out: Vec<ActiveQuarantine> = g
            .iter()
            .filter_map(|(uid, entry)| {
                if entry.expires_at <= now {
                    return None;
                }
                Some(ActiveQuarantine {
                    user_id: crate::per_user_bandwidth::render_user_id_pub(uid),
                    expires_in_secs: (entry.expires_at - now).as_secs(),
                    triggered_by: entry.triggered_by_kind.to_string(),
                })
            })
            .collect();
        out.sort_by_key(|q| q.expires_in_secs);
        out.truncate(limit);
        out
    }

    /// Count of currently-active quarantine entries (gauge — used
    /// in `/metrics`).
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.active_count_at(Instant::now())
    }

    /// Test-friendly count taking explicit `now`.
    #[must_use]
    pub fn active_count_at(&self, now: Instant) -> usize {
        let g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        g.values().filter(|e| e.expires_at > now).count()
    }

    /// Cumulative inserts (counter).
    #[must_use]
    pub fn inserted_total(&self) -> u64 {
        self.inserted_total
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Cumulative refused inserts (counter).
    #[must_use]
    pub fn refused_inserts_total(&self) -> u64 {
        self.refused_inserts_total
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Cumulative quarantine hits (counter).
    #[must_use]
    pub fn quarantine_hits_total(&self) -> u64 {
        self.quarantine_hits_total
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Emit the Prometheus exposition block.
    ///
    /// Six series total (all `proteus_user_quarantine_*` prefix):
    ///   - `_ttl_seconds` gauge — configured TTL
    ///   - `_max_entries` gauge — configured cap
    ///   - `_active_entries` gauge — current population
    ///   - `_inserted_total` counter — cumulative inserts
    ///   - `_refused_inserts_total` counter — cumulative cap rejects
    ///   - `_hits_total` counter — handshakes blocked at admission
    ///     because the user was quarantined
    ///
    /// Per-entry contents are NOT exposed as labelled series
    /// (cardinality explosion — same rationale as
    /// `abuse_fires.rs`). Operators consume the active entries
    /// via `/diagnose`.
    #[must_use]
    pub fn prometheus(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(512);
        let _ = writeln!(
            s,
            "# HELP proteus_user_quarantine_ttl_seconds \
             Operator-set TTL applied to each quarantine entry on insert. \
             0 = quarantine wired but disabled."
        );
        let _ = writeln!(s, "# TYPE proteus_user_quarantine_ttl_seconds gauge");
        let _ = writeln!(
            s,
            "proteus_user_quarantine_ttl_seconds {}",
            self.ttl.as_secs()
        );
        let _ = writeln!(
            s,
            "# HELP proteus_user_quarantine_max_entries \
             Hard cap on quarantine map size."
        );
        let _ = writeln!(s, "# TYPE proteus_user_quarantine_max_entries gauge");
        let _ = writeln!(
            s,
            "proteus_user_quarantine_max_entries {}",
            self.max_entries
        );
        let _ = writeln!(
            s,
            "# HELP proteus_user_quarantine_active_entries \
             Current number of user_ids in quarantine (not expired)."
        );
        let _ = writeln!(s, "# TYPE proteus_user_quarantine_active_entries gauge");
        let _ = writeln!(
            s,
            "proteus_user_quarantine_active_entries {}",
            self.active_count()
        );
        let _ = writeln!(
            s,
            "# HELP proteus_user_quarantine_inserted_total \
             Cumulative quarantine inserts (includes refreshes)."
        );
        let _ = writeln!(s, "# TYPE proteus_user_quarantine_inserted_total counter");
        let _ = writeln!(
            s,
            "proteus_user_quarantine_inserted_total {}",
            self.inserted_total()
        );
        let _ = writeln!(
            s,
            "# HELP proteus_user_quarantine_refused_inserts_total \
             Inserts refused because max_entries was reached. \
             Non-zero rate = either operator should raise the cap OR an attacker is \
             pivoting credentials to overflow the map."
        );
        let _ = writeln!(
            s,
            "# TYPE proteus_user_quarantine_refused_inserts_total counter"
        );
        let _ = writeln!(
            s,
            "proteus_user_quarantine_refused_inserts_total {}",
            self.refused_inserts_total()
        );
        let _ = writeln!(
            s,
            "# HELP proteus_user_quarantine_hits_total \
             Handshakes rejected at admission because the user_id was \
             quarantined. The 'quarantine actually saved us' counter."
        );
        let _ = writeln!(s, "# TYPE proteus_user_quarantine_hits_total counter");
        let _ = writeln!(
            s,
            "proteus_user_quarantine_hits_total {}",
            self.quarantine_hits_total()
        );
        let _ = writeln!(
            s,
            "# HELP proteus_user_quarantine_sessions_torn_down_total \
             Cumulative count of IN-FLIGHT sessions killed when their \
             user_id was newly quarantined. The 'we caught a mid-burst \
             exfiltrator' counter — distinct from hits_total, which only \
             counts NEW handshakes blocked at admission."
        );
        let _ = writeln!(
            s,
            "# TYPE proteus_user_quarantine_sessions_torn_down_total counter"
        );
        let _ = writeln!(
            s,
            "proteus_user_quarantine_sessions_torn_down_total {}",
            self.sessions_torn_down_total()
        );
        let _ = writeln!(
            s,
            "# HELP proteus_user_quarantine_persist_attempts_total \
             Cumulative disk-persistence write attempts. Bumped on \
             every insert when persistence is wired."
        );
        let _ = writeln!(
            s,
            "# TYPE proteus_user_quarantine_persist_attempts_total counter"
        );
        let _ = writeln!(
            s,
            "proteus_user_quarantine_persist_attempts_total {}",
            self.persist_attempts_total()
        );
        let _ = writeln!(
            s,
            "# HELP proteus_user_quarantine_persist_failed_total \
             Disk-persistence write failures. Alert on \
             `attempts - succeeded > 0` (i.e. `failed > 0`) — bans \
             will not survive a restart if persistence is silently \
             failing."
        );
        let _ = writeln!(
            s,
            "# TYPE proteus_user_quarantine_persist_failed_total counter"
        );
        let _ = writeln!(
            s,
            "proteus_user_quarantine_persist_failed_total {}",
            self.persist_failed_total()
        );
        let _ = writeln!(
            s,
            "# HELP proteus_user_quarantine_loaded_from_disk \
             Entries restored from the on-disk persistence file at \
             process startup. Operators read this on a fresh process \
             to confirm prior bans were restored."
        );
        let _ = writeln!(s, "# TYPE proteus_user_quarantine_loaded_from_disk gauge");
        let _ = writeln!(
            s,
            "proteus_user_quarantine_loaded_from_disk {}",
            self.loaded_from_disk()
        );
        let _ = writeln!(
            s,
            "# HELP proteus_user_quarantine_manual_unquarantines_total \
             Operator-driven manual unquarantine calls (false-positive \
             overrides). Each successful removal bumps the counter."
        );
        let _ = writeln!(
            s,
            "# TYPE proteus_user_quarantine_manual_unquarantines_total counter"
        );
        let _ = writeln!(
            s,
            "proteus_user_quarantine_manual_unquarantines_total {}",
            self.manual_unquarantines_total()
        );
        let _ = writeln!(
            s,
            "# HELP proteus_user_quarantine_reload_attempts_total \
             SIGHUP-driven reload attempts (operator hand-edited the \
             persistence file + sent SIGHUP). Bumped on every reload \
             call regardless of outcome."
        );
        let _ = writeln!(
            s,
            "# TYPE proteus_user_quarantine_reload_attempts_total counter"
        );
        let _ = writeln!(
            s,
            "proteus_user_quarantine_reload_attempts_total {}",
            self.reload_attempts_total()
        );
        let _ = writeln!(
            s,
            "# HELP proteus_user_quarantine_reload_failed_total \
             SIGHUP-driven reloads that returned an I/O error. Alert \
             on rate > 0 — the operator's hand-edit may have produced \
             an unreadable file."
        );
        let _ = writeln!(
            s,
            "# TYPE proteus_user_quarantine_reload_failed_total counter"
        );
        let _ = writeln!(
            s,
            "proteus_user_quarantine_reload_failed_total {}",
            self.reload_failed_total()
        );
        s
    }

    /// Render the active-quarantine table for `/diagnose`. Sorted
    /// soonest-to-clear first; column header matches `auto_deny.rs`
    /// for operator familiarity.
    #[must_use]
    pub fn diagnose_table(&self, now_unix_seconds: u64) -> String {
        let _ = now_unix_seconds; // accepted for signature symmetry with abuse_fires
        let snap = self.active_snapshot(64);
        if snap.is_empty() {
            return String::from("USER QUARANTINE: (none active)\n");
        }
        use std::fmt::Write as _;
        let mut s = String::with_capacity(384);
        let _ = writeln!(
            s,
            "USER QUARANTINE ({} active, soonest-to-clear first):",
            snap.len()
        );
        let _ = writeln!(s, "  {:>10}  {:<24}  user_id", "expires_s", "triggered_by");
        for q in &snap {
            let _ = writeln!(
                s,
                "  {:>10}  {:<24}  {}",
                q.expires_in_secs, q.triggered_by, q.user_id
            );
        }
        s
    }
}

/// Map a `triggered_by` label loaded from disk back to the
/// `&'static str` form the in-memory struct expects. Only known
/// AbuseFireKind labels are accepted; an unknown label is mapped
/// to the static `"unknown"` so the entry is preserved (we don't
/// want to drop a valid quarantine just because a future
/// detector-kind name shows up in an old file).
fn intern_triggered_by(label: &str) -> &'static str {
    match label {
        "byte_budget" => crate::abuse_fires::AbuseFireKind::ByteBudget.as_label(),
        "rate_limit" => crate::abuse_fires::AbuseFireKind::RateLimit.as_label(),
        "per_user_bandwidth_rate" => {
            crate::abuse_fires::AbuseFireKind::PerUserBandwidthRate.as_label()
        }
        "test_trigger" => "test_trigger",
        "manual" => "manual",
        _ => "unknown",
    }
}

/// Parse one persisted entry line. Hand-rolled (vs. pulling in
/// serde_json) because the schema is tiny + fixed; the parser
/// only has to find three field values: `user_id`,
/// `expires_unix_seconds`, `triggered_by`. Returns Err on any
/// malformation — the caller drops the line and logs.
fn parse_entry_line(line: &str) -> Result<([u8; 8], u64, &'static str), String> {
    // user_id field — first quoted value AFTER `"user_id":"`
    let uid_str =
        extract_string_field(line, "user_id").ok_or_else(|| "missing user_id field".to_string())?;
    let uid = decode_user_id(&uid_str)?;
    let expires_unix = extract_u64_field(line, "expires_unix_seconds")
        .ok_or_else(|| "missing expires_unix_seconds field".to_string())?;
    let triggered_by = extract_string_field(line, "triggered_by")
        .ok_or_else(|| "missing triggered_by field".to_string())?;
    Ok((uid, expires_unix, intern_triggered_by(&triggered_by)))
}

/// Find a `"name":"value"` pair in `s` and return the `value`
/// portion (with surrounding quotes stripped). Returns None if
/// the field isn't present.
fn extract_string_field(s: &str, name: &str) -> Option<String> {
    let needle = format!(r#""{name}":""#);
    let start = s.find(&needle)? + needle.len();
    // Find the next un-escaped `"`. The producer side already
    // strips `"` and `\` from user-supplied strings via the
    // render_user_id_pub ASCII-or-hex filter; the triggered_by
    // field is a const enum string. So we don't need to handle
    // escapes here — a future format change that needs escapes
    // would also bump the schema_version sentinel.
    let rest = &s[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Find a `"name":N` (integer, no quotes) field and parse it as u64.
fn extract_u64_field(s: &str, name: &str) -> Option<u64> {
    let needle = format!(r#""{name}":"#);
    let start = s.find(&needle)? + needle.len();
    let rest = &s[start..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

/// Decode a user_id string back to `[u8; 8]`. The producer uses
/// the same `render_user_id_pub` strategy as the per-user
/// bandwidth labels: printable-ASCII verbatim (trimmed of nulls)
/// or `hex:<16hexchars>` for non-printable / escape-needing bytes.
fn decode_user_id(s: &str) -> Result<[u8; 8], String> {
    if let Some(hex) = s.strip_prefix("hex:") {
        if hex.len() != 16 {
            return Err(format!("hex user_id must be 16 chars; got {}", hex.len()));
        }
        let mut out = [0u8; 8];
        for i in 0..8 {
            out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                .map_err(|e| format!("hex user_id decode at byte {i}: {e}"))?;
        }
        return Ok(out);
    }
    // Printable-ASCII form. Pad with NULs to 8 bytes (matches
    // the producer's trim_trailing_nulls inverse).
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

    #[test]
    fn disabled_when_ttl_zero() {
        let q = UserQuarantineList::new(Duration::ZERO, 4096);
        assert!(q.is_disabled());
        assert!(!q.insert(*b"alice001", "byte_budget"));
        assert_eq!(q.check(b"alice001"), None);
    }

    #[test]
    fn insert_and_check_returns_remaining_secs() {
        let q = UserQuarantineList::new(secs(600), 4096);
        let now = Instant::now();
        assert!(q.insert_at(*b"alice001", "per_user_bandwidth_rate", now));
        let remaining = q.check_at(b"alice001", now).expect("must be quarantined");
        assert!(
            (599..=600).contains(&remaining),
            "remaining out of range: {remaining}"
        );
    }

    #[test]
    fn unquarantined_user_returns_none() {
        let q = UserQuarantineList::new(secs(600), 4096);
        q.insert(*b"alice001", "byte_budget");
        assert_eq!(q.check(b"bob00002"), None);
    }

    #[test]
    fn entry_expires_after_ttl() {
        let q = UserQuarantineList::new(secs(60), 4096);
        let now = Instant::now();
        q.insert_at(*b"alice001", "rate_limit", now);
        // Right at the boundary — entry should still be considered
        // expired (expires_at <= now branch).
        assert_eq!(q.check_at(b"alice001", now + secs(60)), None);
        // Well past — also expired.
        assert_eq!(q.check_at(b"alice001", now + secs(120)), None);
    }

    #[test]
    fn refresh_updates_deadline_and_trigger() {
        let q = UserQuarantineList::new(secs(60), 4096);
        let now = Instant::now();
        q.insert_at(*b"alice001", "byte_budget", now);
        // Refresh 30s later with a different trigger.
        q.insert_at(*b"alice001", "per_user_bandwidth_rate", now + secs(30));
        let snap = q.active_snapshot_at(64, now + secs(31));
        assert_eq!(snap.len(), 1);
        // Triggered_by reflects the most recent insert.
        assert_eq!(snap[0].triggered_by, "per_user_bandwidth_rate");
        // Remaining ≈ 59s (60s TTL, 1s after the refresh).
        assert!(
            snap[0].expires_in_secs >= 58 && snap[0].expires_in_secs <= 60,
            "refreshed entry's TTL not restarted: {}",
            snap[0].expires_in_secs
        );
    }

    #[test]
    fn cap_refuses_new_inserts_but_keeps_existing() {
        let q = UserQuarantineList::new(secs(60), 2);
        let now = Instant::now();
        assert!(q.insert_at(*b"user0001", "byte_budget", now));
        assert!(q.insert_at(*b"user0002", "byte_budget", now));
        // Third user_id refused.
        assert!(!q.insert_at(*b"user0003", "byte_budget", now));
        assert_eq!(q.refused_inserts_total(), 1);
        assert_eq!(q.active_count_at(now), 2);
        // Existing entries still quarantined.
        assert!(q.check_at(b"user0001", now + secs(10)).is_some());
        assert!(q.check_at(b"user0002", now + secs(10)).is_some());
        // Refused user is NOT quarantined — caller saw `false` and
        // should NOT have treated the insert as successful.
        assert!(q.check_at(b"user0003", now + secs(10)).is_none());
    }

    #[test]
    fn vacuum_removes_expired_entries_eventually() {
        let q = UserQuarantineList::new(secs(30), 4096);
        let now = Instant::now();
        for i in 0..10u8 {
            let mut uid = *b"user0000";
            uid[7] = b'0' + i;
            q.insert_at(uid, "byte_budget", now);
        }
        assert_eq!(q.active_count_at(now), 10);
        // After TTL + the vacuum interval — both must elapse before
        // entries are physically removed from the map.
        let later = now + VACUUM_INTERVAL + secs(60);
        assert_eq!(q.active_count_at(later), 0);
        // The vacuum runs inside `check_at` — call it so the
        // physical map is cleaned. Then verify the map is empty.
        let _ = q.check_at(b"user0000", later);
        let inner = q.inner.lock().unwrap();
        assert_eq!(
            inner.len(),
            0,
            "vacuum must physically remove expired entries"
        );
    }

    #[test]
    fn hit_counter_bumps_only_on_quarantined_hits() {
        let q = UserQuarantineList::new(secs(60), 4096);
        let now = Instant::now();
        q.insert_at(*b"alice001", "rate_limit", now);
        // Miss — no bump.
        assert_eq!(q.check_at(b"bob00002", now), None);
        assert_eq!(q.quarantine_hits_total(), 0);
        // Hit — bump.
        assert!(q.check_at(b"alice001", now).is_some());
        assert_eq!(q.quarantine_hits_total(), 1);
        // Another hit — bump.
        assert!(q.check_at(b"alice001", now + secs(5)).is_some());
        assert_eq!(q.quarantine_hits_total(), 2);
    }

    #[test]
    fn active_snapshot_sorted_soonest_first_and_truncated() {
        let q = UserQuarantineList::new(secs(600), 4096);
        let now = Instant::now();
        // Three inserts at staggered times → different expiries.
        q.insert_at(*b"oldest00", "byte_budget", now);
        q.insert_at(*b"middle00", "rate_limit", now + secs(100));
        q.insert_at(*b"newest00", "per_user_bandwidth_rate", now + secs(200));
        let snap = q.active_snapshot_at(64, now + secs(250));
        assert_eq!(snap.len(), 3);
        assert_eq!(snap[0].user_id, "oldest00"); // soonest to expire (TTL elapsed first)
        assert_eq!(snap[1].user_id, "middle00");
        assert_eq!(snap[2].user_id, "newest00");
        // Truncation honored.
        let snap2 = q.active_snapshot_at(2, now + secs(250));
        assert_eq!(snap2.len(), 2);
        assert_eq!(snap2[0].user_id, "oldest00");
        assert_eq!(snap2[1].user_id, "middle00");
    }

    #[test]
    fn prometheus_emits_all_six_series_always() {
        let q = UserQuarantineList::new(secs(600), 4096);
        let s = q.prometheus();
        for name in [
            "proteus_user_quarantine_ttl_seconds",
            "proteus_user_quarantine_max_entries",
            "proteus_user_quarantine_active_entries",
            "proteus_user_quarantine_inserted_total",
            "proteus_user_quarantine_refused_inserts_total",
            "proteus_user_quarantine_hits_total",
        ] {
            assert!(s.contains(name), "missing {name} in:\n{s}");
        }
        // Disabled-mode TTL=0 still emits all six (operator surface
        // pattern — presence of the series tells operators the slot
        // is wired).
        let q0 = UserQuarantineList::new(Duration::ZERO, 4096);
        let s0 = q0.prometheus();
        assert!(s0.contains("proteus_user_quarantine_ttl_seconds 0"));
        assert!(s0.contains("proteus_user_quarantine_max_entries 4096"));
    }

    #[test]
    fn diagnose_table_renders_empty_marker_when_no_active() {
        let q = UserQuarantineList::new(secs(60), 4096);
        let s = q.diagnose_table(0);
        assert!(s.contains("(none active)"), "{s}");
    }

    #[test]
    fn diagnose_table_renders_user_trigger_and_expires() {
        let q = UserQuarantineList::new(secs(600), 4096);
        q.insert(*b"alice001", "per_user_bandwidth_rate");
        let s = q.diagnose_table(0);
        assert!(s.contains("alice001"), "{s}");
        assert!(s.contains("per_user_bandwidth_rate"), "{s}");
        assert!(s.contains("USER QUARANTINE"), "{s}");
    }

    #[tokio::test]
    async fn register_session_returns_notify_and_tear_down_wakes_it() {
        let q = UserQuarantineList::new(secs(60), 4096);
        let notify_a = q.register_session(*b"alice001");
        let notify_b = q.register_session(*b"alice001"); // second session
        let notify_c = q.register_session(*b"bob00002"); // unrelated

        // Spawn three tasks that park on .notified() and report
        // which one woke up.
        let notify_a_clone = Arc::clone(&notify_a);
        let notify_b_clone = Arc::clone(&notify_b);
        let notify_c_clone = Arc::clone(&notify_c);
        let task_a = tokio::spawn(async move {
            notify_a_clone.notified().await;
            "a-woke"
        });
        let task_b = tokio::spawn(async move {
            notify_b_clone.notified().await;
            "b-woke"
        });
        let task_c = tokio::spawn(async move {
            notify_c_clone.notified().await;
            "c-woke"
        });
        // Give the tasks time to register their .notified()
        // futures with each Notify.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Tear down alice's sessions — must wake A and B but
        // NOT C (bob's notify).
        let woken = q.tear_down_user(b"alice001");
        assert_eq!(woken, 2, "must wake both alice sessions");

        // A and B should resolve; C must still be parked.
        let a = tokio::time::timeout(Duration::from_secs(1), task_a)
            .await
            .expect("a must wake")
            .unwrap();
        assert_eq!(a, "a-woke");
        let b = tokio::time::timeout(Duration::from_secs(1), task_b)
            .await
            .expect("b must wake")
            .unwrap();
        assert_eq!(b, "b-woke");
        assert!(
            tokio::time::timeout(Duration::from_millis(100), task_c)
                .await
                .is_err(),
            "c MUST NOT have woken (different user_id)"
        );

        // Counter bumped by the tear-down.
        assert_eq!(q.sessions_torn_down_total(), 2);
    }

    #[tokio::test]
    async fn insert_at_tears_down_in_flight_sessions_for_user() {
        let q = UserQuarantineList::new(secs(60), 4096);
        let notify = q.register_session(*b"alice001");
        let notify_clone = Arc::clone(&notify);
        let task = tokio::spawn(async move {
            notify_clone.notified().await;
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        // Inserting alice should wake her in-flight session.
        let inserted = q.insert(*b"alice001", "per_user_bandwidth_rate");
        assert!(inserted);
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("insert must tear down in-flight session")
            .unwrap();
        assert_eq!(q.sessions_torn_down_total(), 1);
    }

    #[test]
    fn register_session_vacuums_dead_weak_handles() {
        let q = UserQuarantineList::new(secs(60), 4096);
        {
            let _n = q.register_session(*b"alice001");
        }
        // The first notify dropped. Registering a second session
        // for the same user_id should vacuum the dead weak.
        let _n2 = q.register_session(*b"alice001");
        let g = q.session_notifiers.lock().unwrap();
        let entry = g.get(b"alice001").unwrap();
        assert_eq!(
            entry.len(),
            1,
            "dead weaks must be vacuumed on next register: {entry:?}"
        );
    }

    #[test]
    fn tear_down_user_returns_zero_when_no_in_flight() {
        let q = UserQuarantineList::new(secs(60), 4096);
        let n = q.tear_down_user(b"nobody00");
        assert_eq!(n, 0);
        assert_eq!(q.sessions_torn_down_total(), 0);
    }

    #[test]
    fn prometheus_includes_sessions_torn_down_counter() {
        let q = UserQuarantineList::new(secs(60), 4096);
        let s = q.prometheus();
        assert!(s.contains("proteus_user_quarantine_sessions_torn_down_total 0"));
        assert!(s.contains("proteus_user_quarantine_persist_attempts_total 0"));
        assert!(s.contains("proteus_user_quarantine_persist_failed_total 0"));
        assert!(s.contains("proteus_user_quarantine_loaded_from_disk 0"));
    }

    fn tmpfile(suffix: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "proteus_quarantine_test_{}_{}.jsonl",
            std::process::id(),
            suffix
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn persist_writes_jsonl_file_with_header_and_entries() {
        let path = tmpfile("write");
        let q = UserQuarantineList::new(secs(600), 4096).with_persistence(path.clone());
        q.insert(*b"alice001", "per_user_bandwidth_rate");
        q.insert(*b"bob00002", "rate_limit");
        // insert auto-persists; check counter.
        assert!(q.persist_attempts_total() >= 2);
        assert_eq!(q.persist_failed_total(), 0);
        let body = std::fs::read_to_string(&path).expect("file written");
        assert!(
            body.contains(r#""kind":"header""#),
            "header missing: {body}"
        );
        assert!(
            body.contains(r#""user_id":"alice001""#),
            "alice missing: {body}"
        );
        assert!(
            body.contains(r#""user_id":"bob00002""#),
            "bob missing: {body}"
        );
        assert!(
            body.contains(r#""triggered_by":"per_user_bandwidth_rate""#),
            "trigger missing: {body}"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// Iter-148: persisted user_quarantine file MUST be mode 0600
    /// on Unix. Mirror of the user_quota iter-148 gate; same
    /// rationale (operator-chosen user_id strings are PII on
    /// multi-tenant hosts).
    #[cfg(unix)]
    #[test]
    fn iter148_persist_file_is_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let path = tmpfile("iter148_mode");
        let q = UserQuarantineList::new(secs(600), 4096).with_persistence(path.clone());
        q.insert(*b"alice001", "per_user_bandwidth_rate");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "iter-148: persisted file must be mode 0600 (operator-only); got 0o{mode:o}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_from_disk_restores_unexpired_entries() {
        let path = tmpfile("load_round");
        // First instance: insert two users, persist.
        {
            let q1 = UserQuarantineList::new(secs(600), 4096).with_persistence(path.clone());
            q1.insert(*b"alice001", "per_user_bandwidth_rate");
            q1.insert(*b"bob00002", "rate_limit");
        }
        // Second instance: load from disk.
        let q2 = UserQuarantineList::load_from_disk(path.clone(), secs(600), 4096);
        assert_eq!(q2.loaded_from_disk(), 2, "expected 2 entries restored");
        assert!(q2.check(b"alice001").is_some(), "alice must be quarantined");
        assert!(q2.check(b"bob00002").is_some(), "bob must be quarantined");
        // Triggered_by survives the roundtrip.
        let snap = q2.active_snapshot(64);
        let alice = snap.iter().find(|e| e.user_id == "alice001").unwrap();
        assert_eq!(alice.triggered_by, "per_user_bandwidth_rate");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_from_disk_skips_expired_entries() {
        // Hand-write a JSONL file with two entries: one expired
        // (expires_unix_seconds in the past), one valid.
        let path = tmpfile("expired");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let body = format!(
            "{}\n{}\n{}\n",
            r#"{"kind":"header","schema_version":1}"#,
            format_args!(
                r#"{{"user_id":"expired0","expires_unix_seconds":{},"triggered_by":"byte_budget"}}"#,
                now - 100
            ),
            format_args!(
                r#"{{"user_id":"valid001","expires_unix_seconds":{},"triggered_by":"rate_limit"}}"#,
                now + 300
            )
        );
        std::fs::write(&path, body).unwrap();
        let q = UserQuarantineList::load_from_disk(path.clone(), secs(600), 4096);
        assert_eq!(q.loaded_from_disk(), 1, "only the valid entry restored");
        assert!(q.check(b"expired0").is_none());
        assert!(q.check(b"valid001").is_some());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_from_disk_handles_missing_file_as_empty_fresh_start() {
        let path = tmpfile("missing");
        // file does not exist
        let q = UserQuarantineList::load_from_disk(path.clone(), secs(600), 4096);
        assert_eq!(q.loaded_from_disk(), 0);
        // Persist failure counter MUST stay 0 for "file not found"
        // (that's a fresh start, not an error).
        assert_eq!(q.persist_failed_total(), 0);
    }

    #[test]
    fn load_from_disk_handles_malformed_lines_gracefully() {
        let path = tmpfile("malformed");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let body = format!(
            "{}\n{}\n{}\n",
            r#"this is not json"#,
            r#"{"user_id":"missing fields"}"#,
            format_args!(
                r#"{{"user_id":"valid001","expires_unix_seconds":{},"triggered_by":"rate_limit"}}"#,
                now + 300
            )
        );
        std::fs::write(&path, body).unwrap();
        let q = UserQuarantineList::load_from_disk(path.clone(), secs(600), 4096);
        assert_eq!(
            q.loaded_from_disk(),
            1,
            "valid line restored, others skipped"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn persist_failure_bumps_counter_without_crashing() {
        // Point at a path inside a NONEXISTENT directory — the
        // rename will fail. The in-memory map must stay
        // authoritative; only the counter should reflect the
        // failure.
        let path = std::path::PathBuf::from("/proc/nonexistent_dir/proteus_q.jsonl");
        let q = UserQuarantineList::new(secs(60), 4096).with_persistence(path);
        let inserted = q.insert(*b"alice001", "byte_budget");
        assert!(
            inserted,
            "in-memory insert must succeed even when disk fails"
        );
        assert!(
            q.check(b"alice001").is_some(),
            "alice must still be quarantined"
        );
        assert!(
            q.persist_failed_total() >= 1,
            "persist failure must bump counter"
        );
    }

    #[test]
    fn user_id_roundtrip_through_persistence_handles_hex_form() {
        let path = tmpfile("hexform");
        let weird = [0xff_u8, 0x00, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56];
        {
            let q = UserQuarantineList::new(secs(600), 4096).with_persistence(path.clone());
            q.insert(weird, "byte_budget");
        }
        let q2 = UserQuarantineList::load_from_disk(path.clone(), secs(600), 4096);
        assert_eq!(q2.loaded_from_disk(), 1);
        assert!(q2.check(&weird).is_some(), "weird user_id must roundtrip");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn decode_user_id_rejects_malformed_hex() {
        // wrong length
        assert!(decode_user_id("hex:abc").is_err());
        // too long printable
        assert!(decode_user_id("toolongtoolong").is_err());
    }

    #[test]
    fn parse_entry_line_rejects_missing_fields() {
        assert!(parse_entry_line(r#"{"user_id":"alice001"}"#).is_err());
        assert!(parse_entry_line(r#"{"expires_unix_seconds":123}"#).is_err());
    }

    #[test]
    fn unquarantine_removes_entry_and_bumps_counter() {
        let q = UserQuarantineList::new(secs(600), 4096);
        q.insert(*b"alice001", "byte_budget");
        assert!(q.check(b"alice001").is_some());
        assert_eq!(q.manual_unquarantines_total(), 0);
        // Removed = true on first call, false on no-op repeat.
        assert!(q.unquarantine(b"alice001"));
        assert!(q.check(b"alice001").is_none());
        assert_eq!(q.manual_unquarantines_total(), 1);
        // Repeat is a no-op — no counter bump.
        assert!(!q.unquarantine(b"alice001"));
        assert_eq!(q.manual_unquarantines_total(), 1);
    }

    #[test]
    fn unquarantine_persists_to_disk() {
        let path = tmpfile("unquarantine");
        let q = UserQuarantineList::new(secs(600), 4096).with_persistence(path.clone());
        q.insert(*b"alice001", "byte_budget");
        q.insert(*b"bob00002", "rate_limit");
        // Both present on disk after inserts.
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("alice001"));
        assert!(body.contains("bob00002"));
        // Unquarantine alice — the file must no longer contain alice.
        q.unquarantine(b"alice001");
        let body2 = std::fs::read_to_string(&path).unwrap();
        assert!(
            !body2.contains("alice001"),
            "alice must be gone from disk after unquarantine: {body2}"
        );
        assert!(body2.contains("bob00002"), "bob must remain: {body2}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn reload_from_disk_inserts_new_entries_from_file() {
        // Two-instance scenario: process 1 inserts alice; process 2
        // (same list instance for this test) doesn't know yet but
        // operator edits the file to add bob. Reload picks up bob.
        let path = tmpfile("reload_add");
        let q = UserQuarantineList::new(secs(600), 4096).with_persistence(path.clone());
        q.insert(*b"alice001", "byte_budget");
        // Operator hand-edits the file to add bob and carol.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let body = std::fs::read_to_string(&path).unwrap();
        let extra = format!(
            "{}\n{}\n",
            format_args!(
                r#"{{"user_id":"bob00002","expires_unix_seconds":{},"triggered_by":"rate_limit"}}"#,
                now + 500
            ),
            format_args!(
                r#"{{"user_id":"carol003","expires_unix_seconds":{},"triggered_by":"byte_budget"}}"#,
                now + 400
            ),
        );
        std::fs::write(&path, format!("{body}{extra}")).unwrap();

        let outcome = q.reload_from_disk().expect("reload");
        assert_eq!(
            outcome.added, 2,
            "bob + carol must be inserted: {outcome:?}"
        );
        assert_eq!(outcome.removed, 0);
        assert!(q.check(b"alice001").is_some());
        assert!(q.check(b"bob00002").is_some());
        assert!(q.check(b"carol003").is_some());
        assert_eq!(q.reload_attempts_total(), 1);
        assert_eq!(q.reload_failed_total(), 0);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn reload_from_disk_removes_entries_missing_from_file() {
        let path = tmpfile("reload_remove");
        let q = UserQuarantineList::new(secs(600), 4096).with_persistence(path.clone());
        q.insert(*b"alice001", "byte_budget");
        q.insert(*b"bob00002", "rate_limit");
        // Operator hand-edits to drop alice (manually unbans).
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let body = format!(
            "{}\n{}\n",
            r#"{"kind":"header","schema_version":1}"#,
            format_args!(
                r#"{{"user_id":"bob00002","expires_unix_seconds":{},"triggered_by":"rate_limit"}}"#,
                now + 500
            ),
        );
        std::fs::write(&path, body).unwrap();

        let outcome = q.reload_from_disk().expect("reload");
        assert_eq!(outcome.removed, 1, "alice must be removed: {outcome:?}");
        assert_eq!(outcome.added, 0);
        assert!(q.check(b"alice001").is_none(), "alice unbanned by reload");
        assert!(q.check(b"bob00002").is_some(), "bob still banned");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn reload_from_disk_refreshes_changed_entries() {
        // Operator extends alice's ban by editing the expires_unix
        // forward — reload should update in place + tear down
        // sessions (the extend should re-arm enforcement).
        let path = tmpfile("reload_refresh");
        let q = UserQuarantineList::new(secs(60), 4096).with_persistence(path.clone());
        q.insert(*b"alice001", "byte_budget");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Edit the file: bump alice's expiry to 3600s ahead +
        // change the trigger.
        let body = format!(
            "{}\n{}\n",
            r#"{"kind":"header","schema_version":1}"#,
            format_args!(
                r#"{{"user_id":"alice001","expires_unix_seconds":{},"triggered_by":"per_user_bandwidth_rate"}}"#,
                now + 3600
            ),
        );
        std::fs::write(&path, body).unwrap();

        let outcome = q.reload_from_disk().expect("reload");
        assert_eq!(
            outcome.refreshed, 1,
            "alice's entry must be refreshed: {outcome:?}"
        );
        assert_eq!(outcome.added, 0);
        assert_eq!(outcome.removed, 0);
        let remaining = q.check(b"alice001").unwrap();
        assert!(
            remaining > 3500 && remaining <= 3600,
            "alice's TTL must reflect the extended expiry: {remaining}"
        );
        let snap = q.active_snapshot(64);
        assert_eq!(snap[0].triggered_by, "per_user_bandwidth_rate");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn reload_from_disk_missing_file_clears_all_entries() {
        // Operator deletes the persistence file to lift every ban.
        let path = tmpfile("reload_missing");
        let q = UserQuarantineList::new(secs(600), 4096).with_persistence(path.clone());
        q.insert(*b"alice001", "byte_budget");
        q.insert(*b"bob00002", "rate_limit");
        assert!(path.exists());
        std::fs::remove_file(&path).unwrap();
        let outcome = q.reload_from_disk().expect("reload");
        assert_eq!(outcome.removed, 2);
        assert!(q.check(b"alice001").is_none());
        assert!(q.check(b"bob00002").is_none());
    }

    #[test]
    fn reload_from_disk_counts_malformed_lines() {
        let path = tmpfile("reload_malformed");
        let q = UserQuarantineList::new(secs(600), 4096).with_persistence(path.clone());
        let body = format!(
            "{}\n{}\n{}\n",
            r#"{"kind":"header","schema_version":1}"#,
            r#"not json at all"#,
            r#"{"user_id":"missing_other_fields"}"#,
        );
        std::fs::write(&path, body).unwrap();
        let outcome = q.reload_from_disk().expect("reload");
        assert_eq!(
            outcome.malformed, 2,
            "both malformed lines must be counted: {outcome:?}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn reload_from_disk_with_no_persistence_path_is_a_noop() {
        // No persistence wired — reload returns default outcome
        // without error.
        let q = UserQuarantineList::new(secs(60), 4096);
        let outcome = q.reload_from_disk().expect("reload");
        assert_eq!(outcome, ReloadOutcome::default());
        // The attempt counter STILL bumps so operators see "SIGHUP
        // fired" even when persistence is unwired.
        assert_eq!(q.reload_attempts_total(), 1);
    }

    #[tokio::test]
    async fn reload_from_disk_tears_down_sessions_for_newly_added_bans() {
        // operator hand-edits the file to add a fresh ban for
        // alice WHILE she has an in-flight session → reload
        // should immediately tear it down (just like insert does).
        let path = tmpfile("reload_teardown");
        let q = UserQuarantineList::new(secs(600), 4096).with_persistence(path.clone());
        // Alice has an in-flight session (no ban yet).
        let notify = q.register_session(*b"alice001");
        let notify_clone = Arc::clone(&notify);
        let task = tokio::spawn(async move {
            notify_clone.notified().await;
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        // Operator adds the ban to the file.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let body = format!(
            "{}\n{}\n",
            r#"{"kind":"header","schema_version":1}"#,
            format_args!(
                r#"{{"user_id":"alice001","expires_unix_seconds":{},"triggered_by":"per_user_bandwidth_rate"}}"#,
                now + 600
            ),
        );
        std::fs::write(&path, body).unwrap();
        // SIGHUP-equivalent.
        let outcome = q.reload_from_disk().expect("reload");
        assert_eq!(outcome.added, 1);
        // Alice's session is torn down.
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("alice's in-flight session must be torn down by reload")
            .unwrap();
        assert!(q.sessions_torn_down_total() >= 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn reload_from_disk_does_not_tear_down_for_removes() {
        // The "memory but not file" case is operator unbanning —
        // do NOT call tear_down_user.
        let q = UserQuarantineList::new(secs(60), 4096);
        let path = tmpfile("reload_no_teardown");
        let q = q.with_persistence(path.clone());
        q.insert(*b"alice001", "byte_budget");
        let before = q.sessions_torn_down_total();
        // Drop alice from the file.
        let body = format!("{}\n", r#"{"kind":"header","schema_version":1}"#);
        std::fs::write(&path, body).unwrap();
        let outcome = q.reload_from_disk().expect("reload");
        assert_eq!(outcome.removed, 1);
        assert_eq!(
            q.sessions_torn_down_total(),
            before,
            "removes must NOT bump tear-down counter"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn prometheus_emits_operator_override_counters() {
        let q = UserQuarantineList::new(secs(600), 4096);
        let s = q.prometheus();
        assert!(s.contains("proteus_user_quarantine_manual_unquarantines_total 0"));
        assert!(s.contains("proteus_user_quarantine_reload_attempts_total 0"));
        assert!(s.contains("proteus_user_quarantine_reload_failed_total 0"));
    }

    #[test]
    fn concurrent_insert_check_keeps_invariants() {
        use std::sync::Arc;
        let q = Arc::new(UserQuarantineList::new(secs(60), 4096));
        let mut handles = Vec::new();
        for tid in 0..8u8 {
            let q = Arc::clone(&q);
            handles.push(std::thread::spawn(move || {
                for i in 0..200u64 {
                    let mut uid = [0u8; 8];
                    uid[0] = tid;
                    uid[1..].copy_from_slice(&i.to_be_bytes()[1..]);
                    let _ = q.insert(uid, "byte_budget");
                    let _ = q.check(&uid);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        // Inserts = 8 × 200 = 1600 (no refused at this scale —
        // 1600 distinct ≤ cap 4096).
        assert_eq!(q.inserted_total(), 1600);
        assert_eq!(q.refused_inserts_total(), 0);
        // Active count: each thread's first insert created the
        // entry; each thread's `check` immediately after found it.
        // Both numbers should be exactly 1600 (no collisions
        // across distinct user_ids).
        assert_eq!(q.active_count(), 1600);
    }
}
