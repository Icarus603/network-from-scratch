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
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How often the in-memory map gets vacuumed of expired entries.
/// Mirrors `auto_deny.rs::VACUUM_INTERVAL` — keeps the cost
/// amortized regardless of lookup rate.
const VACUUM_INTERVAL: Duration = Duration::from_secs(30);

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
            last_vacuum: Mutex::new(Instant::now()),
            inserted_total: std::sync::atomic::AtomicU64::new(0),
            refused_inserts_total: std::sync::atomic::AtomicU64::new(0),
            quarantine_hits_total: std::sync::atomic::AtomicU64::new(0),
        }
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
        let mut g = self.inner.lock().expect("UserQuarantineList poisoned");
        if g.contains_key(&user_id) {
            // Refresh: bump the deadline and update the trigger so
            // the most recent detector kind is what's surfaced.
            let entry = g.get_mut(&user_id).unwrap();
            entry.expires_at = expires_at;
            entry.triggered_by_kind = triggered_by;
            self.inserted_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
        let g = self.inner.lock().expect("UserQuarantineList poisoned");
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
        let mut last = self
            .last_vacuum
            .lock()
            .expect("UserQuarantineList last_vacuum poisoned");
        if now.duration_since(*last) < VACUUM_INTERVAL {
            return;
        }
        *last = now;
        drop(last); // release before taking inner lock
        let mut g = self.inner.lock().expect("UserQuarantineList poisoned");
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
        let g = self.inner.lock().expect("UserQuarantineList poisoned");
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
        let g = self.inner.lock().expect("UserQuarantineList poisoned");
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
