//! Recent abuse-alert fires — bounded ring buffer with timestamp,
//! user_id, kind, and contextual scalar (rate in bytes/sec for the
//! bandwidth detector, count for the event-based detectors).
//!
//! ## Why this exists
//!
//! Existing operator-visible signals when an abuse alert fires:
//!
//! 1. **WARN log line** to stderr → `journalctl -u proteus-server
//!    | grep abuse`. Slow, requires journald access, hard to script.
//! 2. **Aggregate counter** on `/metrics` (e.g.
//!    `proteus_abuse_alerts_per_user_bandwidth_total`). Tells the
//!    operator THAT abuse happened, NOT WHO.
//!
//! Neither is actionable for the canonical Proteus operator running
//! a personal VPN for friends on one VPS. When `rate(...) > 0` fires
//! on Alertmanager (or the operator notices the counter ticked up),
//! the question is "WHICH user_id should I rotate the credential
//! for?". The aggregate counter doesn't say.
//!
//! This module collects the last N fires across all three detectors
//! and surfaces them via:
//!
//! - `/metrics` — `proteus_abuse_recent_fires_total` counter +
//!   `proteus_abuse_recent_fire{user_id,kind,seconds_ago}` info-
//!   style gauge for each ring slot.
//! - `/diagnose` — human-readable table of the last N fires.
//! - `admin abuse-fires` CLI — text or JSON output for scripting
//!   (Telegram bot, oncall pager).
//!
//! ## Design
//!
//! Lock-free ring buffer (`parking_lot::Mutex<VecDeque<Fire>>`) with
//! a fixed capacity (default 64 — plenty for "last hour's worth" on
//! any reasonable deployment, doesn't blow memory if the abuse goes
//! sustained). Adds are O(1); snapshot for rendering is O(N).
//!
//! Memory-bounded by design — the buffer never grows past `capacity`,
//! and on cap, the oldest fire is evicted. Operators who want every
//! fire historically should run `journalctl` against the WARN log;
//! this is the *recent* surface.
//!
//! ## Concurrency
//!
//! `std::sync::Mutex<VecDeque<...>>` — fires arrive on the session-
//! close hot path, but that path is already locked by the metrics
//! merge + per-user accumulator; one more brief lock acquisition
//! is in the noise. The snapshot path runs once per scrape.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Operator-visible kinds of abuse fire. Each variant maps 1:1 to
/// an existing detector + Prometheus counter so the rendered ring
/// entries are explainable from `/metrics` alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbuseFireKind {
    /// `abuse_detector.byte_budget` — user repeatedly hit the
    /// per-session byte cap inside the sliding window.
    ByteBudget,
    /// `abuse_detector.rate_limit` — user repeatedly tripped the
    /// per-user rate limiter inside the sliding window.
    RateLimit,
    /// `per_user_bandwidth_rate_detector` — user's sustained
    /// `(tx+rx)` rate crossed the operator-configured MB/s threshold.
    /// The contextual scalar carries the computed bytes/sec at fire
    /// time so operators see the magnitude.
    PerUserBandwidthRate,
}

impl AbuseFireKind {
    /// Short, stable label suitable for a Prometheus label value
    /// or a CLI column. Lowercase + snake_case, never changes
    /// (operators script against these strings).
    #[must_use]
    pub const fn as_label(&self) -> &'static str {
        match self {
            Self::ByteBudget => "byte_budget",
            Self::RateLimit => "rate_limit",
            Self::PerUserBandwidthRate => "per_user_bandwidth_rate",
        }
    }
}

/// One recorded abuse fire. Cheap to clone — all fields are POD.
#[derive(Debug, Clone, Copy)]
pub struct AbuseFire {
    /// Wall-clock instant the fire happened (epoch seconds, fits a
    /// `u64` until year 2286). Recorded at insert time so the
    /// `seconds_ago` displayed on `/metrics` is computed by the
    /// scrape, not frozen at fire time.
    pub at_unix_seconds: u64,
    /// Kind discriminator — see [`AbuseFireKind`].
    pub kind: AbuseFireKind,
    /// 8-byte user_id, rendered by the consumer using the same
    /// printable-ASCII-or-hex strategy as `per_user_bandwidth`.
    pub user_id: [u8; 8],
    /// Contextual scalar:
    ///   - `ByteBudget` / `RateLimit`: typically left at 0 (the
    ///     event itself carries no magnitude; the detector's
    ///     threshold-vs-count check encodes the only number).
    ///   - `PerUserBandwidthRate`: the computed sustained rate
    ///     (bytes/sec) that crossed the threshold.
    ///
    /// Operators see this in the `/diagnose` table + `admin
    /// abuse-fires` CLI to gauge the severity of the burst.
    pub context_value: u64,
}

/// Bounded ring buffer of recent abuse fires. Cheap to share across
/// detector call sites via `Arc`. Construct with
/// [`AbuseFireBuffer::new`].
pub struct AbuseFireBuffer {
    inner: Mutex<VecDeque<AbuseFire>>,
    capacity: usize,
}

impl AbuseFireBuffer {
    /// Build a buffer with the given capacity. `capacity = 0` is
    /// treated as "buffer wired but disabled" — every `push` is a
    /// no-op; the snapshot is always empty. Pattern matches the
    /// other "wired but silent" knobs (rate detector
    /// `threshold_mb_per_sec=0`, conn limiter `max_per_user=0`).
    ///
    /// Recommended production capacity: 64 (covers "last hour" on
    /// any sane deployment). Operators who want every fire
    /// historically should run `journalctl -u proteus-server | grep
    /// abuse` — this surface is the recent-N actionable view.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(VecDeque::with_capacity(capacity.min(64))),
            capacity,
        }
    }

    /// Configured capacity. Surfaced in the Prometheus exposition so
    /// operators see the slot is wired even when no fires have
    /// occurred yet.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Record one fire. When the buffer is at capacity, the oldest
    /// fire is evicted to make room. When `capacity == 0`, this is
    /// a no-op (buffer wired but disabled).
    pub fn push(&self, kind: AbuseFireKind, user_id: [u8; 8], context_value: u64) {
        if self.capacity == 0 {
            return;
        }
        let at_unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        self.push_at(kind, user_id, context_value, at_unix_seconds);
    }

    /// Test-friendly: same as [`Self::push`] but with explicit
    /// timestamp instead of `SystemTime::now()`. Allows unit tests
    /// to assert specific `seconds_ago` values without sleeping.
    pub fn push_at(
        &self,
        kind: AbuseFireKind,
        user_id: [u8; 8],
        context_value: u64,
        at_unix_seconds: u64,
    ) {
        if self.capacity == 0 {
            return;
        }
        let mut g = self.inner.lock().expect("AbuseFireBuffer mutex poisoned");
        if g.len() >= self.capacity {
            g.pop_front();
        }
        g.push_back(AbuseFire {
            at_unix_seconds,
            kind,
            user_id,
            context_value,
        });
    }

    /// Snapshot all currently-buffered fires, oldest first. Cheap —
    /// each fire is a POD copy.
    #[must_use]
    pub fn snapshot(&self) -> Vec<AbuseFire> {
        let g = self.inner.lock().expect("AbuseFireBuffer mutex poisoned");
        g.iter().copied().collect()
    }

    /// Count of fires currently in the buffer (≤ capacity).
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .expect("AbuseFireBuffer mutex poisoned")
            .len()
    }

    /// True when the buffer holds zero fires.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Emit the Prometheus exposition block. Two series:
    ///
    /// - `proteus_abuse_recent_fires_capacity` (gauge) — operator-set
    ///   capacity; lets operators verify the slot is wired and at
    ///   the configured size.
    /// - `proteus_abuse_recent_fires_count` (gauge) — current number
    ///   of fires in the buffer; `count == capacity` is a strong
    ///   signal that abuse is so frequent the buffer is rotating
    ///   (operators should investigate).
    ///
    /// The buffer's CONTENTS are NOT exposed via Prometheus —
    /// renderering each fire as a labelled series would explode
    /// the metric cardinality (one series per user_id per kind per
    /// scrape, growing unboundedly across the operator's lifetime).
    /// Operators consume the contents via `/diagnose` (human-
    /// readable) or `admin abuse-fires` (text / JSON), which are
    /// scrape-shaped, not series-shaped.
    #[must_use]
    pub fn prometheus(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(256);
        let _ = writeln!(
            s,
            "# HELP proteus_abuse_recent_fires_capacity \
             Operator-set capacity of the recent-abuse-fires ring buffer. \
             0 = buffer wired but disabled."
        );
        let _ = writeln!(s, "# TYPE proteus_abuse_recent_fires_capacity gauge");
        let _ = writeln!(s, "proteus_abuse_recent_fires_capacity {}", self.capacity);
        let _ = writeln!(
            s,
            "# HELP proteus_abuse_recent_fires_count \
             Current number of fires in the recent-abuse-fires ring \
             buffer (≤ capacity). count == capacity = abuse is so \
             frequent the buffer is rotating; investigate."
        );
        let _ = writeln!(s, "# TYPE proteus_abuse_recent_fires_count gauge");
        let _ = writeln!(s, "proteus_abuse_recent_fires_count {}", self.len());
        s
    }

    /// Render a human-readable table for `/diagnose`. Columns:
    /// `seconds_ago`, `kind`, `user_id`, `context_value` (when
    /// non-zero). Sorted oldest-first to match the WARN log
    /// chronology, so operators reading both side-by-side don't
    /// need to mentally invert one.
    ///
    /// `now_unix_seconds` is passed in (not read from `SystemTime`)
    /// so the renderer is deterministic for tests + matches the
    /// scrape's own timestamp if the caller is composing a multi-
    /// section diagnose body.
    #[must_use]
    pub fn diagnose_table(&self, now_unix_seconds: u64) -> String {
        use std::fmt::Write as _;
        let entries = self.snapshot();
        if entries.is_empty() {
            return String::from("RECENT ABUSE FIRES: (none)\n");
        }
        let mut s = String::with_capacity(384);
        let _ = writeln!(
            s,
            "RECENT ABUSE FIRES ({} of {} capacity, oldest first):",
            entries.len(),
            self.capacity
        );
        // Header.
        let _ = writeln!(
            s,
            "  {:>10}  {:<24}  {:<16}  context",
            "secs_ago", "kind", "user_id"
        );
        for fire in &entries {
            let secs_ago = now_unix_seconds.saturating_sub(fire.at_unix_seconds);
            let uid = crate::per_user_bandwidth::render_user_id_pub(&fire.user_id);
            let ctx = if fire.context_value > 0 {
                format!("{}", fire.context_value)
            } else {
                String::from("-")
            };
            let _ = writeln!(
                s,
                "  {:>10}  {:<24}  {:<16}  {}",
                secs_ago,
                fire.kind.as_label(),
                uid,
                ctx
            );
        }
        s
    }

    /// Render a JSON Lines body for scripting consumers (Telegram
    /// bots, oncall pagers, etc.). One line per fire, ordered
    /// oldest first. Schema is append-only (same stability
    /// guarantee as the soak report JSON).
    ///
    /// `now_unix_seconds` matches the docstring on
    /// [`Self::diagnose_table`].
    #[must_use]
    pub fn json_lines(&self, now_unix_seconds: u64) -> String {
        use std::fmt::Write as _;
        let entries = self.snapshot();
        let mut s = String::with_capacity(entries.len() * 96);
        for fire in &entries {
            let secs_ago = now_unix_seconds.saturating_sub(fire.at_unix_seconds);
            let uid = crate::per_user_bandwidth::render_user_id_pub(&fire.user_id);
            // No external JSON dep — operators of the canonical
            // single-VPS deployment shouldn't pay a serde_json
            // compile cost for a 6-field line. Inline escape: the
            // user_id rendering already strips `\` and `"` (the
            // `hex:` fallback handles non-printable bytes), so the
            // only character we need to escape here is the kind
            // label, which is a const enum string and never
            // contains anything weird.
            let _ = writeln!(
                s,
                r#"{{"kind":"abuse_fire","at_unix_seconds":{},"seconds_ago":{},"abuse_kind":"{}","user_id":"{}","context_value":{}}}"#,
                fire.at_unix_seconds,
                secs_ago,
                fire.kind.as_label(),
                uid,
                fire.context_value
            );
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_buffer_snapshot_is_empty() {
        let b = AbuseFireBuffer::new(8);
        assert!(b.is_empty());
        assert_eq!(b.snapshot().len(), 0);
        assert_eq!(b.len(), 0);
    }

    #[test]
    fn push_records_kind_user_and_context() {
        let b = AbuseFireBuffer::new(8);
        b.push_at(
            AbuseFireKind::PerUserBandwidthRate,
            *b"alice001",
            123_456_789,
            1_700_000_000,
        );
        let snap = b.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].kind, AbuseFireKind::PerUserBandwidthRate);
        assert_eq!(snap[0].user_id, *b"alice001");
        assert_eq!(snap[0].context_value, 123_456_789);
        assert_eq!(snap[0].at_unix_seconds, 1_700_000_000);
    }

    #[test]
    fn push_evicts_oldest_at_capacity() {
        let b = AbuseFireBuffer::new(3);
        for i in 0..5u64 {
            let mut uid = *b"user000\0";
            uid[7] = b'0' + (i as u8);
            b.push_at(AbuseFireKind::ByteBudget, uid, 0, 1_700_000_000 + i);
        }
        let snap = b.snapshot();
        assert_eq!(snap.len(), 3, "buffer should be capped at 3");
        // Oldest two (indices 0, 1) evicted; 2, 3, 4 remain.
        assert_eq!(snap[0].at_unix_seconds, 1_700_000_002);
        assert_eq!(snap[1].at_unix_seconds, 1_700_000_003);
        assert_eq!(snap[2].at_unix_seconds, 1_700_000_004);
    }

    #[test]
    fn capacity_zero_disables_push() {
        let b = AbuseFireBuffer::new(0);
        b.push(AbuseFireKind::ByteBudget, *b"alice001", 0);
        b.push_at(
            AbuseFireKind::PerUserBandwidthRate,
            *b"bob00002",
            999,
            1_700_000_000,
        );
        assert!(b.is_empty());
    }

    #[test]
    fn snapshot_ordering_oldest_first() {
        let b = AbuseFireBuffer::new(8);
        b.push_at(AbuseFireKind::ByteBudget, *b"alice001", 0, 100);
        b.push_at(AbuseFireKind::RateLimit, *b"bob00002", 0, 200);
        b.push_at(AbuseFireKind::PerUserBandwidthRate, *b"carol003", 999, 300);
        let snap = b.snapshot();
        assert_eq!(snap[0].at_unix_seconds, 100);
        assert_eq!(snap[1].at_unix_seconds, 200);
        assert_eq!(snap[2].at_unix_seconds, 300);
    }

    #[test]
    fn prometheus_emits_capacity_and_count_always() {
        let b = AbuseFireBuffer::new(64);
        let s_empty = b.prometheus();
        assert!(s_empty.contains("proteus_abuse_recent_fires_capacity 64"));
        assert!(s_empty.contains("proteus_abuse_recent_fires_count 0"));
        b.push(AbuseFireKind::ByteBudget, *b"alice001", 0);
        b.push(AbuseFireKind::RateLimit, *b"bob00002", 0);
        let s_two = b.prometheus();
        assert!(s_two.contains("proteus_abuse_recent_fires_capacity 64"));
        assert!(s_two.contains("proteus_abuse_recent_fires_count 2"));
    }

    #[test]
    fn prometheus_for_disabled_buffer_shows_capacity_zero() {
        let b = AbuseFireBuffer::new(0);
        let s = b.prometheus();
        assert!(s.contains("proteus_abuse_recent_fires_capacity 0"));
        assert!(s.contains("proteus_abuse_recent_fires_count 0"));
    }

    #[test]
    fn diagnose_table_renders_empty_marker_when_no_fires() {
        let b = AbuseFireBuffer::new(8);
        let s = b.diagnose_table(1_700_000_000);
        assert!(s.contains("(none)"), "{s}");
    }

    #[test]
    fn diagnose_table_renders_seconds_ago_and_kind_and_user() {
        let b = AbuseFireBuffer::new(8);
        b.push_at(
            AbuseFireKind::PerUserBandwidthRate,
            *b"alice001",
            104_857_600, // 100 MB/s
            1_700_000_000,
        );
        let s = b.diagnose_table(1_700_000_005); // 5 secs later
        assert!(s.contains("alice001"), "{s}");
        assert!(s.contains("per_user_bandwidth_rate"), "{s}");
        assert!(s.contains("104857600"), "{s}");
        assert!(s.contains("5"), "secs_ago not rendered: {s}");
    }

    #[test]
    fn json_lines_one_record_per_fire_with_stable_schema() {
        let b = AbuseFireBuffer::new(8);
        b.push_at(AbuseFireKind::ByteBudget, *b"alice001", 0, 1_700_000_000);
        b.push_at(
            AbuseFireKind::PerUserBandwidthRate,
            *b"bob00002",
            12_345,
            1_700_000_010,
        );
        let s = b.json_lines(1_700_000_100);
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(lines.len(), 2);
        // First line: alice byte_budget, 100s ago.
        assert!(lines[0].contains(r#""abuse_kind":"byte_budget""#));
        assert!(lines[0].contains(r#""user_id":"alice001""#));
        assert!(lines[0].contains(r#""seconds_ago":100"#));
        assert!(lines[0].contains(r#""context_value":0"#));
        // Second line: bob bandwidth, 90s ago, context=12345.
        assert!(lines[1].contains(r#""abuse_kind":"per_user_bandwidth_rate""#));
        assert!(lines[1].contains(r#""user_id":"bob00002""#));
        assert!(lines[1].contains(r#""seconds_ago":90"#));
        assert!(lines[1].contains(r#""context_value":12345"#));
    }

    #[test]
    fn json_lines_empty_for_empty_buffer() {
        let b = AbuseFireBuffer::new(8);
        assert!(b.json_lines(1_700_000_000).is_empty());
    }

    #[test]
    fn kind_label_is_stable_and_snake_case() {
        // Operators script against these strings — any change is a
        // breaking API. This test pins them.
        assert_eq!(AbuseFireKind::ByteBudget.as_label(), "byte_budget");
        assert_eq!(AbuseFireKind::RateLimit.as_label(), "rate_limit");
        assert_eq!(
            AbuseFireKind::PerUserBandwidthRate.as_label(),
            "per_user_bandwidth_rate"
        );
    }

    #[test]
    fn concurrent_push_keeps_ring_invariants() {
        // 16 threads × 1000 pushes each; capacity = 64. Final len
        // must equal capacity; no panic; no data corruption.
        use std::sync::Arc;
        let b = Arc::new(AbuseFireBuffer::new(64));
        let mut handles = Vec::new();
        for tid in 0..16u8 {
            let b = Arc::clone(&b);
            handles.push(std::thread::spawn(move || {
                for i in 0..1000u64 {
                    let mut uid = [0u8; 8];
                    uid[0] = tid;
                    uid[1..].copy_from_slice(&i.to_be_bytes()[1..]);
                    b.push(AbuseFireKind::ByteBudget, uid, i);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(b.len(), 64, "ring must converge to capacity");
        // Snapshot iteration must succeed (no poisoning, no panic).
        let snap = b.snapshot();
        assert_eq!(snap.len(), 64);
    }
}
