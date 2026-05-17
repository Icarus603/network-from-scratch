//! Per-user bandwidth accounting on the server.
//!
//! ## Why this exists
//!
//! Aggregate `proteus_tx_bytes_total` + `proteus_rx_bytes_total`
//! answer "how much bandwidth is the server pushing" but not
//! "which user is responsible for which fraction". Two production
//! scenarios that current metrics can't answer:
//!
//! 1. **Tenant fairness** — "Which of my 10 users is monopolizing
//!    the VPS uplink?" Operator running a personal-VPN-for-friends
//!    setup needs per-user accounting to demote / rate-limit the
//!    one user pushing 800 MB/s while others starve.
//! 2. **Abuse detection** — "Has a credential been stolen and is
//!    being used for exfil?" Existing `abuse_alerts_byte_budget`
//!    fires AFTER a user hits the per-session byte budget; this
//!    module exposes the live `bytes_sent_total{user_id="…"}`
//!    rate so operators alert on `rate(...) > 100MB/s` BEFORE
//!    the budget cap fires.
//!
//! ## Why per-user (not per-session, not per-IP)
//!
//! - Per-session is too granular: a single user opens hundreds of
//!   sessions in normal browsing. Operators want one row per user,
//!   not per session.
//! - Per-IP would conflate users behind a single NAT (multiple
//!   VPN-clients on one home router). The Proteus handshake binds
//!   each session to a `user_id` from `ClientConfig::user_id`
//!   which is the operator's natural unit.
//!
//! ## Memory bound
//!
//! Bounded by the operator's `client_allowlist` size + a small
//! cap on unknown user_ids that haven't yet completed handshake
//! (we still record them so attack-tracing isn't blind to
//! pre-allowlist activity). Default cap: 4096 distinct user_ids.
//! Beyond the cap, additional user_ids share a single
//! `__overflow__` bucket — bandwidth still accounted for, just
//! not attributed by individual user.
//!
//! ## Concurrency
//!
//! `Mutex<HashMap<user_id, AtomicU64>>` for the map; once an entry
//! exists, hot-path bumps are lock-free atomic adds. The mutex is
//! taken only when (a) a new user_id is observed, (b) the
//! Prometheus emitter snapshots the map. (a) is rare past process
//! warmup; (b) is once per scrape.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::per_user_bandwidth_rate_detector::{PerUserBandwidthRateDetector, RateAlertOutcome};

/// Per-user cumulative byte counters. `tx` = bytes the server
/// sent to the user; `rx` = bytes received from the user. The
/// asymmetry is operator-visible — a stolen credential exfiltrating
/// data shows up as `rx_bytes` climbing while `tx_bytes` stays low.
#[derive(Debug, Default)]
struct UserBytes {
    tx: AtomicU64,
    rx: AtomicU64,
}

/// Operator-visible snapshot of one user's bandwidth totals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserBytesSnapshot {
    pub tx: u64,
    pub rx: u64,
}

/// Server-side per-user bandwidth accumulator. Cheap to share
/// across spawned session handlers via `Arc`.
///
/// Construct with `new(max_users)`. Each call to `record(user_id,
/// tx, rx)` bumps that user's running totals; once the map hits
/// `max_users` distinct entries, additional user_ids accumulate
/// into a single `__overflow__` bucket so the memory bound is
/// strict.
pub struct PerUserBandwidth {
    inner: Mutex<HashMap<[u8; 8], Arc<UserBytes>>>,
    max_users: usize,
    overflow: Arc<UserBytes>,
    /// Optional bandwidth-rate abuse detector. When wired, every
    /// `record()` call also feeds the per-user delta into the
    /// detector; if the detector fires, the caller (typically the
    /// binary's session-close hook) emits a structured WARN log
    /// and bumps `proteus_abuse_alerts_per_user_bandwidth_total`.
    rate_detector: Mutex<Option<Arc<PerUserBandwidthRateDetector>>>,
    /// Optional recent-abuse-fires ring buffer. When BOTH this AND
    /// the rate detector are wired, a `Fired` outcome from the
    /// detector ALSO pushes a record into the buffer — so operators
    /// see the user_id + computed rate in `/diagnose` and `admin
    /// abuse-fires`. Stored on the accumulator (not the detector)
    /// because the accumulator already holds the `user_id` at
    /// record time; threading it to the detector would require
    /// changing its API for one consumer.
    abuse_fires: Mutex<Option<Arc<crate::abuse_fires::AbuseFireBuffer>>>,
    /// Optional auto-quarantine list + opt-in flag. When the
    /// operator opts `per_user_bandwidth_rate` into quarantine,
    /// `Fired` from the rate detector ALSO inserts the user_id
    /// into the quarantine list. Held here (same slot pattern as
    /// `abuse_fires` above) so the binary can SIGHUP-swap without
    /// rebuilding the accumulator.
    quarantine: Mutex<Option<Arc<crate::user_quarantine::UserQuarantineList>>>,
    quarantine_on_fire: std::sync::atomic::AtomicBool,
    /// Optional per-user data quota tracker. When wired, every
    /// `record()` call ALSO charges the user's quota bucket with
    /// `(tx + rx)` bytes — so over-quota becomes a hard admission
    /// gate (handled in `user_admission_ok`) while still letting
    /// the bandwidth-rate detector + abuse-fires ring observe
    /// normal usage.
    quota: Mutex<Option<Arc<crate::user_quota::PerUserQuotaTracker>>>,
}

impl PerUserBandwidth {
    /// Construct with a cap of `max_users` distinct user_ids.
    /// Operators set this in `server.yaml` (typical: matches
    /// `client_allowlist` size + 10% headroom for unauthenticated
    /// pre-handshake activity).
    #[must_use]
    pub fn new(max_users: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::with_capacity(max_users.min(64))),
            max_users,
            overflow: Arc::new(UserBytes::default()),
            rate_detector: Mutex::new(None),
            abuse_fires: Mutex::new(None),
            quarantine: Mutex::new(None),
            quarantine_on_fire: std::sync::atomic::AtomicBool::new(false),
            quota: Mutex::new(None),
        }
    }

    /// Attach the per-user data quota tracker. When wired, every
    /// `record()` call charges `(tx + rx)` against the user's
    /// quota bucket; the actual admission-gate check lives in
    /// `user_admission_ok`.
    pub fn set_quota(&self, tracker: Option<Arc<crate::user_quota::PerUserQuotaTracker>>) {
        let mut g = self
            .quota
            .lock()
            .expect("PerUserBandwidth quota lock poisoned");
        *g = tracker;
    }

    /// Read the quota tracker handle.
    #[must_use]
    pub fn quota(&self) -> Option<Arc<crate::user_quota::PerUserQuotaTracker>> {
        self.quota
            .lock()
            .expect("PerUserBandwidth quota lock poisoned")
            .clone()
    }

    /// Attach an auto-quarantine list + opt-in flag. When `opt_in
    /// = true`, every `Fired` outcome from the rate detector
    /// inserts the user_id into the quarantine list with the
    /// list's configured TTL. When `opt_in = false`, the list is
    /// still wired (operator gets the observability surface for
    /// SIGHUP swap) but no auto-insert happens.
    pub fn set_quarantine(
        &self,
        list: Option<Arc<crate::user_quarantine::UserQuarantineList>>,
        opt_in: bool,
    ) {
        let mut g = self
            .quarantine
            .lock()
            .expect("PerUserBandwidth quarantine lock poisoned");
        *g = list;
        self.quarantine_on_fire
            .store(opt_in, std::sync::atomic::Ordering::Relaxed);
    }

    /// Read-only accessor for the current auto-quarantine list.
    #[must_use]
    pub fn quarantine(&self) -> Option<Arc<crate::user_quarantine::UserQuarantineList>> {
        self.quarantine
            .lock()
            .expect("PerUserBandwidth quarantine lock poisoned")
            .clone()
    }

    /// Attach a recent-abuse-fires ring buffer. When wired, every
    /// `Fired` outcome from the rate detector ALSO pushes a record
    /// into the buffer (kind=PerUserBandwidthRate, context=rate
    /// bytes/sec). Hot-swappable via `Mutex<Option<...>>` so the
    /// binary can swap on SIGHUP without rebuilding the accumulator.
    pub fn set_abuse_fires(&self, buf: Option<Arc<crate::abuse_fires::AbuseFireBuffer>>) {
        let mut g = self
            .abuse_fires
            .lock()
            .expect("PerUserBandwidth abuse_fires lock poisoned");
        *g = buf;
    }

    /// Read-only accessor for the current abuse-fires buffer.
    #[must_use]
    pub fn abuse_fires(&self) -> Option<Arc<crate::abuse_fires::AbuseFireBuffer>> {
        self.abuse_fires
            .lock()
            .expect("PerUserBandwidth abuse_fires lock poisoned")
            .clone()
    }

    /// Builder: attach a bandwidth-rate abuse detector. The detector
    /// is consulted on every `record()` call; on `Fired`, the caller
    /// is responsible for the WARN log + counter bump.
    ///
    /// SIGHUP hot-reload: the detector slot is itself behind a
    /// `Mutex<Option<...>>` so the binary can swap detectors on
    /// reload without rebuilding the bandwidth accumulator. The
    /// `record_with_rate_check` path takes the lock once per session
    /// completion (low rate — not on the data-plane hot path).
    pub fn set_rate_detector(&self, detector: Option<Arc<PerUserBandwidthRateDetector>>) {
        let mut g = self
            .rate_detector
            .lock()
            .expect("PerUserBandwidth rate_detector lock poisoned");
        *g = detector;
    }

    /// Read-only accessor for the current rate detector. Returns
    /// `None` when no detector is wired.
    #[must_use]
    pub fn rate_detector(&self) -> Option<Arc<PerUserBandwidthRateDetector>> {
        self.rate_detector
            .lock()
            .expect("PerUserBandwidth rate_detector lock poisoned")
            .clone()
    }

    /// Record one session's `(tx_bytes, rx_bytes)` against
    /// `user_id`. Called from `InFlightGuard::drop` so the
    /// per-user totals merge AT THE SAME MOMENT as the global
    /// totals — operators never see drift between the aggregate
    /// and the per-user sum.
    ///
    /// Back-compat shim: discards the rate detector's alert
    /// outcome. Callers that want to surface the alert (the binary's
    /// session-close hook) should use [`Self::record_with_rate_check`]
    /// instead.
    pub fn record(&self, user_id: [u8; 8], tx: u64, rx: u64) {
        let _ = self.record_with_rate_check(user_id, tx, rx);
    }

    /// Like [`Self::record`] but returns the bandwidth-rate
    /// detector's alert outcome (or `RateAlertOutcome::Quiet` when
    /// no detector is wired). Callers use the outcome to drive the
    /// WARN log + counter bump for sustained-rate abuse alerts.
    ///
    /// Even when no detector is wired this records into the per-user
    /// accumulator — the rate check is purely additive.
    pub fn record_with_rate_check(&self, user_id: [u8; 8], tx: u64, rx: u64) -> RateAlertOutcome {
        // Hot path: look up + bump under read-lock semantics
        // (mutex is fine because once an entry exists we only
        // touch the atomics; the mutex is dropped immediately).
        let bucket = {
            let mut g = self.inner.lock().expect("PerUserBandwidth lock poisoned");
            if let Some(entry) = g.get(&user_id) {
                Arc::clone(entry)
            } else if g.len() >= self.max_users {
                // Cap hit: accumulate into the overflow bucket
                // (preserves total accounting; operator sees the
                // overflow in /metrics as a flag to raise the
                // cap).
                Arc::clone(&self.overflow)
            } else {
                let bucket = Arc::new(UserBytes::default());
                g.insert(user_id, Arc::clone(&bucket));
                bucket
            }
        };
        if tx > 0 {
            bucket.tx.fetch_add(tx, Ordering::Relaxed);
        }
        if rx > 0 {
            bucket.rx.fetch_add(rx, Ordering::Relaxed);
        }
        // Charge the per-user quota tracker (when wired) with the
        // full (tx + rx) byte count. The quota tracker's
        // is_over_quota() check happens at the post-handshake
        // admission gate; this just keeps the running tally
        // current. Quota tracking is purely additive — it never
        // changes the outcome of the rate-check below.
        if let Some(quota) = self.quota() {
            let bytes_total = tx.saturating_add(rx);
            if bytes_total > 0 {
                let _ = quota.record(user_id, bytes_total);
            }
        }
        // Consult the rate detector if wired. The detector's
        // window-based rate measurement is based on the sum of
        // (tx + rx) bytes — both directions count toward "sustained
        // bandwidth" because operators care about NIC saturation /
        // exfiltration regardless of direction.
        if let Some(det) = self.rate_detector() {
            let bytes_total = tx.saturating_add(rx);
            let outcome = det.record(user_id, bytes_total);
            // On Fired, also push into the recent-abuse-fires ring
            // buffer (when wired). Context_value carries the
            // computed rate so the `/diagnose` table / CLI shows
            // the magnitude of the burst.
            if let RateAlertOutcome::Fired { bytes_per_sec: _ } = outcome {
                if let Some(buf) = self.abuse_fires() {
                    if let RateAlertOutcome::Fired { bytes_per_sec } = outcome {
                        buf.push(
                            crate::abuse_fires::AbuseFireKind::PerUserBandwidthRate,
                            user_id,
                            bytes_per_sec,
                        );
                    }
                }
                // Auto-quarantine when the operator opted this
                // detector kind in. Strongest signal of all three
                // detectors (hysteresis-protected, sliding-window
                // RATE — not a single-event spike), so a single
                // fire is enough to ban for the TTL.
                if self
                    .quarantine_on_fire
                    .load(std::sync::atomic::Ordering::Relaxed)
                {
                    if let Some(qlist) = self.quarantine() {
                        if qlist.insert(
                            user_id,
                            crate::abuse_fires::AbuseFireKind::PerUserBandwidthRate.as_label(),
                        ) {
                            tracing::warn!(
                                user_id = %crate::per_user_bandwidth::render_user_id_pub(&user_id),
                                ttl_secs = qlist.ttl().as_secs(),
                                "auto-quarantine: user_id banned for TTL on per_user_bandwidth_rate abuse fire"
                            );
                        }
                    }
                }
            }
            return outcome;
        }
        RateAlertOutcome::Quiet
    }

    /// Snapshot the per-user totals. Returns a `(user_id, tx, rx)`
    /// triple per recorded user, plus the overflow bucket as a
    /// separate entry with user_id `b"OVERFLOW"` (8-byte
    /// placeholder). Used by the Prometheus emitter.
    ///
    /// Sorted by `user_id` lexically so the rendered output is
    /// stable across scrapes (helps consumers that diff between
    /// scrapes).
    #[must_use]
    pub fn snapshot(&self) -> Vec<([u8; 8], UserBytesSnapshot)> {
        let g = self.inner.lock().expect("PerUserBandwidth lock poisoned");
        let mut out: Vec<_> = g
            .iter()
            .map(|(uid, b)| {
                (
                    *uid,
                    UserBytesSnapshot {
                        tx: b.tx.load(Ordering::Relaxed),
                        rx: b.rx.load(Ordering::Relaxed),
                    },
                )
            })
            .collect();
        out.sort_by_key(|(uid, _)| *uid);
        // Append the overflow bucket only when it's non-zero —
        // operators who never hit the cap don't see a confusing
        // `__overflow__` row.
        let overflow = UserBytesSnapshot {
            tx: self.overflow.tx.load(Ordering::Relaxed),
            rx: self.overflow.rx.load(Ordering::Relaxed),
        };
        if overflow.tx > 0 || overflow.rx > 0 {
            out.push((*b"OVERFLOW", overflow));
        }
        out
    }

    /// Count of distinct user_ids currently tracked (excluding the
    /// overflow bucket). Operator gauges this via
    /// `proteus_per_user_bandwidth_tracked_users` to know when
    /// they're approaching the cap.
    #[must_use]
    pub fn tracked_users(&self) -> usize {
        self.inner
            .lock()
            .expect("PerUserBandwidth lock poisoned")
            .len()
    }

    /// Operator-supplied cap.
    #[must_use]
    pub fn max_users(&self) -> usize {
        self.max_users
    }

    /// Emit the Prometheus exposition block. Renders three series:
    ///
    /// - `proteus_per_user_bytes_sent_total{user_id="…"}` (counter)
    /// - `proteus_per_user_bytes_received_total{user_id="…"}` (counter)
    /// - `proteus_per_user_bandwidth_tracked_users` (gauge —
    ///   distinct user_ids in the map, excluding overflow)
    ///
    /// PromQL recipes operators script against this:
    ///
    /// ```promql
    /// # top 5 bandwidth users right now
    /// topk(5, rate(proteus_per_user_bytes_sent_total[1m]))
    ///
    /// # user pushing > 100 MB/s — potential abuse
    /// rate(proteus_per_user_bytes_sent_total[1m]) > 100 * 1024 * 1024
    ///
    /// # user_ids overflowing the cap — raise max_users in YAML
    /// proteus_per_user_bandwidth_tracked_users >= 4096
    /// ```
    #[must_use]
    pub fn prometheus(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(512);
        let entries = self.snapshot();
        if !entries.is_empty() {
            let _ = writeln!(
                s,
                "# HELP proteus_per_user_bytes_sent_total Lifetime bytes sent to each user (tx)."
            );
            let _ = writeln!(s, "# TYPE proteus_per_user_bytes_sent_total counter");
            for (uid, snap) in &entries {
                let _ = writeln!(
                    s,
                    r#"proteus_per_user_bytes_sent_total{{user_id="{}"}} {}"#,
                    escape_label(&render_user_id(uid)),
                    snap.tx
                );
            }
            let _ = writeln!(
                s,
                "# HELP proteus_per_user_bytes_received_total Lifetime bytes received from each user (rx)."
            );
            let _ = writeln!(s, "# TYPE proteus_per_user_bytes_received_total counter");
            for (uid, snap) in &entries {
                let _ = writeln!(
                    s,
                    r#"proteus_per_user_bytes_received_total{{user_id="{}"}} {}"#,
                    escape_label(&render_user_id(uid)),
                    snap.rx
                );
            }
        }
        // tracked_users gauge always present — operator script can
        // tell "is per-user bandwidth feature wired" from this
        // (presence = wired).
        let _ = writeln!(
            s,
            "# HELP proteus_per_user_bandwidth_tracked_users Distinct user_ids currently tracked (cap = max_users)."
        );
        let _ = writeln!(s, "# TYPE proteus_per_user_bandwidth_tracked_users gauge");
        let _ = writeln!(
            s,
            "proteus_per_user_bandwidth_tracked_users {}",
            self.tracked_users()
        );
        // Append the rate-detector's gauges if a detector is wired.
        // This keeps "the bandwidth metrics" rendered as one
        // contiguous block on /metrics — operators don't need to
        // know the detector lives in a separate module.
        if let Some(det) = self.rate_detector() {
            s.push_str(&det.prometheus());
        }
        s
    }
}

/// Public re-export of [`render_user_id`] for callers outside this
/// module (the metrics module's WARN log uses it to render user_ids
/// consistently with the `/metrics` label format).
#[must_use]
pub fn render_user_id_pub(uid: &[u8; 8]) -> String {
    render_user_id(uid)
}

/// Render a user_id `[u8; 8]` as an operator-friendly string.
/// Strategy:
///   - If every byte is ASCII printable (0x21..=0x7E) AND the
///     value contains no `"` or `\`, render as the trimmed UTF-8
///     string (most operator-chosen user_ids like "alice001" are
///     ASCII).
///   - Otherwise render as `hex:<16 hex chars>` so the operator
///     can still grep + report. The `hex:` prefix disambiguates
///     from a literal ASCII id that happens to look like hex.
fn render_user_id(uid: &[u8; 8]) -> String {
    // Special-case the overflow marker so it renders without the
    // `hex:` prefix.
    if uid == b"OVERFLOW" {
        return "__overflow__".to_string();
    }
    let trimmed: &[u8] = match uid.iter().position(|&b| b == 0) {
        Some(end) => &uid[..end],
        None => &uid[..],
    };
    let printable = !trimmed.is_empty()
        && trimmed
            .iter()
            .all(|&b| (0x21..=0x7E).contains(&b) && b != b'"' && b != b'\\');
    if printable {
        // Safe by construction (printable-ASCII subset is valid UTF-8).
        std::str::from_utf8(trimmed)
            .map(|s| s.to_string())
            .unwrap_or_else(|_| format!("hex:{}", hex_encode(uid)))
    } else {
        format!("hex:{}", hex_encode(uid))
    }
}

fn hex_encode(b: &[u8; 8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut s = String::with_capacity(16);
    for &byte in b {
        s.push(HEX[(byte >> 4) as usize] as char);
        s.push(HEX[(byte & 0x0f) as usize] as char);
    }
    s
}

/// Prometheus 0.0.4 label-value escape: `\` → `\\`, `"` → `\"`,
/// `\n` → `\n`. The `render_user_id` ASCII filter already strips
/// the dangerous characters, but this stays defense-in-depth for
/// the `hex:` path and any future render strategies.
fn escape_label(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '\\' => out.push_str(r"\\"),
            '"' => out.push_str(r#"\""#),
            '\n' => out.push_str(r"\n"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_accumulator_has_zero_tracked_users() {
        let p = PerUserBandwidth::new(4096);
        assert_eq!(p.tracked_users(), 0);
        assert!(p.snapshot().is_empty());
    }

    #[test]
    fn record_creates_entry_and_accumulates() {
        let p = PerUserBandwidth::new(4096);
        p.record(*b"alice001", 100, 200);
        p.record(*b"alice001", 50, 25);
        assert_eq!(p.tracked_users(), 1);
        let snap = p.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].0, *b"alice001");
        assert_eq!(snap[0].1.tx, 150);
        assert_eq!(snap[0].1.rx, 225);
    }

    #[test]
    fn distinct_user_ids_get_distinct_entries() {
        let p = PerUserBandwidth::new(4096);
        p.record(*b"alice001", 100, 0);
        p.record(*b"bob00002", 200, 0);
        p.record(*b"carol003", 300, 0);
        assert_eq!(p.tracked_users(), 3);
        let snap = p.snapshot();
        assert_eq!(snap.len(), 3);
        // Sorted lexically.
        assert_eq!(snap[0].0, *b"alice001");
        assert_eq!(snap[1].0, *b"bob00002");
        assert_eq!(snap[2].0, *b"carol003");
    }

    #[test]
    fn overflow_bucket_collects_beyond_cap() {
        let p = PerUserBandwidth::new(2);
        p.record(*b"user0001", 100, 0);
        p.record(*b"user0002", 100, 0);
        // Cap hit; these two go to overflow.
        p.record(*b"user0003", 50, 25);
        p.record(*b"user0004", 75, 50);
        assert_eq!(p.tracked_users(), 2, "cap is 2");
        let snap = p.snapshot();
        assert_eq!(snap.len(), 3, "2 tracked + 1 overflow row");
        // Overflow row appears last + has user_id b"OVERFLOW".
        assert_eq!(snap[2].0, *b"OVERFLOW");
        assert_eq!(snap[2].1.tx, 125, "overflow tx accumulated");
        assert_eq!(snap[2].1.rx, 75);
    }

    #[test]
    fn record_zero_bytes_does_not_create_overflow_row() {
        // Edge case: cap hit, record (0, 0) — overflow snapshot
        // stays at 0 → no overflow row in the snapshot output.
        let p = PerUserBandwidth::new(1);
        p.record(*b"user0001", 0, 0);
        p.record(*b"user0002", 0, 0); // would go to overflow
        let snap = p.snapshot();
        assert_eq!(
            snap.len(),
            1,
            "zero-byte overflow must NOT add a row: {snap:?}"
        );
    }

    #[test]
    fn render_user_id_ascii_printable_uses_utf8() {
        assert_eq!(render_user_id(b"alice001"), "alice001");
        assert_eq!(render_user_id(b"bob00002"), "bob00002");
    }

    #[test]
    fn render_user_id_trims_trailing_nulls() {
        // user_id "bob" zero-padded
        assert_eq!(render_user_id(b"bob\0\0\0\0\0"), "bob");
    }

    #[test]
    fn render_user_id_falls_back_to_hex_when_non_printable() {
        let bad = [0xff_u8, 0x00, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56];
        assert_eq!(render_user_id(&bad), "hex:ff00abcdef123456");
    }

    #[test]
    fn render_user_id_falls_back_to_hex_when_contains_quotes() {
        let quote_id = [b'a', b'"', b'b', 0, 0, 0, 0, 0];
        let rendered = render_user_id(&quote_id);
        assert!(
            rendered.starts_with("hex:"),
            "must use hex prefix when '\"' in id: {rendered}"
        );
    }

    #[test]
    fn render_user_id_overflow_marker_renders_as_double_underscore() {
        assert_eq!(render_user_id(b"OVERFLOW"), "__overflow__");
    }

    #[test]
    fn prometheus_emits_tracked_users_gauge_always() {
        let p = PerUserBandwidth::new(4096);
        let s = p.prometheus();
        // Empty accumulator still emits the gauge.
        assert!(
            s.contains("proteus_per_user_bandwidth_tracked_users 0"),
            "{s}"
        );
        assert!(!s.contains("proteus_per_user_bytes_sent_total"));
    }

    #[test]
    fn prometheus_emits_per_user_series_when_recorded() {
        let p = PerUserBandwidth::new(4096);
        p.record(*b"alice001", 100, 200);
        p.record(*b"bob00002", 50, 75);
        let s = p.prometheus();
        assert!(
            s.contains(r#"proteus_per_user_bytes_sent_total{user_id="alice001"} 100"#),
            "{s}"
        );
        assert!(
            s.contains(r#"proteus_per_user_bytes_received_total{user_id="alice001"} 200"#),
            "{s}"
        );
        assert!(
            s.contains(r#"proteus_per_user_bytes_sent_total{user_id="bob00002"} 50"#),
            "{s}"
        );
        assert!(s.contains("proteus_per_user_bandwidth_tracked_users 2"));
    }

    #[test]
    fn prometheus_help_and_type_appear_once_per_metric_name() {
        let p = PerUserBandwidth::new(4096);
        p.record(*b"a       ", 1, 2);
        p.record(*b"b       ", 3, 4);
        let s = p.prometheus();
        // Two user rows per series, but HELP/TYPE appear once.
        for name in [
            "proteus_per_user_bytes_sent_total",
            "proteus_per_user_bytes_received_total",
            "proteus_per_user_bandwidth_tracked_users",
        ] {
            assert_eq!(
                s.matches(&format!("# HELP {name} ")).count(),
                1,
                "expected 1 HELP for {name}: {s}"
            );
            assert_eq!(
                s.matches(&format!("# TYPE {name} ")).count(),
                1,
                "expected 1 TYPE for {name}: {s}"
            );
        }
    }

    #[test]
    fn prometheus_emits_overflow_row_with_double_underscore_label() {
        let p = PerUserBandwidth::new(1);
        p.record(*b"user0001", 100, 0);
        p.record(*b"user0002", 50, 25); // overflow
        let s = p.prometheus();
        assert!(
            s.contains(r#"proteus_per_user_bytes_sent_total{user_id="__overflow__"} 50"#),
            "{s}"
        );
        assert!(
            s.contains(r#"proteus_per_user_bytes_received_total{user_id="__overflow__"} 25"#),
            "{s}"
        );
    }

    #[test]
    fn snapshot_ordering_is_stable_across_calls() {
        let p = PerUserBandwidth::new(4096);
        // Insert out of order; snapshot must sort.
        p.record(*b"zeta0001", 1, 0);
        p.record(*b"alpha001", 1, 0);
        p.record(*b"mike0001", 1, 0);
        let s1: Vec<_> = p.snapshot().into_iter().map(|(uid, _)| uid).collect();
        let s2: Vec<_> = p.snapshot().into_iter().map(|(uid, _)| uid).collect();
        assert_eq!(s1, s2);
        assert_eq!(s1[0], *b"alpha001");
        assert_eq!(s1[1], *b"mike0001");
        assert_eq!(s1[2], *b"zeta0001");
    }

    #[test]
    fn concurrent_record_does_not_panic_or_drop_bytes() {
        // 16 threads × 1000 records each — counters must match.
        let p = Arc::new(PerUserBandwidth::new(4096));
        let mut handles = Vec::new();
        for _ in 0..16 {
            let p = Arc::clone(&p);
            handles.push(std::thread::spawn(move || {
                for _ in 0..1000 {
                    p.record(*b"alice001", 1, 1);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let snap = p.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].1.tx, 16_000);
        assert_eq!(snap[0].1.rx, 16_000);
    }
}
