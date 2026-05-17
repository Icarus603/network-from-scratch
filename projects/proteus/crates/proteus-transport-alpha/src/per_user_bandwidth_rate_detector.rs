//! Per-user **bandwidth-rate** abuse detector — in-process auto-fire.
//!
//! ## Why this exists (separate from `abuse_detector.rs`)
//!
//! The existing [`crate::abuse_detector::AbuseDetector`] fires on
//! **discrete events**: byte-budget cap hits, per-user rate-limit
//! rejects. It needs an event to *happen* before it counts. That's
//! perfect for "this user repeatedly tripped the cap", but it misses
//! the obvious abuse pattern operators care about most:
//!
//! > "User X has been doing 200 MB/s sustained for 30 seconds —
//! > almost certainly a stolen credential running an exfil tool."
//!
//! No discrete event fires for that pattern as long as the user
//! stays under `max_session_bytes`. The previous answer was "scrape
//! `proteus_per_user_bytes_sent_total`, run PromQL `rate(...) >
//! 100MB/s`, alert via Alertmanager". That works for ops teams with
//! a Prometheus stack. It does NOT work for the canonical Proteus
//! operator — someone running a personal VPN for friends on a
//! single VPS who has only `journalctl` + maybe a Telegram bot
//! tailing the logs.
//!
//! This module brings the alert in-process: feed every per-session
//! `(tx, rx)` merge through it, compute the rolling-window byte
//! rate per user, and fire ONCE per burst the moment the rate
//! crosses the operator-set MB/s threshold. The operator sees a
//! structured WARN line + `proteus_abuse_alerts_per_user_bandwidth_total`
//! ticks up.
//!
//! ## Why sliding window over instant rate
//!
//! Instant rate (= bytes between two adjacent `record()` calls /
//! elapsed time) is noisy as hell — a 1 MB session that closes
//! in 10 ms looks like 100 MB/s for that instant. Sliding window
//! smooths that into "bytes in the last N seconds / N seconds",
//! which matches the operator's mental model ("sustained rate") and
//! avoids paging on every fast-completing session.
//!
//! ## Fire-once-per-burst semantics
//!
//! When the rate crosses the threshold we fire **once**, set an
//! `alerted` flag, and stay silent until the rate drops below
//! `threshold * exit_factor` (default 0.5 → must drop to 50% of
//! threshold to reset). Hysteresis prevents flapping at the
//! threshold boundary — a user oscillating around 100 MB/s won't
//! generate 100 alerts.
//!
//! ## Memory bound
//!
//! Per-user `VecDeque<(Instant, u64)>` capped at one entry per
//! `record()` call inside the window. Vacuumed on every record.
//! Cap: same `max_users` as the per-user bandwidth accumulator;
//! beyond cap, samples are dropped (memory bound > alerting
//! perfection — the alternative is unbounded growth under attack).

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Per-user bandwidth-rate abuse detector. Cheap to share across
/// session handlers via `Arc`. Construct with
/// [`PerUserBandwidthRateDetector::new`].
pub struct PerUserBandwidthRateDetector {
    window: Duration,
    /// Bytes-per-second threshold above which the detector fires.
    /// Compared against `bytes_in_window / window_secs` so it tracks
    /// the operator's "sustained MB/s" mental model.
    threshold_bytes_per_sec: u64,
    /// Hysteresis: the per-user alert flag resets only when the rate
    /// drops below `threshold_bytes_per_sec * exit_factor`. Default
    /// 0.5 — must drop to half threshold to re-arm. Prevents flapping
    /// at the boundary.
    exit_factor: f64,
    /// Cap on the number of distinct user_ids tracked. Beyond the
    /// cap, additional users' samples are silently dropped (the alert
    /// machinery still tracks the users already inside the cap;
    /// memory stays bounded under attack).
    max_users: usize,
    inner: Mutex<HashMap<[u8; 8], UserSamples>>,
}

#[derive(Debug)]
struct UserSamples {
    /// `(timestamp, bytes_delta)` — one entry per `record()` call.
    /// Entries outside the window are drained on each touch so the
    /// deque is bounded by the number of session-completions inside
    /// the window for this user.
    samples: VecDeque<(Instant, u64)>,
    /// Running sum of `bytes_delta` over the deque. Maintained
    /// incrementally so the rate check is O(1) after the vacuum.
    sum_bytes: u64,
    /// `true` once a burst-alert has fired for this user; resets when
    /// the rate drops below `threshold * exit_factor`.
    alerted: bool,
}

impl UserSamples {
    fn new() -> Self {
        Self {
            samples: VecDeque::new(),
            sum_bytes: 0,
            alerted: false,
        }
    }
}

/// Outcome of one `record_at` call. The caller (typically wired
/// inside `PerUserBandwidth::record`) uses this to decide whether to
/// emit a structured WARN log + bump
/// `proteus_abuse_alerts_per_user_bandwidth_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateAlertOutcome {
    /// No alert this call. Either the rate is below threshold, or
    /// the rate is above threshold but a burst-alert has already
    /// fired in this burst.
    Quiet,
    /// First sample in this burst that took the user across the
    /// threshold — fire ONE WARN line + bump the counter. Subsequent
    /// samples in the same burst return `Quiet` until the rate drops
    /// below `threshold * exit_factor` and resets the latch.
    Fired {
        /// Computed rolling-window rate (bytes/sec). Surfaced in the
        /// WARN log so operators see the magnitude.
        bytes_per_sec: u64,
    },
}

impl PerUserBandwidthRateDetector {
    /// Construct. `threshold_bytes_per_sec=0` is treated as "detector
    /// disabled" — `record_at` is a no-op that always returns
    /// `Quiet`. Operators who want the detector wired but silent for
    /// testing leave the threshold at 0.
    #[must_use]
    pub fn new(window: Duration, threshold_bytes_per_sec: u64, max_users: usize) -> Self {
        Self {
            window,
            threshold_bytes_per_sec,
            exit_factor: 0.5,
            max_users,
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Builder: override the default `exit_factor` (0.5). Must be in
    /// `[0.0, 1.0]`. Values outside the range are clamped (a value
    /// of 1.0 means "no hysteresis — re-arm as soon as one sample
    /// drops below threshold", which will flap; 0.0 means "never
    /// re-arm during the user's lifetime", which is also a poor
    /// choice but operationally valid).
    #[must_use]
    pub fn with_exit_factor(mut self, factor: f64) -> Self {
        self.exit_factor = factor.clamp(0.0, 1.0);
        self
    }

    /// `true` when the operator-supplied threshold is 0 — the
    /// detector is effectively disabled. The wire-up keeps the
    /// detector installed (so a SIGHUP hot-swap can flip the
    /// threshold to non-zero without a restart) but every record
    /// returns `Quiet`.
    #[must_use]
    pub fn is_disabled(&self) -> bool {
        self.threshold_bytes_per_sec == 0
    }

    /// Distinct users currently being tracked (excluding the
    /// dropped-on-cap overflow). Used for telemetry + tests.
    #[must_use]
    pub fn tracked_users(&self) -> usize {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    /// Operator-set threshold (bytes/sec). Surfaced in the
    /// Prometheus gauge so operators can verify the running config
    /// matches their YAML edit.
    #[must_use]
    pub fn threshold_bytes_per_sec(&self) -> u64 {
        self.threshold_bytes_per_sec
    }

    /// Sliding-window length (seconds, as a `Duration`). Surfaced
    /// in metrics for the same verification reason.
    #[must_use]
    pub fn window(&self) -> Duration {
        self.window
    }

    /// Record one session's `(tx + rx)` byte delta for `user_id` at
    /// `now`. Returns the alert outcome.
    ///
    /// Called by [`crate::per_user_bandwidth::PerUserBandwidth::record`]
    /// the moment a session completes and its totals are merged.
    pub fn record_at(&self, user_id: [u8; 8], bytes: u64, now: Instant) -> RateAlertOutcome {
        if self.threshold_bytes_per_sec == 0 || bytes == 0 {
            // Disabled or zero-byte session — never fires. The
            // zero-byte case also skips the map mutation so empty
            // handshakes don't take the mutex.
            return RateAlertOutcome::Quiet;
        }
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        // Cap enforcement: new users beyond the cap drop their sample
        // silently. Existing users keep being tracked.
        if !g.contains_key(&user_id) && g.len() >= self.max_users {
            return RateAlertOutcome::Quiet;
        }
        let entry = g.entry(user_id).or_insert_with(UserSamples::new);

        // Append, then vacuum the front (expired samples).
        entry.samples.push_back((now, bytes));
        entry.sum_bytes = entry.sum_bytes.saturating_add(bytes);
        while let Some(&(t, b)) = entry.samples.front() {
            if now.duration_since(t) > self.window {
                entry.samples.pop_front();
                entry.sum_bytes = entry.sum_bytes.saturating_sub(b);
            } else {
                break;
            }
        }

        // Compute rolling-window rate. Floor at 1 second to avoid a
        // tiny-window divide-by-near-zero artifact in the first
        // sample of each user — a user that uploads 5 MB in 100 ms
        // would otherwise look like 50 MB/s and trigger a 100 MB/s
        // alert immediately. Using the configured window as the
        // denominator (NOT the elapsed time since the first sample)
        // gives operators the "MB/s averaged over the window" they
        // configured, which is what their YAML says.
        let window_secs = self.window.as_secs_f64().max(1.0);
        let rate_bps_f = entry.sum_bytes as f64 / window_secs;
        let rate_bps = rate_bps_f as u64;

        // Hysteresis-driven latch:
        //   - threshold crossed (rate >= threshold) + not alerted → fire.
        //   - dropped below `threshold * exit_factor` → re-arm.
        //   - in between → hold current latch state.
        let exit_threshold = (self.threshold_bytes_per_sec as f64 * self.exit_factor) as u64;
        if rate_bps < exit_threshold && entry.alerted {
            entry.alerted = false;
        }
        if rate_bps >= self.threshold_bytes_per_sec && !entry.alerted {
            entry.alerted = true;
            return RateAlertOutcome::Fired {
                bytes_per_sec: rate_bps,
            };
        }
        RateAlertOutcome::Quiet
    }

    /// `Instant::now()` convenience.
    pub fn record(&self, user_id: [u8; 8], bytes: u64) -> RateAlertOutcome {
        self.record_at(user_id, bytes, Instant::now())
    }

    /// Reset all per-user state. Used by tests; production has no
    /// reason to call this (the vacuum keeps memory bounded).
    pub fn clear(&self) {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).clear();
    }

    /// Emit the Prometheus gauges for the detector's configured
    /// parameters. Helpful for operators verifying their YAML edit
    /// landed (alongside the `proteus_abuse_alerts_per_user_bandwidth_total`
    /// counter that the binary maintains on `ServerMetrics`).
    #[must_use]
    pub fn prometheus(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(384);
        let _ = writeln!(
            s,
            "# HELP proteus_per_user_bandwidth_rate_threshold_bytes_per_sec \
             Operator-set sustained-bandwidth threshold (bytes/sec) above which \
             a per-user abuse alert fires. 0 = detector disabled."
        );
        let _ = writeln!(
            s,
            "# TYPE proteus_per_user_bandwidth_rate_threshold_bytes_per_sec gauge"
        );
        let _ = writeln!(
            s,
            "proteus_per_user_bandwidth_rate_threshold_bytes_per_sec {}",
            self.threshold_bytes_per_sec
        );
        let _ = writeln!(
            s,
            "# HELP proteus_per_user_bandwidth_rate_window_seconds \
             Sliding-window length (seconds) over which per-user bandwidth \
             rate is averaged for the abuse detector."
        );
        let _ = writeln!(
            s,
            "# TYPE proteus_per_user_bandwidth_rate_window_seconds gauge"
        );
        let _ = writeln!(
            s,
            "proteus_per_user_bandwidth_rate_window_seconds {}",
            self.window.as_secs()
        );
        let _ = writeln!(
            s,
            "# HELP proteus_per_user_bandwidth_rate_tracked_users \
             Distinct user_ids currently sampled by the bandwidth-rate \
             detector (capped at max_users)."
        );
        let _ = writeln!(
            s,
            "# TYPE proteus_per_user_bandwidth_rate_tracked_users gauge"
        );
        let _ = writeln!(
            s,
            "proteus_per_user_bandwidth_rate_tracked_users {}",
            self.tracked_users()
        );
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }
    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }
    /// 10 MB/s threshold for tests — small enough we can exercise it
    /// without allocating gigabytes, large enough no rounding artifact
    /// trips the test by accident.
    const TEST_THRESHOLD: u64 = 10 * 1024 * 1024;

    #[test]
    fn disabled_when_threshold_zero() {
        let d = PerUserBandwidthRateDetector::new(secs(10), 0, 4096);
        assert!(d.is_disabled());
        assert_eq!(
            d.record(*b"alice001", 1_000_000_000),
            RateAlertOutcome::Quiet
        );
    }

    #[test]
    fn quiet_when_under_threshold() {
        let d = PerUserBandwidthRateDetector::new(secs(10), TEST_THRESHOLD, 4096);
        let now = Instant::now();
        // 1 MiB in a 10s window = 100 KiB/s, well under 10 MiB/s.
        assert_eq!(
            d.record_at(*b"alice001", 1024 * 1024, now),
            RateAlertOutcome::Quiet
        );
    }

    #[test]
    fn fires_on_threshold_cross_once() {
        let d = PerUserBandwidthRateDetector::new(secs(10), TEST_THRESHOLD, 4096);
        let now = Instant::now();
        // 200 MiB across the window = 20 MiB/s sustained, clearly
        // over 10 MiB/s.
        let burst = 200 * 1024 * 1024;
        let r = d.record_at(*b"alice001", burst, now);
        match r {
            RateAlertOutcome::Fired { bytes_per_sec } => {
                assert!(
                    bytes_per_sec >= TEST_THRESHOLD,
                    "fired bytes/sec must be ≥ threshold, got {bytes_per_sec}"
                );
            }
            other => panic!("expected Fired, got {other:?}"),
        }
        // Second record at SAME burst — alerted latch holds; quiet.
        assert_eq!(
            d.record_at(*b"alice001", burst, now + ms(100)),
            RateAlertOutcome::Quiet,
            "must not fire twice in same burst"
        );
    }

    #[test]
    fn re_arms_after_rate_drops_below_exit_factor() {
        let d = PerUserBandwidthRateDetector::new(secs(10), TEST_THRESHOLD, 4096);
        let t0 = Instant::now();
        let burst = 200 * 1024 * 1024;
        assert!(matches!(
            d.record_at(*b"alice001", burst, t0),
            RateAlertOutcome::Fired { .. }
        ));
        // Walk forward past the window so the deque empties + rate
        // drops to zero. Re-arm condition met.
        let later = t0 + secs(15);
        // Tiny sample — under exit threshold.
        assert_eq!(
            d.record_at(*b"alice001", 1024, later),
            RateAlertOutcome::Quiet
        );
        // Now another big burst — must fire again because the latch
        // re-armed.
        assert!(matches!(
            d.record_at(*b"alice001", burst, later + ms(10)),
            RateAlertOutcome::Fired { .. }
        ));
    }

    #[test]
    fn hysteresis_prevents_flap_at_threshold_boundary() {
        // exit_factor=0.5 (default). Threshold=10 MB/s. Once fired,
        // rate must drop below 5 MB/s to re-arm. A user oscillating
        // at ~9-10 MB/s should fire ONCE then stay quiet.
        let d = PerUserBandwidthRateDetector::new(secs(10), TEST_THRESHOLD, 4096);
        let t0 = Instant::now();
        // First sample at threshold → fires.
        let burst = 110 * 1024 * 1024; // ~11 MB/s
        assert!(matches!(
            d.record_at(*b"alice001", burst, t0),
            RateAlertOutcome::Fired { .. }
        ));
        // Subsequent samples slightly under threshold but above
        // exit factor (e.g. 8 MB/s) — quiet.
        let mid = 80 * 1024 * 1024;
        for k in 1..5 {
            assert_eq!(
                d.record_at(*b"alice001", mid, t0 + ms(100 * k)),
                RateAlertOutcome::Quiet,
                "must not flap at sample {k} (rate within hysteresis band)"
            );
        }
    }

    #[test]
    fn distinct_users_have_independent_state() {
        let d = PerUserBandwidthRateDetector::new(secs(10), TEST_THRESHOLD, 4096);
        let now = Instant::now();
        let burst = 200 * 1024 * 1024;
        assert!(matches!(
            d.record_at(*b"alice001", burst, now),
            RateAlertOutcome::Fired { .. }
        ));
        // Bob hasn't sent anything yet — must fire on his own burst,
        // independent of alice's latch.
        assert!(matches!(
            d.record_at(*b"bob00002", burst, now + ms(50)),
            RateAlertOutcome::Fired { .. }
        ));
    }

    #[test]
    fn samples_expire_out_of_window() {
        let d = PerUserBandwidthRateDetector::new(secs(2), TEST_THRESHOLD, 4096);
        let t0 = Instant::now();
        // Two small samples 3s apart — older one expires before the
        // second is recorded. Sum should reflect only the new sample.
        d.record_at(*b"alice001", 100, t0);
        d.record_at(*b"alice001", 100, t0 + secs(5));
        let inner = d.inner.lock().unwrap();
        let s = inner.get(b"alice001").unwrap();
        assert_eq!(
            s.samples.len(),
            1,
            "old sample must be vacuumed: {:?}",
            s.samples
        );
        assert_eq!(s.sum_bytes, 100);
    }

    #[test]
    fn zero_byte_record_is_a_noop() {
        let d = PerUserBandwidthRateDetector::new(secs(10), TEST_THRESHOLD, 4096);
        let now = Instant::now();
        assert_eq!(d.record_at(*b"alice001", 0, now), RateAlertOutcome::Quiet);
        // Map untouched.
        assert_eq!(d.tracked_users(), 0);
    }

    #[test]
    fn cap_drops_new_users_silently_keeps_existing_tracked() {
        // Cap = 2: alice + bob tracked, carol is new beyond cap → dropped.
        let d = PerUserBandwidthRateDetector::new(secs(10), TEST_THRESHOLD, 2);
        let now = Instant::now();
        d.record_at(*b"alice001", 1024, now);
        d.record_at(*b"bob00002", 1024, now);
        assert_eq!(d.tracked_users(), 2);
        // Carol is dropped at cap.
        let r = d.record_at(*b"carol003", 200 * 1024 * 1024, now);
        assert_eq!(r, RateAlertOutcome::Quiet, "carol over cap must not fire");
        assert_eq!(d.tracked_users(), 2, "cap honored");
        // Existing user (alice) can still cross threshold normally.
        let burst = 200 * 1024 * 1024;
        assert!(matches!(
            d.record_at(*b"alice001", burst, now + ms(10)),
            RateAlertOutcome::Fired { .. }
        ));
    }

    #[test]
    fn prometheus_emits_threshold_window_tracked_gauges() {
        let d = PerUserBandwidthRateDetector::new(secs(30), 100 * 1024 * 1024, 4096);
        d.record(*b"alice001", 1024);
        let s = d.prometheus();
        assert!(
            s.contains("proteus_per_user_bandwidth_rate_threshold_bytes_per_sec 104857600"),
            "{s}"
        );
        assert!(
            s.contains("proteus_per_user_bandwidth_rate_window_seconds 30"),
            "{s}"
        );
        assert!(
            s.contains("proteus_per_user_bandwidth_rate_tracked_users 1"),
            "{s}"
        );
    }

    #[test]
    fn prometheus_renders_zero_threshold_disabled_detector() {
        let d = PerUserBandwidthRateDetector::new(secs(30), 0, 4096);
        let s = d.prometheus();
        // Operator-visible: threshold gauge shows 0 → detector disabled.
        assert!(s.contains("proteus_per_user_bandwidth_rate_threshold_bytes_per_sec 0"));
        // tracked_users still emits as 0 — operators script "detector
        // present but disabled" from this combination.
        assert!(s.contains("proteus_per_user_bandwidth_rate_tracked_users 0"));
    }

    #[test]
    fn exit_factor_clamped_to_unit_interval() {
        let d_neg = PerUserBandwidthRateDetector::new(secs(10), TEST_THRESHOLD, 4096)
            .with_exit_factor(-1.0);
        assert!((d_neg.exit_factor - 0.0).abs() < 1e-12);
        let d_big =
            PerUserBandwidthRateDetector::new(secs(10), TEST_THRESHOLD, 4096).with_exit_factor(5.0);
        assert!((d_big.exit_factor - 1.0).abs() < 1e-12);
    }
}
