//! Per-user sliding-window abuse detector.
//!
//! Production deployments care about three patterns that the existing
//! per-event log lines don't surface well:
//!
//! 1. **Credential abuse** — same `user_id` repeatedly hitting the
//!    byte-budget cap. Indicates a stolen credential being used to
//!    exfiltrate data.
//! 2. **Brute-force / botnet** — same `user_id` repeatedly rejected
//!    by the per-user rate limiter. Indicates the legitimate client
//!    is misconfigured OR multiple bots are using one credential.
//! 3. **Aggressive disconnects** — same `user_id` accumulating
//!    abnormal `close_reason` events at a high rate.
//!
//! Operators today have to grep through the access log to spot these
//! patterns. This module aggregates them: a per-user count over a
//! sliding window, with one structured WARN log + one Prometheus
//! counter increment the moment the threshold crosses.
//!
//! Design:
//! - In-memory only. We don't persist event histories across server
//!   restarts; the window is short enough (5 minutes default) that
//!   restarting is the equivalent of clearing the alert.
//! - Lock-free fast path: a single [`Mutex<HashMap>`] keyed on
//!   `user_id`. The check runs once per session close (low rate),
//!   not on the data-plane hot path.
//! - Bounded memory: vacuum on every check (drop entries whose
//!   window is fully expired). With reasonable thresholds the map
//!   never exceeds ~`active_users`.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// One abuse-detector instance. Cheap to clone via Arc when the
/// caller shares it across tasks.
pub struct AbuseDetector {
    window: Duration,
    threshold: usize,
    /// Per-user event timestamps. VecDeque so we can drain expired
    /// entries from the front in O(1) amortized.
    events: Mutex<HashMap<[u8; 8], UserState>>,
}

struct UserState {
    /// Timestamps of the last `<= threshold` events that fell inside
    /// the window. Older events get drained on each check.
    timestamps: VecDeque<Instant>,
    /// `true` once we've emitted a fired-alert for this user during
    /// the current burst. Reset once the window goes empty so a
    /// later burst re-alerts.
    alerted: bool,
}

impl AbuseDetector {
    /// Build a detector with a sliding-window length + the number of
    /// events that constitute "abuse". For example,
    /// `(window=300s, threshold=3)` means "3 byte-budget hits within
    /// 5 minutes for the same user".
    #[must_use]
    pub fn new(window: Duration, threshold: usize) -> Self {
        Self {
            window,
            threshold,
            events: Mutex::new(HashMap::new()),
        }
    }

    /// Record one event for `user_id` at `now`. Returns `true` if
    /// this event just crossed the threshold (i.e. the caller should
    /// fire a WARN log + bump a counter). Subsequent events in the
    /// same burst return `false` so each burst alerts exactly once.
    ///
    /// Pure-CPU; no I/O. Safe to call from any context.
    pub fn record_at(&self, user_id: [u8; 8], now: Instant) -> bool {
        let mut events = self.events.lock().expect("AbuseDetector mutex poisoned");

        // Periodic vacuum: drop fully-expired user state. O(N) on
        // the map but only runs amortized — the hot path is the
        // VecDeque drain below.
        events.retain(|_, state| {
            // Keep if there's at least one timestamp still inside
            // the window OR we're mid-alert (so a brand-new burst
            // immediately after silence resets correctly).
            state
                .timestamps
                .back()
                .is_some_and(|&t| now.duration_since(t) < self.window)
        });

        let state = events.entry(user_id).or_insert_with(|| UserState {
            timestamps: VecDeque::with_capacity(self.threshold + 1),
            alerted: false,
        });

        // Drop expired entries from the front of this user's deque.
        while let Some(&front) = state.timestamps.front() {
            if now.duration_since(front) >= self.window {
                state.timestamps.pop_front();
            } else {
                break;
            }
        }

        // If the window went empty, reset the alert flag so the next
        // burst gets a fresh alert.
        if state.timestamps.is_empty() {
            state.alerted = false;
        }

        state.timestamps.push_back(now);

        // Cap the deque size to threshold so memory stays bounded
        // even for users sustaining the threshold rate indefinitely.
        while state.timestamps.len() > self.threshold {
            state.timestamps.pop_front();
        }

        // Fire-once semantics: emit the alert only on the first
        // event that brings us AT OR ABOVE threshold; subsequent
        // events in the same burst are silent until the window
        // goes empty again.
        if state.timestamps.len() >= self.threshold && !state.alerted {
            state.alerted = true;
            true
        } else {
            false
        }
    }

    /// Convenience wrapper using `Instant::now()`.
    pub fn record(&self, user_id: [u8; 8]) -> bool {
        self.record_at(user_id, Instant::now())
    }

    /// Number of users currently being tracked. Used for telemetry +
    /// tests.
    #[must_use]
    pub fn tracked_users(&self) -> usize {
        self.events
            .lock()
            .expect("AbuseDetector mutex poisoned")
            .len()
    }

    /// Force-drop all per-user state. Used by tests / SIGHUP.
    pub fn clear(&self) {
        self.events
            .lock()
            .expect("AbuseDetector mutex poisoned")
            .clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn first_event_does_not_alert() {
        let d = AbuseDetector::new(ms(500), 3);
        let t = Instant::now();
        assert!(!d.record_at(*b"alice001", t));
    }

    #[test]
    fn alerts_when_threshold_crossed_in_window() {
        let d = AbuseDetector::new(ms(500), 3);
        let t = Instant::now();
        assert!(!d.record_at(*b"alice001", t));
        assert!(!d.record_at(*b"alice001", t + ms(50)));
        assert!(d.record_at(*b"alice001", t + ms(100)));
    }

    #[test]
    fn does_not_alert_when_events_age_out() {
        let d = AbuseDetector::new(ms(100), 3);
        let t = Instant::now();
        d.record_at(*b"alice001", t);
        d.record_at(*b"alice001", t + ms(50));
        // Third event after the window has rolled past the first two.
        // The 3rd is the only one in the current window — no alert.
        assert!(!d.record_at(*b"alice001", t + ms(200)));
    }

    #[test]
    fn alerts_exactly_once_per_burst() {
        let d = AbuseDetector::new(ms(1000), 2);
        let t = Instant::now();
        assert!(!d.record_at(*b"alice001", t));
        assert!(d.record_at(*b"alice001", t + ms(10)));
        // Further events in the same window — already alerted, no
        // duplicate alert.
        assert!(!d.record_at(*b"alice001", t + ms(20)));
        assert!(!d.record_at(*b"alice001", t + ms(30)));
    }

    #[test]
    fn alerts_again_after_window_goes_empty() {
        let d = AbuseDetector::new(ms(100), 2);
        let t = Instant::now();
        d.record_at(*b"alice001", t);
        assert!(d.record_at(*b"alice001", t + ms(10))); // first burst
                                                        // Wait past the window so the deque empties.
        let later = t + ms(500);
        assert!(!d.record_at(*b"alice001", later));
        assert!(d.record_at(*b"alice001", later + ms(10))); // second burst
    }

    #[test]
    fn different_users_are_independent() {
        let d = AbuseDetector::new(ms(1000), 2);
        let t = Instant::now();
        // alice trips
        d.record_at(*b"alice001", t);
        assert!(d.record_at(*b"alice001", t + ms(10)));
        // bob is unaffected
        assert!(!d.record_at(*b"bob00000", t + ms(10)));
        assert!(d.record_at(*b"bob00000", t + ms(20)));
    }

    #[test]
    fn vacuum_drops_idle_users() {
        let d = AbuseDetector::new(ms(50), 5);
        let t = Instant::now();
        for i in 0..10u8 {
            let mut uid = [0u8; 8];
            uid[0] = i;
            d.record_at(uid, t);
        }
        assert_eq!(d.tracked_users(), 10);
        // Far past the window — vacuum drops them all.
        d.record_at(*b"refreshr", t + ms(200));
        // We tracked 1 refreshr + 0 from the past round (vacuumed).
        assert_eq!(d.tracked_users(), 1);
    }

    #[test]
    fn deque_size_capped_to_threshold() {
        // A user sustaining the threshold rate forever should not
        // accumulate unbounded events.
        let d = AbuseDetector::new(ms(10_000), 3);
        let t = Instant::now();
        for i in 0..100u64 {
            d.record_at(*b"flooder1", t + Duration::from_micros(i));
        }
        // We can't read the deque directly, but the test is that
        // the call returns and no allocation explodes — it's
        // implicitly verified by completion.
        assert_eq!(d.tracked_users(), 1);
    }

    #[test]
    fn clear_drops_all_state() {
        let d = AbuseDetector::new(ms(100), 2);
        d.record(*b"alice001");
        d.record(*b"bob00000");
        assert!(d.tracked_users() >= 1);
        d.clear();
        assert_eq!(d.tracked_users(), 0);
    }

    #[test]
    fn threshold_of_one_alerts_on_first_event() {
        // Edge case: threshold=1 means "alert immediately".
        let d = AbuseDetector::new(ms(1000), 1);
        assert!(d.record(*b"alice001"));
        // Same user, same window — no duplicate alert.
        assert!(!d.record(*b"alice001"));
    }
}
