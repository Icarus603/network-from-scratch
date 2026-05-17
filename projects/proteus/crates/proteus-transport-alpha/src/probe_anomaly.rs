//! Per-source-IP cover-forward anomaly detector (2026 threat-intel
//! main line 4 follow-on).
//!
//! ## Why this exists
//!
//! Cover-forward is the byte-verbatim splice that runs whenever an
//! auth check fails. Under normal operation it fires only on the
//! very occasional misconfigured client. Under sustained probe
//! traffic from a Tiangou-class adversary it fires *repeatedly* from
//! the same source IP (or /24 prefix) — that pattern is itself the
//! signal that an attacker is mapping the Proteus server, even
//! though each individual cover-forward looks like a legit HTTPS
//! response from the cover URL.
//!
//! The cover-endpoint pool (`cover_pool.rs`) defeats the *time-
//! series-rotation* signal a single observer would otherwise infer.
//! This module defeats the *probe-volume* signal: it sliding-window-
//! counts cover-forwards per source IP and fires a structured
//! WARN log + Prometheus metric increment the moment any /24 (v4) /
//! /48 (v6) crosses the threshold.
//!
//! ## Why per-/24 affinity instead of per-/32
//!
//! Same rationale as `cover_pool.rs`: full /32 keying lets an
//! attacker rotate src IPs within their NAT or hosting block to
//! escape detection. Collapsing to /24 (v4) / /48 (v6) means any
//! small-network origin accumulates against one bucket, so the
//! attacker cannot dilute their score by rebinding.
//!
//! ## What this module does NOT do
//!
//! - **Does not block.** Firing the anomaly only emits the metric +
//!   log; the operator's existing rate-limiter / firewall remains
//!   the actual block. We deliberately don't add a second
//!   block-decision path so the rate-limiter stays the single
//!   source of truth for "is this IP allowed".
//! - **Does not persist.** Same as `AbuseDetector` — in-memory
//!   only; restart clears history.
//! - **Does not cross-correlate with cover-pool selection.** This
//!   detector watches `record_at(peer_ip)` calls; whether that peer
//!   hashed to cover URL A or B in the pool is irrelevant to the
//!   anomaly count.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// One probe-anomaly detector instance. Hold inside an `Arc` to
/// share across accept-loop tasks.
pub struct ProbeAnomalyDetector {
    window: Duration,
    threshold: usize,
    /// Per-/24 (v4) / /48 (v6) prefix bucket → recent cover-forward
    /// timestamps. We key on the prefix bytes (3 for v4, 6 for v6)
    /// in a single uniform `Vec<u8>`-keyed map so the impl handles
    /// both address families with one code path.
    events: Mutex<HashMap<PrefixKey, PrefixState>>,
    /// Hard cap on the map size — defense against an attacker who
    /// sweeps src IPs across millions of prefixes to OOM the
    /// detector's bookkeeping. When this cap is hit, the detector
    /// stops tracking new prefixes (existing tracked prefixes
    /// continue) and increments `dropped_prefix_inserts`.
    max_prefixes: usize,
    dropped_prefix_inserts: std::sync::atomic::AtomicU64,
}

type PrefixKey = [u8; 6]; // 3 bytes for v4 (zero-padded), 6 bytes for v6

struct PrefixState {
    timestamps: VecDeque<Instant>,
    alerted: bool,
}

/// Default sliding-window length (5 minutes — matches `AbuseDetector`).
pub const DEFAULT_WINDOW: Duration = Duration::from_secs(300);

/// Default per-prefix threshold (8 cover-forwards in 5 min).
///
/// Rationale: a single misconfigured legitimate client typically
/// generates 1-2 cover-forwards before the operator notices and
/// fixes the config. 8 in 5 minutes is well above any organic
/// failure rate and well below the rate a deliberate prober
/// would need to sustain to be worth alerting on.
pub const DEFAULT_THRESHOLD: usize = 8;

/// Default cap on tracked prefixes (16 k entries × ~64 bytes each
/// ≈ 1 MiB of bookkeeping per detector — well under the per-session
/// memory ceilings elsewhere in the codebase).
pub const DEFAULT_MAX_PREFIXES: usize = 16 * 1024;

impl ProbeAnomalyDetector {
    /// Build a detector with the supplied sliding-window length +
    /// threshold + bookkeeping cap.
    #[must_use]
    pub fn new(window: Duration, threshold: usize, max_prefixes: usize) -> Self {
        Self {
            window,
            threshold,
            events: Mutex::new(HashMap::new()),
            max_prefixes,
            dropped_prefix_inserts: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Convenience constructor with the documented defaults.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_WINDOW, DEFAULT_THRESHOLD, DEFAULT_MAX_PREFIXES)
    }

    /// Compute the prefix key for an `IpAddr` — /24 for v4, /48 for v6.
    #[must_use]
    pub fn prefix_key(ip: IpAddr) -> PrefixKey {
        let mut k = [0u8; 6];
        match ip {
            IpAddr::V4(v4) => {
                let oct = v4.octets();
                k[..3].copy_from_slice(&oct[..3]);
            }
            IpAddr::V6(v6) => {
                let oct = v6.octets();
                k.copy_from_slice(&oct[..6]);
            }
        }
        k
    }

    /// Record one cover-forward event from `ip` at `now`. Returns
    /// `Some(prefix_key)` exactly once per anomaly burst, the moment
    /// the threshold is crossed — the caller logs + bumps a
    /// Prometheus counter on that signal. Returns `None` for every
    /// other event (below threshold, or above threshold but already
    /// alerted in this burst).
    pub fn record_at(&self, ip: IpAddr, now: Instant) -> Option<PrefixKey> {
        let key = Self::prefix_key(ip);
        let mut events = self
            .events
            .lock()
            .expect("ProbeAnomalyDetector mutex poisoned");

        // Periodic vacuum — drop fully-expired prefix state. Cheap
        // amortized; the hot path is the VecDeque drain below.
        events.retain(|_, state| {
            state
                .timestamps
                .back()
                .is_some_and(|&t| now.duration_since(t) < self.window)
        });

        // Memory cap: only refuse INSERTS once we hit the cap;
        // existing tracked prefixes continue to record. This means
        // an attacker can't evict legitimate-but-misconfigured
        // clients from the table by IP-sweep flooding.
        if !events.contains_key(&key) && events.len() >= self.max_prefixes {
            self.dropped_prefix_inserts
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return None;
        }

        let state = events.entry(key).or_insert_with(|| PrefixState {
            timestamps: VecDeque::with_capacity(self.threshold + 1),
            alerted: false,
        });

        // Drop expired entries from the front of this prefix's deque.
        while let Some(&front) = state.timestamps.front() {
            if now.duration_since(front) >= self.window {
                state.timestamps.pop_front();
            } else {
                break;
            }
        }
        if state.timestamps.is_empty() {
            state.alerted = false;
        }
        state.timestamps.push_back(now);
        // Cap deque size to threshold so memory stays bounded even
        // under sustained-rate attackers.
        while state.timestamps.len() > self.threshold {
            state.timestamps.pop_front();
        }

        // Fire-once: emit the alert on the first event that brings
        // the prefix AT OR ABOVE threshold; subsequent events in the
        // same burst are silent until the window goes empty.
        if state.timestamps.len() >= self.threshold && !state.alerted {
            state.alerted = true;
            return Some(key);
        }
        None
    }

    /// Diagnostic accessor: how many distinct prefixes the detector
    /// is currently tracking. Useful for metrics.
    #[must_use]
    pub fn tracked(&self) -> usize {
        self.events.lock().map(|e| e.len()).unwrap_or(0)
    }

    /// Diagnostic accessor: total times an INSERT was refused
    /// because the per-detector `max_prefixes` cap was hit. Indicates
    /// memory pressure (legitimate ops needs to bump the cap) OR an
    /// ongoing IP-sweep attack (operator should bring the rate-
    /// limiter in).
    #[must_use]
    pub fn dropped_prefix_inserts(&self) -> u64 {
        self.dropped_prefix_inserts
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn below_threshold_never_fires() {
        let det = ProbeAnomalyDetector::new(Duration::from_secs(60), 5, 1024);
        let now = Instant::now();
        for i in 0..4 {
            assert!(
                det.record_at(ip4(1, 2, 3, 4), now + Duration::from_millis(i * 10))
                    .is_none(),
                "fired below threshold at i={i}"
            );
        }
    }

    #[test]
    fn at_threshold_fires_exactly_once_per_burst() {
        let det = ProbeAnomalyDetector::new(Duration::from_secs(60), 3, 1024);
        let now = Instant::now();
        // 1st, 2nd events: below threshold.
        assert!(det.record_at(ip4(10, 0, 0, 1), now).is_none());
        assert!(det
            .record_at(ip4(10, 0, 0, 1), now + Duration::from_millis(10))
            .is_none());
        // 3rd event: at threshold — fires.
        let fired = det.record_at(ip4(10, 0, 0, 1), now + Duration::from_millis(20));
        assert!(fired.is_some());
        let key = fired.unwrap();
        // /24 of 10.0.0.x = [10, 0, 0, 0, 0, 0]
        assert_eq!(&key[..3], &[10, 0, 0]);
        // 4th+ events: silent (fire-once).
        assert!(det
            .record_at(ip4(10, 0, 0, 1), now + Duration::from_millis(30))
            .is_none());
        assert!(det
            .record_at(ip4(10, 0, 0, 1), now + Duration::from_millis(40))
            .is_none());
    }

    #[test]
    fn slash24_collapses_within_same_network() {
        // 198.51.100.{1, 42, 200} all share the same /24 and so
        // contribute to one bucket. Threshold = 3 means three
        // probes from any combination of those IPs trips the alarm.
        let det = ProbeAnomalyDetector::new(Duration::from_secs(60), 3, 1024);
        let now = Instant::now();
        assert!(det.record_at(ip4(198, 51, 100, 1), now).is_none());
        assert!(det
            .record_at(ip4(198, 51, 100, 42), now + Duration::from_millis(10))
            .is_none());
        let fired = det.record_at(ip4(198, 51, 100, 200), now + Duration::from_millis(20));
        assert!(
            fired.is_some(),
            "/24 collapse failed — 3 probes from same /24 didn't fire"
        );
    }

    #[test]
    fn different_slash24s_count_independently() {
        let det = ProbeAnomalyDetector::new(Duration::from_secs(60), 3, 1024);
        let now = Instant::now();
        // 3 probes from 10.0.0.x → fires
        assert!(det.record_at(ip4(10, 0, 0, 1), now).is_none());
        assert!(det
            .record_at(ip4(10, 0, 0, 2), now + Duration::from_millis(1))
            .is_none());
        let fire_a = det.record_at(ip4(10, 0, 0, 3), now + Duration::from_millis(2));
        assert!(fire_a.is_some());
        // 3 probes from 10.0.1.x → fires INDEPENDENTLY (different /24)
        assert!(det
            .record_at(ip4(10, 0, 1, 1), now + Duration::from_millis(3))
            .is_none());
        assert!(det
            .record_at(ip4(10, 0, 1, 2), now + Duration::from_millis(4))
            .is_none());
        let fire_b = det.record_at(ip4(10, 0, 1, 3), now + Duration::from_millis(5));
        assert!(fire_b.is_some());
        assert_ne!(fire_a, fire_b, "different /24s must give different keys");
    }

    #[test]
    fn window_expires_resets_burst() {
        let det = ProbeAnomalyDetector::new(Duration::from_secs(1), 3, 1024);
        let now = Instant::now();
        // 3 probes within 1s → fires
        assert!(det.record_at(ip4(203, 0, 113, 1), now).is_none());
        assert!(det
            .record_at(ip4(203, 0, 113, 1), now + Duration::from_millis(10))
            .is_none());
        assert!(det
            .record_at(ip4(203, 0, 113, 1), now + Duration::from_millis(20))
            .is_some());
        // 2 more in the same burst — silent
        assert!(det
            .record_at(ip4(203, 0, 113, 1), now + Duration::from_millis(30))
            .is_none());
        // Past the window — new burst should re-arm.
        let later = now + Duration::from_secs(5);
        assert!(det.record_at(ip4(203, 0, 113, 1), later).is_none());
        assert!(det
            .record_at(ip4(203, 0, 113, 1), later + Duration::from_millis(10))
            .is_none());
        assert!(
            det.record_at(ip4(203, 0, 113, 1), later + Duration::from_millis(20))
                .is_some(),
            "second burst (after window expiry) failed to re-fire"
        );
    }

    #[test]
    fn max_prefixes_cap_refuses_new_inserts_but_keeps_existing() {
        let det = ProbeAnomalyDetector::new(Duration::from_secs(60), 3, 4);
        let now = Instant::now();
        // Fill the cap with 4 distinct /24s — each gets one timestamp.
        for i in 0..4u8 {
            det.record_at(ip4(10, 0, i, 1), now);
        }
        assert_eq!(det.tracked(), 4);
        // A new /24 attempt is refused (cap of 4 already full).
        assert!(det
            .record_at(ip4(10, 0, 99, 1), now + Duration::from_millis(1))
            .is_none());
        assert_eq!(det.dropped_prefix_inserts(), 1);

        // Existing /24 inserts continue to work. The 10.0.0.0/24
        // bucket already has 1 timestamp from the fill loop above
        // (at `now`). Adding one more pushes count to 2 (below
        // threshold = 3) — still None. Adding another pushes count
        // to 3 (at threshold) — must fire.
        let pre = det.tracked();
        assert!(det
            .record_at(ip4(10, 0, 0, 1), now + Duration::from_millis(2))
            .is_none());
        let fired = det.record_at(ip4(10, 0, 0, 1), now + Duration::from_millis(3));
        assert!(
            fired.is_some(),
            "max_prefixes cap should not block existing-prefix records: \
             10.0.0.0/24 had 1 timestamp from fill loop + 2 more = 3 (at threshold)"
        );
        assert_eq!(det.tracked(), pre);
    }

    #[test]
    fn ipv6_prefix_key_uses_slash48() {
        let p1: IpAddr = "2001:db8:cafe::1".parse().unwrap();
        let p2: IpAddr = "2001:db8:cafe:beef::99".parse().unwrap();
        let p3: IpAddr = "2001:db8:dead::1".parse().unwrap();
        assert_eq!(
            ProbeAnomalyDetector::prefix_key(p1),
            ProbeAnomalyDetector::prefix_key(p2),
            "v6 /48 collapse failed — same /48 produced different keys"
        );
        assert_ne!(
            ProbeAnomalyDetector::prefix_key(p1),
            ProbeAnomalyDetector::prefix_key(p3),
            "v6 different /48 should produce different keys"
        );
    }

    #[test]
    fn defaults_are_sensible() {
        // Spec assertion: change requires explicit operator-impact
        // discussion in the commit message.
        assert_eq!(DEFAULT_WINDOW, Duration::from_secs(300));
        assert_eq!(DEFAULT_THRESHOLD, 8);
        assert_eq!(DEFAULT_MAX_PREFIXES, 16 * 1024);
        let det = ProbeAnomalyDetector::with_defaults();
        assert_eq!(det.tracked(), 0);
    }
}
