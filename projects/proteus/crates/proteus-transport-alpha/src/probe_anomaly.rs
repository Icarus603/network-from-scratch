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
    /// Bounded ring buffer of the most recent N anomaly fires.
    /// Operators consult this via `proteus-server admin status` (or
    /// the `proteus_probe_anomaly_recent_*` Prometheus gauges) to
    /// identify exactly which /24 (v4) / /48 (v6) prefixes are
    /// currently tripping the detector — the most operationally
    /// critical question ("WHICH IP do I blackhole-route?") that the
    /// raw counter `probe_anomalies_fired_total` cannot answer on
    /// its own.
    ///
    /// Bounded so the buffer can't grow without bound under
    /// continuous attacks; the cap matches `DEFAULT_RECENT_FIRES_CAP`.
    /// Locked with a separate mutex from `events` so the hot path
    /// (record_at) doesn't contend with the warm path (Prometheus
    /// scrape) any more than necessary.
    recent_fires: Mutex<VecDeque<RecentFire>>,
    recent_fires_cap: usize,
}

/// One row in the recent-fires ring buffer. Cheap to clone, suitable
/// for read-side accessor surfaces (Prometheus exporter, admin CLI).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecentFire {
    pub prefix: PrefixKey,
    pub family: IpFamily,
    pub fired_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpFamily {
    V4,
    V6,
}

impl RecentFire {
    /// Render the prefix in the conventional `a.b.c.0/24` or
    /// `a:b:c::/48` form for human-readable output (admin CLI,
    /// Prometheus label values, log lines).
    #[must_use]
    pub fn prefix_string(&self) -> String {
        match self.family {
            IpFamily::V4 => format!(
                "{}.{}.{}.0/24",
                self.prefix[0], self.prefix[1], self.prefix[2]
            ),
            IpFamily::V6 => {
                // /48 = first 3 hextets; the rest is all-zero.
                let h0 = u16::from_be_bytes([self.prefix[0], self.prefix[1]]);
                let h1 = u16::from_be_bytes([self.prefix[2], self.prefix[3]]);
                let h2 = u16::from_be_bytes([self.prefix[4], self.prefix[5]]);
                format!("{h0:x}:{h1:x}:{h2:x}::/48")
            }
        }
    }
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

/// Default cap on the recent-fires ring buffer (64 entries × ~32
/// bytes each ≈ 2 KiB). 64 is enough that an operator paging
/// through `proteus-server admin status` sees the active offenders
/// even during a multi-/24 attack burst, without unbounded
/// memory growth under sustained sieve probing.
pub const DEFAULT_RECENT_FIRES_CAP: usize = 64;

impl ProbeAnomalyDetector {
    /// Build a detector with the supplied sliding-window length +
    /// threshold + bookkeeping cap. The recent-fires ring buffer
    /// uses [`DEFAULT_RECENT_FIRES_CAP`]; operators who need a larger
    /// buffer (very busy servers) can use `new_with_recent_cap`.
    #[must_use]
    pub fn new(window: Duration, threshold: usize, max_prefixes: usize) -> Self {
        Self::new_with_recent_cap(window, threshold, max_prefixes, DEFAULT_RECENT_FIRES_CAP)
    }

    /// Build a detector with an explicit recent-fires ring buffer cap.
    #[must_use]
    pub fn new_with_recent_cap(
        window: Duration,
        threshold: usize,
        max_prefixes: usize,
        recent_fires_cap: usize,
    ) -> Self {
        Self {
            window,
            threshold,
            events: Mutex::new(HashMap::new()),
            max_prefixes,
            dropped_prefix_inserts: std::sync::atomic::AtomicU64::new(0),
            recent_fires: Mutex::new(VecDeque::with_capacity(recent_fires_cap.max(1))),
            recent_fires_cap: recent_fires_cap.max(1),
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
            // Drop the per-prefix events lock BEFORE acquiring the
            // recent-fires lock so the two never sit contended at
            // the same time. The lock-order discipline is one-way:
            // events → recent_fires, never the reverse.
            let family = match ip {
                IpAddr::V4(_) => IpFamily::V4,
                IpAddr::V6(_) => IpFamily::V6,
            };
            let fire = RecentFire {
                prefix: key,
                family,
                fired_at: now,
            };
            drop(events);
            self.push_recent_fire(fire);
            return Some(key);
        }
        None
    }

    /// Append `fire` to the ring buffer, evicting the oldest entry
    /// when the cap is reached.
    fn push_recent_fire(&self, fire: RecentFire) {
        let mut ring = self
            .recent_fires
            .lock()
            .expect("ProbeAnomalyDetector recent_fires mutex poisoned");
        if ring.len() >= self.recent_fires_cap {
            ring.pop_front();
        }
        ring.push_back(fire);
    }

    /// Snapshot the recent-fires ring buffer, oldest-first.
    /// Operationally exposed via `proteus-server admin status` JSON
    /// and the Prometheus `proteus_probe_anomaly_recent_*` lines so
    /// the operator can identify exactly which /24 prefixes are
    /// currently tripping the detector (the "WHICH IP do I
    /// blackhole-route?" question the bare counter can't answer).
    #[must_use]
    pub fn recent_fires(&self) -> Vec<RecentFire> {
        self.recent_fires
            .lock()
            .map(|r| r.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Render a Prometheus exposition snippet for the detector's
    /// own gauges + the recent-fires ring (as a labelled gauge
    /// per recent prefix, value = seconds since fire). The
    /// `proteus_probe_anomalies_fired_total` counter is exposed by
    /// `ServerMetrics::prometheus()` separately; this snippet adds
    /// the diagnostic surfaces the counter alone doesn't carry.
    ///
    /// Designed to be appended to `ServerMetrics::prometheus()`
    /// output by the HTTP handler when a detector is configured.
    #[must_use]
    pub fn prometheus_extension(&self, now: Instant) -> String {
        let tracked = self.tracked();
        let dropped = self.dropped_prefix_inserts();
        let mut out = String::with_capacity(512);
        out.push_str(
            "# HELP proteus_probe_anomaly_tracked_prefixes Number of distinct /24 (v4) / /48 (v6) prefixes currently in the detector's sliding window.\n",
        );
        out.push_str("# TYPE proteus_probe_anomaly_tracked_prefixes gauge\n");
        out.push_str(&format!(
            "proteus_probe_anomaly_tracked_prefixes {tracked}\n"
        ));
        out.push_str(
            "# HELP proteus_probe_anomaly_dropped_inserts_total Times the detector refused to track a new prefix because max_prefixes was reached (IP-sweep defense).\n",
        );
        out.push_str("# TYPE proteus_probe_anomaly_dropped_inserts_total counter\n");
        out.push_str(&format!(
            "proteus_probe_anomaly_dropped_inserts_total {dropped}\n"
        ));
        // Recent fires: one gauge line per entry, value = seconds
        // since fire (operator can sort/topk in PromQL).
        let fires = self.recent_fires();
        out.push_str(
            "# HELP proteus_probe_anomaly_recent_secs Seconds since the most recent anomaly fire for this prefix. One line per prefix in the bounded ring buffer.\n",
        );
        out.push_str("# TYPE proteus_probe_anomaly_recent_secs gauge\n");
        for fire in &fires {
            let secs_ago = now
                .checked_duration_since(fire.fired_at)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            // Sanitize prefix string for Prometheus label values:
            // colons in v6 are fine; `"` and `\` would need escaping
            // but our format produces neither.
            out.push_str(&format!(
                "proteus_probe_anomaly_recent_secs{{prefix=\"{}\"}} {}\n",
                fire.prefix_string(),
                secs_ago,
            ));
        }
        out
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
        assert_eq!(DEFAULT_RECENT_FIRES_CAP, 64);
        let det = ProbeAnomalyDetector::with_defaults();
        assert_eq!(det.tracked(), 0);
        assert!(det.recent_fires().is_empty());
    }

    // ---------- recent-fires ring + Prometheus extension ----------

    #[test]
    fn recent_fires_starts_empty_records_on_burst() {
        let det = ProbeAnomalyDetector::new(Duration::from_secs(60), 3, 1024);
        assert!(det.recent_fires().is_empty());
        let t = Instant::now();
        // 2 below threshold — no fire, no recent-fires entry.
        det.record_at(ip4(198, 51, 100, 1), t);
        det.record_at(ip4(198, 51, 100, 2), t);
        assert!(det.recent_fires().is_empty());
        // 3rd at threshold — fires AND appears in the ring.
        let fired = det.record_at(ip4(198, 51, 100, 3), t);
        assert!(fired.is_some());
        let recent = det.recent_fires();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].family, IpFamily::V4);
        assert_eq!(&recent[0].prefix[..3], &[198, 51, 100]);
        assert_eq!(recent[0].prefix_string(), "198.51.100.0/24");
    }

    #[test]
    fn recent_fires_fire_once_per_burst_does_not_duplicate_in_ring() {
        let det = ProbeAnomalyDetector::new(Duration::from_secs(60), 2, 1024);
        let t = Instant::now();
        det.record_at(ip4(10, 0, 0, 1), t);
        det.record_at(ip4(10, 0, 0, 1), t);
        // Several more in the same burst should be silent — the ring
        // must NOT receive duplicate entries even though we're
        // calling record_at repeatedly.
        for i in 0..10 {
            det.record_at(ip4(10, 0, 0, 1), t + Duration::from_millis(i));
        }
        assert_eq!(
            det.recent_fires().len(),
            1,
            "ring buffer recorded duplicate fires within the same burst",
        );
    }

    #[test]
    fn recent_fires_ring_caps_at_configured_size_evicting_oldest() {
        // Cap ring at 3 so we can verify FIFO eviction behavior with
        // a small number of /24s.
        let det = ProbeAnomalyDetector::new_with_recent_cap(
            Duration::from_secs(60),
            2,
            1024,
            3, // recent_fires_cap = 3
        );
        let t0 = Instant::now();
        for net_idx in 0..5u8 {
            // 2 events per /24 → each fires once.
            det.record_at(ip4(10, 0, net_idx, 1), t0);
            det.record_at(ip4(10, 0, net_idx, 2), t0);
        }
        let recent = det.recent_fires();
        assert_eq!(recent.len(), 3, "cap of 3 not honored");
        // FIFO: oldest evicted — only nets 2, 3, 4 should remain.
        assert_eq!(recent[0].prefix[2], 2);
        assert_eq!(recent[1].prefix[2], 3);
        assert_eq!(recent[2].prefix[2], 4);
    }

    #[test]
    fn recent_fires_ring_records_ipv6_with_slash48_rendering() {
        let det = ProbeAnomalyDetector::new(Duration::from_secs(60), 2, 1024);
        let t = Instant::now();
        let p1: IpAddr = "2001:db8:cafe::1".parse().unwrap();
        let p2: IpAddr = "2001:db8:cafe::2".parse().unwrap();
        det.record_at(p1, t);
        det.record_at(p2, t);
        let recent = det.recent_fires();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].family, IpFamily::V6);
        assert_eq!(recent[0].prefix_string(), "2001:db8:cafe::/48");
    }

    #[test]
    fn prometheus_extension_emits_expected_lines() {
        let det = ProbeAnomalyDetector::new(Duration::from_secs(60), 2, 1024);
        let t0 = Instant::now();
        det.record_at(ip4(203, 0, 113, 1), t0);
        det.record_at(ip4(203, 0, 113, 2), t0);
        // 5 seconds later, scrape happens.
        let scrape_at = t0 + Duration::from_secs(5);
        let body = det.prometheus_extension(scrape_at);

        // Gauges and counters must be present with HELP/TYPE rows.
        assert!(body.contains("# HELP proteus_probe_anomaly_tracked_prefixes"));
        assert!(body.contains("# TYPE proteus_probe_anomaly_tracked_prefixes gauge"));
        assert!(body.contains("proteus_probe_anomaly_tracked_prefixes 1"));

        assert!(body.contains("# HELP proteus_probe_anomaly_dropped_inserts_total"));
        assert!(body.contains("# TYPE proteus_probe_anomaly_dropped_inserts_total counter"));
        assert!(body.contains("proteus_probe_anomaly_dropped_inserts_total 0"));

        // Recent-fire row with the prefix label + ~5s elapsed.
        assert!(body.contains("# TYPE proteus_probe_anomaly_recent_secs gauge"));
        assert!(
            body.contains("proteus_probe_anomaly_recent_secs{prefix=\"203.0.113.0/24\"} 5"),
            "expected labelled recent_secs line in:\n{body}"
        );
    }

    #[test]
    fn prometheus_extension_with_no_fires_still_emits_zero_lines() {
        let det = ProbeAnomalyDetector::with_defaults();
        let body = det.prometheus_extension(Instant::now());
        assert!(body.contains("proteus_probe_anomaly_tracked_prefixes 0"));
        assert!(body.contains("proteus_probe_anomaly_dropped_inserts_total 0"));
        // No recent-secs lines should appear (just the HELP/TYPE
        // header which is fine — Prometheus tolerates empty
        // metric families).
        let recent_count = body
            .lines()
            .filter(|l| l.starts_with("proteus_probe_anomaly_recent_secs{"))
            .count();
        assert_eq!(recent_count, 0);
    }
}
