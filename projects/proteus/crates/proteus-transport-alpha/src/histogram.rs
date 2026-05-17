//! Bounded-bucket Prometheus-compatible histogram for latency
//! tracking on the hot path.
//!
//! ## Why this exists
//!
//! Aggregate counters tell operators "how many handshakes
//! happened" but not "is any user experiencing degraded
//! latency". A handshake p99 creeping from 50ms to 500ms is the
//! leading indicator of nearly every production problem:
//!
//!   - CPU contention from a noisy neighbour on the VPS.
//!   - GC / RT pauses from a runtime regression.
//!   - Network jitter on the loopback (unlikely but real on
//!     congested cloud hosts).
//!   - ML-KEM keygen suddenly 10x slower after a dep upgrade.
//!   - Kernel scheduler issues under high concurrency.
//!
//! Operators dashboard `histogram_quantile(0.99, rate(...))` to
//! catch these BEFORE users complain. Without histograms, they
//! discover latency regressions only via support tickets.
//!
//! ## Design
//!
//! Lock-free additive histogram backed by an array of
//! `AtomicU64` counters — one per bucket boundary + one for the
//! `+Inf` bucket. Each `observe(d)` call walks the boundary
//! array once and bumps the appropriate cumulative bucket; this
//! is a tight loop of `Ordering::Relaxed` atomic adds, fine for
//! the hot path (handshake completion rate caps at a few thousand
//! per second on any production hardware, well below atomic-
//! contention regimes).
//!
//! The bucket boundaries are the Prometheus client library
//! default for seconds-scaled latency: `[0.005, 0.01, 0.025,
//! 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]`. Covers the
//! "fast loopback handshake" (sub-10ms) through "degraded
//! handshake" (multi-second) range that operators care about.
//! Operators who need a different range can build the same
//! shape with `Histogram::with_boundaries` (future API; today
//! the default is fine for every shipped surface).
//!
//! ## Prometheus exposition
//!
//! Produces the canonical histogram shape:
//!
//! ```text
//! proteus_<name>_bucket{le="0.005"} 0
//! proteus_<name>_bucket{le="0.01"} 12
//! proteus_<name>_bucket{le="0.025"} 47
//! …
//! proteus_<name>_bucket{le="+Inf"} 50
//! proteus_<name>_sum 1.234
//! proteus_<name>_count 50
//! ```
//!
//! Bucket counts are CUMULATIVE per Prometheus convention —
//! `bucket{le="0.025"}` includes everything observed at ≤0.025s.
//! The `+Inf` bucket equals `count`. Operators query via
//! `histogram_quantile(0.99, rate(proteus_<name>_bucket[5m]))`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Default Prometheus-client bucket boundaries (seconds). Eleven
/// buckets covering 5ms to 10s. Matches the upstream client
/// library defaults so operators' existing dashboards work
/// unchanged.
pub const DEFAULT_BUCKETS_SECS: [f64; 11] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Bounded-bucket histogram. `buckets[i]` accumulates the count
/// of observations whose value falls in bucket `i` (cumulative
/// per Prometheus convention — `buckets[i]` is the count
/// `<= boundaries[i]`). `inf_bucket` holds the total count.
///
/// `sum_micros` is the cumulative sum in microseconds (chosen
/// over a float so the atomic operations stay lock-free and
/// integer-deterministic; the Prometheus exposition divides by
/// 1_000_000 to render as seconds).
#[derive(Debug)]
pub struct LatencyHistogram {
    name: &'static str,
    help: &'static str,
    boundaries: &'static [f64],
    /// One AtomicU64 per boundary; cumulative count
    /// `<= boundaries[i]`. Length = boundaries.len().
    buckets: Vec<AtomicU64>,
    /// `+Inf` bucket = total count.
    inf_bucket: AtomicU64,
    /// Cumulative observed value, in microseconds. Sum-of-
    /// seconds renders by dividing this by 1e6.
    sum_micros: AtomicU64,
}

impl LatencyHistogram {
    /// Build a histogram with the Prometheus default boundaries.
    #[must_use]
    pub fn new(name: &'static str, help: &'static str) -> Self {
        Self::with_boundaries(name, help, &DEFAULT_BUCKETS_SECS)
    }

    /// Build with operator-chosen boundaries. Boundaries MUST be
    /// strictly ascending; debug assertion enforces this.
    #[must_use]
    pub fn with_boundaries(
        name: &'static str,
        help: &'static str,
        boundaries: &'static [f64],
    ) -> Self {
        debug_assert!(
            boundaries.windows(2).all(|w| w[0] < w[1]),
            "histogram boundaries must be strictly ascending"
        );
        let buckets = (0..boundaries.len()).map(|_| AtomicU64::new(0)).collect();
        Self {
            name,
            help,
            boundaries,
            buckets,
            inf_bucket: AtomicU64::new(0),
            sum_micros: AtomicU64::new(0),
        }
    }

    /// Record one observation. `duration` is the measured value;
    /// the histogram converts to seconds internally for the
    /// bucket walk, but stores the sum in microseconds for the
    /// reasons in the struct docstring.
    pub fn observe(&self, duration: Duration) {
        let secs = duration.as_secs_f64();
        let micros = duration.as_micros();
        // Cast to u64 with saturating clamp — durations larger
        // than ~584000 years are impossible in any production
        // setting but the saturating cast keeps the code
        // panic-free for the worst case.
        let micros_u64 = u64::try_from(micros).unwrap_or(u64::MAX);
        self.sum_micros.fetch_add(micros_u64, Ordering::Relaxed);
        self.inf_bucket.fetch_add(1, Ordering::Relaxed);
        // Cumulative bucket walk: bump EVERY bucket whose
        // boundary is `>= secs`. Prometheus convention is
        // cumulative (le="0.025" includes everything ≤25ms),
        // so the bucket walk is monotonic.
        for (i, &boundary) in self.boundaries.iter().enumerate() {
            if secs <= boundary {
                self.buckets[i].fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Convenience: observe a `Duration` measured by computing
    /// `Instant::elapsed()` at the call site.
    pub fn observe_secs(&self, secs: f64) {
        let micros = (secs * 1_000_000.0) as u64;
        let duration = Duration::from_micros(micros);
        self.observe(duration);
    }

    /// Cumulative count of observations (= `+Inf` bucket value).
    #[must_use]
    pub fn count(&self) -> u64 {
        self.inf_bucket.load(Ordering::Relaxed)
    }

    /// Cumulative sum of observed values, in seconds. Computed
    /// by dividing the internal microsecond sum by 1e6.
    #[must_use]
    pub fn sum_seconds(&self) -> f64 {
        self.sum_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0
    }

    /// Snapshot per-bucket counts (one entry per boundary) plus
    /// the `+Inf` bucket. Used by the Prometheus renderer + by
    /// tests asserting bucket-walk behavior.
    #[must_use]
    pub fn snapshot(&self) -> Vec<(f64, u64)> {
        let mut out: Vec<(f64, u64)> = self
            .boundaries
            .iter()
            .enumerate()
            .map(|(i, &b)| (b, self.buckets[i].load(Ordering::Relaxed)))
            .collect();
        // +Inf bucket has no finite boundary; the renderer
        // treats it specially. We surface it as f64::INFINITY
        // in the snapshot so callers can distinguish.
        out.push((f64::INFINITY, self.inf_bucket.load(Ordering::Relaxed)));
        out
    }

    /// Compute an approximate quantile (e.g. p99 = 0.99) from
    /// the current bucket counts. Returns the boundary at which
    /// the cumulative count first crosses `q × total`. Useful
    /// for `/diagnose` rendering without forcing operators to
    /// query Prometheus.
    ///
    /// Edge cases:
    ///   - empty histogram → returns 0.0.
    ///   - q outside `[0, 1]` → clamped.
    ///   - quantile lands in the `+Inf` bucket → returns the
    ///     largest finite boundary (operators should INFER
    ///     "above the largest bucket" from the rendered text).
    #[must_use]
    pub fn quantile(&self, q: f64) -> f64 {
        let total = self.count();
        if total == 0 {
            return 0.0;
        }
        let q = q.clamp(0.0, 1.0);
        let target = ((total as f64) * q).ceil() as u64;
        for (i, &boundary) in self.boundaries.iter().enumerate() {
            if self.buckets[i].load(Ordering::Relaxed) >= target {
                return boundary;
            }
        }
        // Quantile lands beyond the largest finite bucket;
        // return the last boundary as the floor.
        self.boundaries.last().copied().unwrap_or(0.0)
    }

    /// Render the canonical Prometheus histogram exposition for
    /// this metric. `name` and `help` come from the histogram's
    /// own fields; the renderer prepends the `proteus_` prefix.
    #[must_use]
    pub fn prometheus(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(512);
        let _ = writeln!(s, "# HELP proteus_{} {}", self.name, self.help);
        let _ = writeln!(s, "# TYPE proteus_{} histogram", self.name);
        for (i, &boundary) in self.boundaries.iter().enumerate() {
            let count = self.buckets[i].load(Ordering::Relaxed);
            let _ = writeln!(
                s,
                "proteus_{}_bucket{{le=\"{}\"}} {count}",
                self.name,
                format_le(boundary)
            );
        }
        let _ = writeln!(
            s,
            "proteus_{}_bucket{{le=\"+Inf\"}} {}",
            self.name,
            self.inf_bucket.load(Ordering::Relaxed)
        );
        // _sum and _count are the canonical aggregate footer.
        let _ = writeln!(s, "proteus_{}_sum {}", self.name, self.sum_seconds());
        let _ = writeln!(s, "proteus_{}_count {}", self.name, self.count());
        s
    }
}

/// Format a bucket boundary as a Prometheus `le=` label value.
/// Strips trailing `.0` (Prometheus convention: `5` not `5.0`),
/// but keeps fractional values like `0.025` verbatim.
fn format_le(b: f64) -> String {
    if b == b.trunc() && b.abs() < 1e9 {
        format!("{}", b as i64)
    } else {
        // Use a short f64 formatter that drops trailing zeros
        // without emitting scientific notation for the ranges
        // we care about (microseconds through 10 seconds).
        let raw = format!("{b}");
        raw
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_histogram_has_zero_count_and_sum() {
        let h = LatencyHistogram::new("test_empty", "test");
        assert_eq!(h.count(), 0);
        assert_eq!(h.sum_seconds(), 0.0);
        assert_eq!(h.quantile(0.99), 0.0);
    }

    #[test]
    fn observe_bumps_count_and_sum() {
        let h = LatencyHistogram::new("test_basic", "test");
        h.observe(Duration::from_millis(15));
        h.observe(Duration::from_millis(30));
        assert_eq!(h.count(), 2);
        // 15ms + 30ms = 0.045s; tolerate fp slop.
        assert!((h.sum_seconds() - 0.045).abs() < 1e-6);
    }

    #[test]
    fn buckets_are_cumulative_per_prometheus_convention() {
        let h = LatencyHistogram::new("test_cumul", "test");
        // 7ms → buckets ≥ 0.01 (10ms) all bump.
        h.observe(Duration::from_millis(7));
        // 60ms → buckets ≥ 0.1 all bump.
        h.observe(Duration::from_millis(60));
        // 800ms → buckets ≥ 1.0 all bump.
        h.observe(Duration::from_millis(800));
        let snap = h.snapshot();
        // boundary 0.005 (5ms) — 0 observations land at or below.
        assert_eq!(snap[0].1, 0, "5ms bucket: {:?}", snap[0]);
        // boundary 0.01 (10ms) — 1 observation (the 7ms one).
        assert_eq!(snap[1].1, 1, "10ms bucket: {:?}", snap[1]);
        // boundary 0.05 (50ms) — still 1.
        assert_eq!(snap[3].1, 1, "50ms bucket: {:?}", snap[3]);
        // boundary 0.1 (100ms) — now 2 (7ms + 60ms).
        assert_eq!(snap[4].1, 2, "100ms bucket: {:?}", snap[4]);
        // boundary 1.0 (1s) — all 3 (7ms + 60ms + 800ms).
        assert_eq!(snap[7].1, 3, "1s bucket: {:?}", snap[7]);
        // +Inf — 3.
        assert_eq!(snap.last().unwrap().1, 3);
    }

    #[test]
    fn quantile_returns_boundary_at_cumulative_target() {
        let h = LatencyHistogram::new("test_quantile", "test");
        // 10 observations: 5 at 7ms (bucket le=0.01) + 5 at
        // 200ms (bucket le=0.25). p50 → boundary 0.01;
        // p95 → boundary 0.25.
        for _ in 0..5 {
            h.observe(Duration::from_millis(7));
        }
        for _ in 0..5 {
            h.observe(Duration::from_millis(200));
        }
        // p50 = 5th observation = 7ms ≤ 0.01.
        let p50 = h.quantile(0.5);
        assert!((p50 - 0.01).abs() < 1e-9, "p50 expected 0.01, got {p50}");
        // p95 = 10th obs → 200ms ≤ 0.25.
        let p95 = h.quantile(0.95);
        assert!((p95 - 0.25).abs() < 1e-9, "p95 expected 0.25, got {p95}");
    }

    #[test]
    fn quantile_returns_zero_for_empty_histogram() {
        let h = LatencyHistogram::new("test_q_empty", "test");
        assert_eq!(h.quantile(0.99), 0.0);
        assert_eq!(h.quantile(0.0), 0.0);
        assert_eq!(h.quantile(1.0), 0.0);
    }

    #[test]
    fn quantile_clamps_out_of_range_inputs() {
        let h = LatencyHistogram::new("test_q_clamp", "test");
        h.observe(Duration::from_millis(5));
        h.observe(Duration::from_millis(50));
        // q < 0 → treat as 0 → first non-zero bucket.
        let q_neg = h.quantile(-0.5);
        assert!(q_neg > 0.0);
        // q > 1 → treat as 1 → last bucket reached.
        let q_over = h.quantile(2.0);
        assert!(q_over > 0.0);
    }

    #[test]
    fn observation_above_all_buckets_only_bumps_inf() {
        let h = LatencyHistogram::new("test_overflow", "test");
        // 30s observation — exceeds the 10s top boundary.
        h.observe(Duration::from_secs(30));
        let snap = h.snapshot();
        // Every finite bucket should be 0.
        for &(_, count) in &snap[..snap.len() - 1] {
            assert_eq!(count, 0);
        }
        // +Inf = 1.
        assert_eq!(snap.last().unwrap().1, 1);
        assert_eq!(h.count(), 1);
    }

    #[test]
    fn observation_at_boundary_lands_in_that_bucket() {
        // Observe exactly 0.01s — should bump the 0.01 bucket
        // (Prometheus convention is le=less-than-or-equal).
        let h = LatencyHistogram::new("test_boundary", "test");
        h.observe(Duration::from_millis(10));
        let snap = h.snapshot();
        // 0.005 bucket: 0 (10ms > 5ms).
        assert_eq!(snap[0].1, 0);
        // 0.01 bucket: 1 (10ms <= 10ms).
        assert_eq!(snap[1].1, 1);
    }

    #[test]
    fn prometheus_emits_canonical_histogram_shape() {
        let h = LatencyHistogram::new("test_prom", "Test histogram");
        h.observe(Duration::from_millis(15));
        h.observe(Duration::from_millis(150));
        let s = h.prometheus();
        assert!(s.contains("# HELP proteus_test_prom"));
        assert!(s.contains("# TYPE proteus_test_prom histogram"));
        // Verify a few sample bucket lines.
        assert!(
            s.contains(r#"proteus_test_prom_bucket{le="0.005"} 0"#),
            "{s}"
        );
        // 15ms observation lands in bucket le=0.025; cumulative
        // count should be 1 at that boundary.
        assert!(
            s.contains(r#"proteus_test_prom_bucket{le="0.025"} 1"#),
            "{s}"
        );
        // 15ms + 150ms = 2 observations ≤ 0.25.
        assert!(
            s.contains(r#"proteus_test_prom_bucket{le="0.25"} 2"#),
            "{s}"
        );
        assert!(s.contains(r#"proteus_test_prom_bucket{le="+Inf"} 2"#));
        assert!(s.contains("proteus_test_prom_sum 0.165"));
        assert!(s.contains("proteus_test_prom_count 2"));
    }

    #[test]
    fn prometheus_le_label_strips_trailing_zero_for_integers() {
        let h = LatencyHistogram::new("test_le", "test");
        let s = h.prometheus();
        // Integer-valued boundaries render as `1` not `1.0`,
        // `5` not `5.0`, etc. (matches Prometheus client style.)
        assert!(s.contains(r#"le="1""#), "{s}");
        assert!(s.contains(r#"le="5""#), "{s}");
        assert!(s.contains(r#"le="10""#), "{s}");
        // Fractional boundaries keep their decimal point.
        assert!(s.contains(r#"le="0.005""#));
        assert!(s.contains(r#"le="0.025""#));
        assert!(s.contains(r#"le="2.5""#));
    }

    #[test]
    fn concurrent_observe_keeps_invariants() {
        use std::sync::Arc;
        let h = Arc::new(LatencyHistogram::new("test_concur", "test"));
        let mut handles = Vec::new();
        for _ in 0..16 {
            let h = Arc::clone(&h);
            handles.push(std::thread::spawn(move || {
                for _ in 0..100 {
                    h.observe(Duration::from_millis(20));
                }
            }));
        }
        for x in handles {
            x.join().unwrap();
        }
        assert_eq!(h.count(), 16 * 100);
        // 20ms × 1600 = 32s. Tolerate fp slop.
        assert!((h.sum_seconds() - 32.0).abs() < 1e-3);
        // 20ms falls in the le=0.025 bucket — all 1600
        // observations should be there cumulatively.
        let snap = h.snapshot();
        // le=0.025 is index 2.
        assert_eq!(snap[2].1, 1600);
    }

    #[test]
    fn observe_secs_helper_is_equivalent_to_observe_duration() {
        let h1 = LatencyHistogram::new("h1", "test");
        let h2 = LatencyHistogram::new("h2", "test");
        h1.observe(Duration::from_millis(42));
        h2.observe_secs(0.042);
        assert_eq!(h1.count(), h2.count());
        // Sum slop is OK because of fp→u64 conversion; difference
        // should be well under a microsecond.
        let delta = (h1.sum_seconds() - h2.sum_seconds()).abs();
        assert!(delta < 1e-6, "delta {delta}");
    }

    #[test]
    fn custom_boundaries_are_honored() {
        const C: [f64; 3] = [0.1, 1.0, 10.0];
        let h = LatencyHistogram::with_boundaries("custom", "test", &C);
        h.observe(Duration::from_millis(50));
        h.observe(Duration::from_secs(5));
        let snap = h.snapshot();
        assert_eq!(snap.len(), 4); // 3 finite + +Inf
        assert_eq!(snap[0].1, 1); // 50ms ≤ 0.1
        assert_eq!(snap[1].1, 1); // still 1 (5s > 1.0)
        assert_eq!(snap[2].1, 2); // both observations ≤ 10
        assert_eq!(snap[3].1, 2); // +Inf = total
    }
}
