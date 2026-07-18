//! Hysteria2-style **Brutal** congestion controller for Proteus β.
//!
//! ## Why this exists
//!
//! quinn's stock BBR is loss-*tolerant* relative to CUBIC, but still
//! collapses under the 15–30 % loss regimes GFW-class QUIC throttling
//! produces (measured: ~0.4 MiB/s at 30 % synthetic loss on loopback
//! BBR — see `notes/perf/2026-05-19-netem-loss-sweep.jsonl`). That is
//! the exact design point Hysteria2's Brutal controller targets.
//!
//! Brutal's contract (matching Hy2 operator semantics):
//!
//! 1. Operator configures a **target rate** (bits/s) — typically the
//!    paid uplink they measured end-to-end, not auto-detected.
//! 2. Congestion window = `target_bytes_per_sec × RTT × 2 /
//!    ack_rate`, matching Hysteria2's BDP headroom and bounded loss
//!    compensation.
//! 3. **Loss does not shrink the window.** Packet loss is treated as
//!    the network's problem to retransmit around, not a congestion
//!    signal.
//! 4. Pacing rate is `target / ack_rate`, so a path delivering 80 %
//!    of sent bytes can still deliver the operator's requested rate.
//!
//! ## Fairness / safety
//!
//! Brutal is **not** TCP-friendly. It is the right tool only when the
//! operator owns the bottleneck (dedicated VPS uplink) or is fighting
//! an adversarial loss injector that is *not* responding to
//! back-off. Default remains BBR; operators opt in via
//! `beta_congestion: brutal` + `beta_brutal_target_mbps: N`.
//!
//! ## Spec / roadmap
//!
//! Closes the M3 "Brutal-clone CC" headline gap called out in
//! `projects/proteus/README.md` and `notes/perf/README.md`.

use std::any::Any;
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::congestion::{Controller, ControllerFactory, ControllerMetrics};
// RttEstimator is part of the Controller trait signature but not
// re-exported through `quinn`. Pin the same quinn-proto version
// quinn 0.11 depends on.
use quinn_proto::RttEstimator;

/// Default target: 100 Mbit/s. Matches a common mid-tier VPS uplink
/// and is high enough that loopback benches aren't artificially
/// rate-limited by the controller when operators first flip the
/// switch without tuning.
pub const DEFAULT_TARGET_BPS: u64 = 100_000_000;

/// Hard ceiling on the computed window so a pathological RTT spike
/// (e.g. 5 s stall) cannot allocate a multi-GiB in-flight budget.
const MAX_WINDOW_BYTES: u64 = 256 * 1024 * 1024;
const SAMPLE_SLOT_COUNT: usize = 5;
const MIN_SAMPLE_PACKETS: u64 = 50;
const MIN_ACK_RATE: f64 = 0.8;
const WINDOW_MULTIPLIER: f64 = 2.0;
const UNKNOWN_RTT_WINDOW: u64 = 10_240;

/// Configuration for [`Brutal`]. Cheap to clone via `Arc`.
#[derive(Debug, Clone)]
pub struct BrutalConfig {
    /// Target send rate in **bits per second**.
    pub target_bps: u64,
}

impl Default for BrutalConfig {
    fn default() -> Self {
        Self {
            target_bps: DEFAULT_TARGET_BPS,
        }
    }
}

impl BrutalConfig {
    /// Construct from a human-friendly megabit/s number.
    #[must_use]
    pub fn from_mbps(mbps: u64) -> Self {
        Self {
            target_bps: mbps.saturating_mul(1_000_000),
        }
    }

    #[must_use]
    pub fn target_bytes_per_sec(&self) -> u64 {
        // bits → bytes; integer division floors (slightly under target).
        self.target_bps / 8
    }
}

/// Loss-immune, rate-targeted congestion controller.
#[derive(Debug, Clone)]
pub struct Brutal {
    config: Arc<BrutalConfig>,
    current_mtu: u64,
    /// Bytes in flight allowed. Recalculated on every ACK from
    /// `target_bytes_per_sec × RTT`.
    window: u64,
    /// Bytes/s derived once from config (cached for metrics).
    target_bytes_per_sec: u64,
    /// Five one-second delivery samples, mirroring Hysteria2's
    /// rolling loss-compensation window. Quinn's controller API
    /// reports bytes rather than packet arrays, so we accumulate
    /// acknowledged/lost bytes and use `50 × MTU` as the minimum
    /// statistically useful sample.
    sample_start: Instant,
    samples: [DeliverySample; SAMPLE_SLOT_COUNT],
    ack_rate: f64,
}

#[derive(Debug, Clone, Copy, Default)]
struct DeliverySample {
    second: u64,
    initialized: bool,
    acked_bytes: u64,
    lost_bytes: u64,
}

impl Brutal {
    #[must_use]
    pub fn new(config: Arc<BrutalConfig>, current_mtu: u16) -> Self {
        let target_bytes_per_sec = config.target_bytes_per_sec().max(1);
        // Seed window with a 100 ms RTT guess. This is deliberately
        // larger than Hysteria2's 10 KiB unknown-RTT fallback so the
        // first flight can fill a long-haul path before the first ACK.
        let seed_rtt = Duration::from_millis(100);
        let window = bdp_window(target_bytes_per_sec, seed_rtt, current_mtu as u64, 1.0);
        Self {
            config,
            current_mtu: current_mtu as u64,
            window,
            target_bytes_per_sec,
            sample_start: Instant::now(),
            samples: [DeliverySample::default(); SAMPLE_SLOT_COUNT],
            ack_rate: 1.0,
        }
    }

    fn minimum_window(&self) -> u64 {
        UNKNOWN_RTT_WINDOW.max(self.current_mtu)
    }

    fn recompute_window(&mut self, rtt: Duration) {
        self.window = bdp_window(
            self.target_bytes_per_sec,
            rtt,
            self.current_mtu,
            self.ack_rate,
        );
    }

    fn record_delivery(&mut self, now: Instant, acked_bytes: u64, lost_bytes: u64) {
        let second = now.saturating_duration_since(self.sample_start).as_secs();
        let slot = second as usize % SAMPLE_SLOT_COUNT;
        let sample = &mut self.samples[slot];
        if !sample.initialized || sample.second != second {
            *sample = DeliverySample {
                second,
                initialized: true,
                acked_bytes: 0,
                lost_bytes: 0,
            };
        }
        sample.acked_bytes = sample.acked_bytes.saturating_add(acked_bytes);
        sample.lost_bytes = sample.lost_bytes.saturating_add(lost_bytes);
        self.update_ack_rate(second);
    }

    fn update_ack_rate(&mut self, current_second: u64) {
        let oldest = current_second.saturating_sub(SAMPLE_SLOT_COUNT as u64);
        let (acked, lost) = self
            .samples
            .iter()
            .filter(|s| s.initialized && s.second >= oldest)
            .fold((0u64, 0u64), |(acked, lost), s| {
                (
                    acked.saturating_add(s.acked_bytes),
                    lost.saturating_add(s.lost_bytes),
                )
            });
        let total = acked.saturating_add(lost);
        let minimum_sample = MIN_SAMPLE_PACKETS.saturating_mul(self.current_mtu);
        self.ack_rate = if total < minimum_sample {
            1.0
        } else {
            ((acked as f64) / (total as f64)).clamp(MIN_ACK_RATE, 1.0)
        };
    }
}

/// `target_bytes_per_sec × RTT × 2 / ack_rate`, clamped to a safe
/// lower/upper bound. The multiplier and ACK-rate floor match
/// Hysteria2's current Brutal implementation.
fn bdp_window(target_bytes_per_sec: u64, rtt: Duration, mtu: u64, ack_rate: f64) -> u64 {
    // Avoid zero RTT (loopback can report sub-ms); floor at 1 ms so
    // the window doesn't collapse to 2×MTU and stall bulk send.
    let rtt = rtt.max(Duration::from_millis(1));
    let rtt_ns = rtt.as_nanos().max(1);
    // bytes = rate * rtt_secs = rate * rtt_ns / 1e9
    let base = (target_bytes_per_sec as u128).saturating_mul(rtt_ns) / 1_000_000_000u128;
    let compensated = (base as f64 * WINDOW_MULTIPLIER / ack_rate.clamp(MIN_ACK_RATE, 1.0)) as u128;
    let raw = compensated.min(MAX_WINDOW_BYTES as u128) as u64;
    raw.max(UNKNOWN_RTT_WINDOW.max(mtu.max(1)))
}

impl Controller for Brutal {
    fn on_ack(
        &mut self,
        now: Instant,
        _sent: Instant,
        bytes: u64,
        _app_limited: bool,
        rtt: &RttEstimator,
    ) {
        // Always recompute from latest smoothed RTT. We ignore
        // app_limited — Brutal's job is to offer the full BDP budget
        // so the application can fill it when it has data.
        self.record_delivery(now, bytes, 0);
        self.recompute_window(rtt.get());
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        // The whole point of Brutal: **do not shrink on loss**.
        // Loss only feeds the bounded delivery-rate compensation.
        self.record_delivery(now, 0, lost_bytes);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.current_mtu = new_mtu as u64;
        self.window = self.window.max(self.minimum_window());
    }

    fn window(&self) -> u64 {
        self.window
    }

    fn metrics(&self) -> ControllerMetrics {
        // `ControllerMetrics` is `#[non_exhaustive]`; construct it
        // through `Default` so this crate stays source-compatible
        // when quinn-proto adds new optional metrics.
        let mut metrics = ControllerMetrics::default();
        metrics.congestion_window = self.window;
        // bits/s — matches quinn's ControllerMetrics unit.
        metrics.pacing_rate = Some((self.config.target_bps as f64 / self.ack_rate) as u64);
        metrics
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        // Same seed as `new` — 100 ms × rate.
        bdp_window(
            self.target_bytes_per_sec,
            Duration::from_millis(100),
            self.current_mtu,
            1.0,
        )
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

impl ControllerFactory for BrutalConfig {
    fn build(self: Arc<Self>, _now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(Brutal::new(self, current_mtu))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_mbps_converts_correctly() {
        let c = BrutalConfig::from_mbps(100);
        assert_eq!(c.target_bps, 100_000_000);
        assert_eq!(c.target_bytes_per_sec(), 12_500_000);
    }

    #[test]
    fn bdp_window_scales_with_rtt() {
        let rate = 12_500_000; // 100 Mbit/s
        let mtu = 1200u64;
        let w_100ms = bdp_window(rate, Duration::from_millis(100), mtu, 1.0);
        let w_200ms = bdp_window(rate, Duration::from_millis(200), mtu, 1.0);
        // Brutal keeps 2×BDP headroom: 2.5 MB at 100 ms, 5 MB at
        // 200 ms for a 100 Mbit/s target.
        assert!((2_400_000..=2_600_000).contains(&w_100ms), "got {w_100ms}");
        assert!((4_900_000..=5_100_000).contains(&w_200ms), "got {w_200ms}");
        assert!(w_200ms > w_100ms);
    }

    #[test]
    fn bdp_window_floors_at_unknown_rtt_window() {
        let w = bdp_window(1, Duration::from_millis(1), 1200, 1.0);
        assert_eq!(w, UNKNOWN_RTT_WINDOW);
    }

    #[test]
    fn bdp_window_caps_at_max() {
        // 100 Gbit/s × 10 s would be enormous — must clamp.
        let w = bdp_window(12_500_000_000, Duration::from_secs(10), 1200, 1.0);
        assert_eq!(w, MAX_WINDOW_BYTES);
    }

    #[test]
    fn bdp_window_compensates_for_loss_with_bounded_gain() {
        let rate = 12_500_000;
        let no_loss = bdp_window(rate, Duration::from_millis(100), 1200, 1.0);
        let twenty_pct_loss = bdp_window(rate, Duration::from_millis(100), 1200, 0.8);
        assert_eq!(twenty_pct_loss, no_loss * 5 / 4);
        // Inputs below Hysteria2's 80% floor cannot amplify without
        // bound.
        assert_eq!(
            bdp_window(rate, Duration::from_millis(100), 1200, 0.1),
            twenty_pct_loss
        );
    }

    #[test]
    fn congestion_event_does_not_shrink_without_persistent() {
        let cfg = Arc::new(BrutalConfig::from_mbps(100));
        let mut b = Brutal::new(cfg, 1200);
        let before = b.window();
        assert!(
            before > 2400,
            "seed window should be BDP-scale, got {before}"
        );
        let now = Instant::now();
        b.on_congestion_event(now, now, false, 12_000);
        assert_eq!(
            b.window(),
            before,
            "non-persistent loss MUST NOT shrink Brutal window"
        );
    }

    #[test]
    fn persistent_congestion_does_not_shrink_window() {
        let cfg = Arc::new(BrutalConfig::from_mbps(100));
        let mut b = Brutal::new(cfg, 1200);
        let before = b.window();
        let now = Instant::now();
        b.on_congestion_event(now, now, true, 100_000);
        assert_eq!(b.window(), before);
    }

    #[test]
    fn delivery_samples_raise_pacing_and_window_after_loss() {
        let cfg = Arc::new(BrutalConfig::from_mbps(100));
        let mut b = Brutal::new(cfg, 1200);
        let now = b.sample_start + Duration::from_secs(1);
        b.record_delivery(now, 80_000, 20_000);
        assert_eq!(b.ack_rate, 0.8);
        assert_eq!(b.metrics().pacing_rate, Some(125_000_000));
    }

    #[test]
    fn factory_builds_controller() {
        let cfg = Arc::new(BrutalConfig::from_mbps(50));
        let ctrl = ControllerFactory::build(cfg, Instant::now(), 1350);
        assert!(ctrl.window() >= 2 * 1350);
        assert_eq!(ctrl.metrics().pacing_rate, Some(50_000_000));
    }

    #[test]
    fn initial_window_matches_seed_bdp() {
        let cfg = Arc::new(BrutalConfig::from_mbps(100));
        let b = Brutal::new(cfg, 1200);
        assert_eq!(b.initial_window(), b.window());
    }
}
