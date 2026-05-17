//! Per-call-site token-bucket throttle for `tracing::warn!` /
//! `tracing::error!` calls on hot rejection paths.
//!
//! ## Why this exists
//!
//! The accept loop fires `warn!(peer = %peer, "firewall denied; \
//! routing to cover")` (and similar) on every rejected
//! connection. Under a scanner / DoS-prober pounding at
//! 1000 conn/sec, that's 3.6M log lines per hour — easily enough
//! to fill `/var/log/journal` on a small VPS and force systemd-
//! journald to start dropping records. When journald rate-limits
//! (`SystemMaxFileSize` is hit), legitimate operational warnings
//! get dropped alongside the noise, and the operator's first
//! signal is "I can't see what happened".
//!
//! Standard Linux pattern (`pr_warn_ratelimited(3)`, nginx
//! `error_log_throttle`, journald's `RateLimitInterval=` /
//! `RateLimitBurst=`): emit the first N events in a sliding
//! window, then suppress the rest with a periodic
//! "(suppressed M)" rollup. This module is the in-process
//! token-bucket that the hot paths consult.
//!
//! ## Why not just lean on `RateLimitInterval=` in journald
//!
//! journald's rate-limiter is per-unit, not per-message-template.
//! The whole proteus-server unit hits the limit, so a
//! firewall-flood drops both the noisy "firewall denied" lines
//! AND the genuinely important "TLS reload FAILED" line that
//! happened in the same window. The in-process throttle is
//! per-call-site (each `Throttle` instance owns its own
//! bucket), so a flood on one path doesn't suppress a separate
//! path's first emission.
//!
//! ## Design
//!
//! * **Token bucket** — one bucket per `Throttle` instance.
//!   Bucket starts full (`burst` tokens), refills at
//!   `refill_per_sec` tokens per second.
//! * **Try-emit** returns `Allowed | Suppressed(n_since_last_allow)`.
//!   The caller wires the result into `tracing::warn!` /
//!   `tracing::error!` directly — when `Allowed`, emit the
//!   normal log line; when `Suppressed`, suppress.
//! * **Rollup** — every `rollup_interval` (default 60s) the
//!   throttle's `roll_up()` method returns the cumulative
//!   suppressed count for the window, which the caller emits
//!   as a single `warn!` line. The background tasks in the
//!   binary call `roll_up()` from a periodic tick.
//!
//! Concurrency: every counter is `AtomicU64`; `try_acquire` is
//! a single CAS round-trip plus a `now()` read. Cheap enough
//! to wrap every hot-path log call.
//!
//! ## What this is NOT
//!
//! - Not a tracing subscriber layer. We DON'T intercept all
//!   logs globally — only the call sites the operator wires
//!   explicitly. Global subscriber-layer throttling would also
//!   suppress one-off `error!` lines from cold paths, which is
//!   the opposite of what we want.
//! - Not a per-peer-IP rate limiter. The connection-level rate
//!   limiter (`crate::rate_limit`) handles per-IP enforcement;
//!   this is just about the LOG VOLUME those rejections produce.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Result of a [`Throttle::try_acquire`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcquireResult {
    /// Emit the log line. The throttle deducted one token.
    Allowed,
    /// Suppress the log line. The throttle is over budget. The
    /// `u64` is the count of suppressions accumulated since the
    /// last `Allowed` (or since the last `roll_up`) — useful if
    /// the caller wants a "(suppressed N in burst)" style
    /// inline message instead of (or in addition to) the
    /// periodic rollup.
    Suppressed(u64),
}

/// Per-call-site token-bucket throttle. Build one with
/// [`Throttle::new`] and call [`Throttle::try_acquire`] at the
/// log-line site:
///
/// ```ignore
/// static FW_DENIED_THROTTLE: Throttle = Throttle::new(10, 1.0);
/// // ...
/// if let AcquireResult::Allowed = FW_DENIED_THROTTLE.try_acquire() {
///     tracing::warn!(peer = %peer, "firewall denied; routing to cover");
/// }
/// ```
///
/// Periodic rollup (typically wired in a 60s tick task):
///
/// ```ignore
/// let suppressed = FW_DENIED_THROTTLE.roll_up();
/// if suppressed > 0 {
///     tracing::warn!(suppressed, "firewall-denied: suppressed N similar messages in last 60s");
/// }
/// ```
pub struct Throttle {
    /// Maximum burst capacity (tokens). Starts full at this value.
    burst: u64,
    /// Tokens per second refill. Stored as fixed-point (10⁶) so
    /// the steady-state path doesn't pay for f64 ops on the hot
    /// path. `1.0 tps` → 1_000_000 here.
    refill_micros_per_sec: u64,
    /// Available tokens × 1_000_000 (fixed-point so refill can
    /// be fractional).
    tokens_micro: AtomicU64,
    /// Last refill instant (microseconds since `epoch_instant`).
    last_refill_micros: AtomicU64,
    /// Reference instant captured at construction so the rolling
    /// "now" math is monotonic. We only ever store offsets from
    /// this point.
    epoch_instant: Instant,
    /// Cumulative suppressed events since the last `roll_up`.
    suppressed_since_rollup: AtomicU64,
    /// Cumulative ALL-TIME suppressed count — operator can see
    /// the total via [`Throttle::total_suppressed`] for /metrics.
    total_suppressed: AtomicU64,
    /// Cumulative ALL-TIME allowed count — pairs with above so
    /// dashboards can compute a suppression ratio.
    total_allowed: AtomicU64,
}

impl Throttle {
    /// Build a new throttle. `burst` is the max tokens the bucket
    /// can hold (and the starting balance). `refill_per_sec` is
    /// the steady-state refill rate; fractional values OK
    /// (e.g. `0.1` → 1 token every 10 seconds).
    ///
    /// Sensible defaults for a hot-reject path:
    ///   * `burst = 10` — first 10 events through cleanly
    ///   * `refill_per_sec = 1.0` — long-term cap 1 line/sec
    #[must_use]
    pub fn new(burst: u64, refill_per_sec: f64) -> Self {
        let refill_micros = (refill_per_sec.max(0.0) * 1_000_000.0) as u64;
        let epoch = Instant::now();
        Self {
            burst,
            refill_micros_per_sec: refill_micros,
            tokens_micro: AtomicU64::new(burst.saturating_mul(1_000_000)),
            last_refill_micros: AtomicU64::new(0),
            epoch_instant: epoch,
            suppressed_since_rollup: AtomicU64::new(0),
            total_suppressed: AtomicU64::new(0),
            total_allowed: AtomicU64::new(0),
        }
    }

    /// Try to deduct one token. Returns [`AcquireResult::Allowed`]
    /// when a token was available, [`AcquireResult::Suppressed`]
    /// otherwise.
    pub fn try_acquire(&self) -> AcquireResult {
        self.refill();
        // CAS loop — common case is single-iteration on
        // uncontended path.
        loop {
            let cur = self.tokens_micro.load(Ordering::Relaxed);
            if cur >= 1_000_000 {
                let new = cur - 1_000_000;
                match self.tokens_micro.compare_exchange_weak(
                    cur,
                    new,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        self.total_allowed.fetch_add(1, Ordering::Relaxed);
                        return AcquireResult::Allowed;
                    }
                    Err(_) => continue, // retry on contention
                }
            } else {
                let n = self.suppressed_since_rollup.fetch_add(1, Ordering::Relaxed) + 1;
                self.total_suppressed.fetch_add(1, Ordering::Relaxed);
                return AcquireResult::Suppressed(n);
            }
        }
    }

    /// Refill bucket based on time elapsed since last refill.
    /// Called implicitly by [`try_acquire`]; the caller doesn't
    /// need to invoke it directly.
    fn refill(&self) {
        let now_micros = self
            .epoch_instant
            .elapsed()
            .as_micros()
            .min(u64::MAX as u128) as u64;
        let last = self.last_refill_micros.load(Ordering::Relaxed);
        if now_micros <= last {
            return; // monotonic clock; should never go backward, but defend
        }
        let elapsed_micros = now_micros - last;
        // tokens to add: refill_micros_per_sec * elapsed_micros / 1_000_000
        // We carry the multiplication in u128 to avoid overflow even at
        // huge burst values + large elapsed windows.
        let to_add = (self.refill_micros_per_sec as u128 * elapsed_micros as u128) / 1_000_000;
        let to_add = to_add.min(u64::MAX as u128) as u64;
        if to_add == 0 {
            // Not enough time has passed to add a whole micro-token;
            // skip the CAS to keep the hot path cheap.
            return;
        }
        // Atomically update last_refill so concurrent callers don't
        // double-add. If CAS fails, another caller did the refill —
        // we just bail and let try_acquire's next iteration re-check.
        if self
            .last_refill_micros
            .compare_exchange(last, now_micros, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        // Cap at burst capacity (fixed-point).
        let cap = self.burst.saturating_mul(1_000_000);
        // Saturating add then min-cap; cheap and avoids the
        // CAS-loop we don't strictly need for this.
        let cur = self.tokens_micro.load(Ordering::Relaxed);
        let new = (cur.saturating_add(to_add)).min(cap);
        self.tokens_micro.store(new, Ordering::Relaxed);
    }

    /// Take the cumulative suppressed-since-last-rollup count
    /// AND reset the counter to zero atomically. Returns 0 when
    /// nothing was suppressed in the window. Caller emits a
    /// single `warn!(suppressed, "...")` when non-zero.
    pub fn roll_up(&self) -> u64 {
        self.suppressed_since_rollup.swap(0, Ordering::Relaxed)
    }

    /// All-time total of allowed events, for /metrics exposition.
    #[must_use]
    pub fn total_allowed(&self) -> u64 {
        self.total_allowed.load(Ordering::Relaxed)
    }

    /// All-time total of suppressed events. Operators dashboarding
    /// `proteus_log_suppressed_total{site="..."}` watch this for
    /// a sudden uptick (= scanner / DoS hammer arrived).
    #[must_use]
    pub fn total_suppressed(&self) -> u64 {
        self.total_suppressed.load(Ordering::Relaxed)
    }
}

impl std::fmt::Debug for Throttle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Throttle")
            .field("burst", &self.burst)
            .field(
                "refill_per_sec",
                &(self.refill_micros_per_sec as f64 / 1_000_000.0),
            )
            .field("total_allowed", &self.total_allowed())
            .field("total_suppressed", &self.total_suppressed())
            .finish()
    }
}

/// Helper macro to keep call sites terse. Expands to:
///
/// ```ignore
/// match $throttle.try_acquire() {
///     $crate::log_throttle::AcquireResult::Allowed => $emit_block,
///     $crate::log_throttle::AcquireResult::Suppressed(_) => {}
/// }
/// ```
///
/// Use:
///
/// ```ignore
/// throttled_warn!(FW_DENIED_THROTTLE, {
///     tracing::warn!(peer = %peer, "firewall denied; routing to cover");
/// });
/// ```
#[macro_export]
macro_rules! throttled_warn {
    ($throttle:expr, $block:block) => {
        if let $crate::log_throttle::AcquireResult::Allowed = $throttle.try_acquire() {
            $block
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn fresh_throttle_admits_burst_then_suppresses() {
        let t = Throttle::new(3, 0.0); // 3 burst, never refill
        assert_eq!(t.try_acquire(), AcquireResult::Allowed);
        assert_eq!(t.try_acquire(), AcquireResult::Allowed);
        assert_eq!(t.try_acquire(), AcquireResult::Allowed);
        // 4th call is suppressed; n_since_last_allow == 1.
        assert!(matches!(t.try_acquire(), AcquireResult::Suppressed(1)));
        assert!(matches!(t.try_acquire(), AcquireResult::Suppressed(2)));
        assert_eq!(t.total_allowed(), 3);
        assert_eq!(t.total_suppressed(), 2);
    }

    #[test]
    fn rollup_returns_count_and_resets_counter() {
        let t = Throttle::new(1, 0.0);
        let _ = t.try_acquire();
        let _ = t.try_acquire();
        let _ = t.try_acquire();
        let _ = t.try_acquire();
        assert_eq!(t.roll_up(), 3);
        assert_eq!(t.roll_up(), 0, "rollup must reset");
        // But total_suppressed is NOT reset by rollup.
        assert_eq!(t.total_suppressed(), 3);
    }

    #[test]
    fn refill_makes_tokens_available_over_time() {
        // 1 burst, refill 100 tokens/sec → one new token every 10 ms.
        let t = Throttle::new(1, 100.0);
        assert_eq!(t.try_acquire(), AcquireResult::Allowed);
        assert!(matches!(t.try_acquire(), AcquireResult::Suppressed(_)));
        std::thread::sleep(std::time::Duration::from_millis(50));
        // After 50 ms at 100 tps, ~5 tokens have refilled but burst caps at 1.
        assert_eq!(t.try_acquire(), AcquireResult::Allowed);
    }

    #[test]
    fn burst_caps_at_configured_max_regardless_of_idle_time() {
        let t = Throttle::new(2, 1000.0); // huge refill rate
        std::thread::sleep(std::time::Duration::from_millis(50)); // tons of "refill" possible
        assert_eq!(t.try_acquire(), AcquireResult::Allowed);
        assert_eq!(t.try_acquire(), AcquireResult::Allowed);
        // Third must suppress — bucket caps at 2 even though we slept.
        assert!(matches!(t.try_acquire(), AcquireResult::Suppressed(_)));
    }

    #[test]
    fn zero_refill_means_one_shot_burst() {
        let t = Throttle::new(1, 0.0);
        assert_eq!(t.try_acquire(), AcquireResult::Allowed);
        std::thread::sleep(std::time::Duration::from_millis(50));
        // Refill rate is 0; the token never comes back.
        assert!(matches!(t.try_acquire(), AcquireResult::Suppressed(_)));
    }

    #[test]
    fn concurrent_acquires_do_not_double_admit_above_burst() {
        // Many threads racing on a single 100-burst throttle should
        // see at most 100 Allowed even if every call is concurrent.
        let t = Arc::new(Throttle::new(100, 0.0));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let t = Arc::clone(&t);
            handles.push(std::thread::spawn(move || {
                let mut allowed = 0u64;
                for _ in 0..1000 {
                    if t.try_acquire() == AcquireResult::Allowed {
                        allowed += 1;
                    }
                }
                allowed
            }));
        }
        let total_allowed: u64 = handles.into_iter().map(|h| h.join().unwrap()).sum();
        assert_eq!(
            total_allowed, 100,
            "burst cap must hold under concurrent access; got {total_allowed}"
        );
        assert_eq!(t.total_allowed(), 100);
    }

    #[test]
    fn macro_expansion_admits_burst_and_suppresses() {
        let t = Throttle::new(2, 0.0);
        let mut emitted = 0;
        for _ in 0..5 {
            crate::throttled_warn!(t, {
                emitted += 1;
            });
        }
        assert_eq!(emitted, 2, "macro must respect burst cap");
        assert_eq!(t.total_suppressed(), 3);
    }

    #[test]
    fn debug_format_includes_key_state() {
        let t = Throttle::new(5, 2.5);
        let s = format!("{t:?}");
        assert!(s.contains("burst: 5"));
        assert!(s.contains("refill_per_sec: 2.5"));
    }
}
