//! Per-source-IP token-bucket rate limiter.
//!
//! Production deployments hit two distinct DoS vectors:
//!
//! 1. **Handshake amplification** — every new TCP connection costs the
//!    server ~50 µs of ML-KEM-768 decapsulation. An attacker that
//!    opens 100k connections per second can saturate a core without
//!    transferring any application data.
//! 2. **AEAD-drop fan-out** — once authenticated, an attacker can flood
//!    garbage records to force the receiver to repeatedly decrypt
//!    (constant-time AEAD verify is ~1 µs). The data-plane silent-drop
//!    rule (spec §11.16) is correct but expensive at scale.
//!
//! This module supplies a coarse-grained per-source-IP bucket:
//! `capacity` permits with `refill_per_sec` refill. The
//! [`ServerCtx::serve`] loop calls [`RateLimiter::check`] before paying
//! any ML-KEM cost. By default, attacks that breach the limit are
//! routed to the cover-forward path so an attacker cannot distinguish
//! "rate-limited" from "this is a generic HTTPS server".

use std::collections::HashMap;
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

/// One token bucket.
#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

/// Per-IP token-bucket rate limiter.
pub struct RateLimiter {
    capacity: f64,
    refill_per_sec: f64,
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
    /// Cap on how many distinct IPs we track. Prevents memory blow-up
    /// under random-source-IP flood (which spoofed UDP could do but
    /// TCP cannot — still we cap defensively).
    max_buckets: usize,
}

impl RateLimiter {
    /// Build a new limiter. `capacity` is the burst size (max tokens),
    /// `refill_per_sec` is the steady-state rate. A handshake costs 1
    /// token.
    #[must_use]
    pub fn new(capacity: f64, refill_per_sec: f64) -> Self {
        Self {
            capacity,
            refill_per_sec,
            buckets: Mutex::new(HashMap::new()),
            max_buckets: 1 << 16, // 64 K distinct source IPs
        }
    }

    /// Try to consume one token for `ip`. Returns `true` if allowed.
    pub fn check(&self, ip: IpAddr) -> bool {
        let mut buckets = self.buckets.lock().expect("rate-limit mutex");
        if buckets.len() >= self.max_buckets {
            // Garbage-collect: drop full buckets (idle senders).
            buckets.retain(|_, b| b.tokens < self.capacity);
            if buckets.len() >= self.max_buckets {
                // Still full — fall back to deny everything.
                return false;
            }
        }
        let now = Instant::now();
        let entry = buckets.entry(ip).or_insert(Bucket {
            tokens: self.capacity,
            last_refill: now,
        });
        let elapsed = now.duration_since(entry.last_refill).as_secs_f64();
        entry.tokens = (entry.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        entry.last_refill = now;
        if entry.tokens >= 1.0 {
            entry.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Drop entries that have refilled to capacity (effectively idle).
    /// Production loops can call this on a 60-second cadence to bound
    /// memory.
    pub fn vacuum(&self) {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().expect("rate-limit mutex");
        let cap = self.capacity;
        let refill = self.refill_per_sec;
        buckets.retain(|_, b| {
            let elapsed = now.duration_since(b.last_refill).as_secs_f64();
            let projected_tokens = (b.tokens + elapsed * refill).min(cap);
            // Keep only buckets that are NOT at capacity (i.e. recently
            // consumed); drop fully-refilled idle entries.
            projected_tokens < cap
        });
    }

    /// Number of tracked buckets (for telemetry / sanity tests).
    #[must_use]
    pub fn tracked(&self) -> usize {
        self.buckets.lock().expect("rate-limit mutex").len()
    }
}

/// Generic token-bucket limiter keyed on any `Hash + Eq + Clone` type.
///
/// Mirrors [`RateLimiter`] but generic in the key. Two instantiations
/// ship today:
///
/// - `KeyedRateLimiter<[u8; 8]>` — per-user-id limit. Layered on top
///   of the per-IP limit, this is what makes Proteus CGNAT-fair:
///   multiple users behind one NAT can each get their own budget.
/// - `KeyedRateLimiter<()>` — degenerate single-bucket limit, used
///   as the global `max_handshakes_per_minute` cap. The unit-keyed
///   variant amortizes to one HashMap entry forever.
pub struct KeyedRateLimiter<K: Hash + Eq + Clone> {
    capacity: f64,
    refill_per_sec: f64,
    buckets: Mutex<HashMap<K, Bucket>>,
    max_buckets: usize,
    /// Monotonic counter of `check()` calls that returned `false`.
    /// Exported to Prometheus by the binary (per-user, global).
    rejections: AtomicU64,
}

impl<K: Hash + Eq + Clone> KeyedRateLimiter<K> {
    /// Build a new limiter. `capacity` is the burst size, `refill_per_sec`
    /// the steady-state rate. `max_buckets` caps memory (one bucket per
    /// distinct key). For single-key buckets (global cap), pass 1.
    #[must_use]
    pub fn new(capacity: f64, refill_per_sec: f64, max_buckets: usize) -> Self {
        Self {
            capacity,
            refill_per_sec,
            buckets: Mutex::new(HashMap::new()),
            max_buckets,
            rejections: AtomicU64::new(0),
        }
    }

    /// Try to consume one token for `key`. Returns `true` if allowed.
    /// Rejections increment a monotonic counter readable via
    /// [`Self::rejection_count`].
    pub fn check(&self, key: &K) -> bool {
        let allowed = self.check_inner(key);
        if !allowed {
            self.rejections.fetch_add(1, Ordering::Relaxed);
        }
        allowed
    }

    fn check_inner(&self, key: &K) -> bool {
        let mut buckets = self.buckets.lock().expect("keyed rate-limit mutex");
        if buckets.len() >= self.max_buckets && !buckets.contains_key(key) {
            // GC: drop fully-refilled idle buckets first.
            buckets.retain(|_, b| b.tokens < self.capacity);
            if buckets.len() >= self.max_buckets {
                return false;
            }
        }
        let now = Instant::now();
        let entry = buckets.entry(key.clone()).or_insert(Bucket {
            tokens: self.capacity,
            last_refill: now,
        });
        let elapsed = now.duration_since(entry.last_refill).as_secs_f64();
        entry.tokens = (entry.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        entry.last_refill = now;
        if entry.tokens >= 1.0 {
            entry.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Drop entries that have refilled to capacity (idle).
    pub fn vacuum(&self) {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().expect("keyed rate-limit mutex");
        let cap = self.capacity;
        let refill = self.refill_per_sec;
        buckets.retain(|_, b| {
            let elapsed = now.duration_since(b.last_refill).as_secs_f64();
            let projected_tokens = (b.tokens + elapsed * refill).min(cap);
            projected_tokens < cap
        });
    }

    /// Number of tracked buckets.
    #[must_use]
    pub fn tracked(&self) -> usize {
        self.buckets.lock().expect("keyed rate-limit mutex").len()
    }

    /// Number of `check()` calls that returned `false` since startup.
    #[must_use]
    pub fn rejection_count(&self) -> u64 {
        self.rejections.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn allows_up_to_capacity_then_denies() {
        let lim = RateLimiter::new(3.0, 0.001); // virtually no refill
        let a = ip("203.0.113.1");
        assert!(lim.check(a));
        assert!(lim.check(a));
        assert!(lim.check(a));
        assert!(!lim.check(a));
    }

    #[test]
    fn refills_over_time() {
        let lim = RateLimiter::new(2.0, 100.0); // 100 tokens/sec
        let a = ip("203.0.113.2");
        assert!(lim.check(a));
        assert!(lim.check(a));
        assert!(!lim.check(a));
        thread::sleep(Duration::from_millis(50));
        assert!(lim.check(a)); // ~5 tokens refilled
    }

    #[test]
    fn distinct_ips_are_independent() {
        let lim = RateLimiter::new(1.0, 0.001);
        let a = ip("203.0.113.10");
        let b = ip("203.0.113.11");
        assert!(lim.check(a));
        assert!(lim.check(b));
        assert!(!lim.check(a));
        assert!(!lim.check(b));
    }

    #[test]
    fn ipv6_buckets_independent_from_ipv4() {
        let lim = RateLimiter::new(1.0, 0.001);
        let a = ip("203.0.113.20");
        let b = ip("2001:db8::1");
        assert!(lim.check(a));
        assert!(lim.check(b));
        assert!(!lim.check(a));
        assert!(!lim.check(b));
    }

    #[test]
    fn vacuum_does_not_panic() {
        let lim = RateLimiter::new(5.0, 1.0);
        for i in 0..100 {
            let ip_v: IpAddr = format!("198.51.100.{i}").parse().unwrap();
            let _ = lim.check(ip_v);
        }
        lim.vacuum();
    }

    #[test]
    fn vacuum_drops_idle_full_buckets() {
        // High refill so any visited bucket will be at capacity after
        // a real-time sleep (we simulate it via re-check after sleep).
        let lim = RateLimiter::new(5.0, 1000.0);
        for i in 0..10 {
            let ip_v: IpAddr = format!("198.51.100.{i}").parse().unwrap();
            assert!(lim.check(ip_v));
        }
        assert_eq!(lim.tracked(), 10);
        thread::sleep(Duration::from_millis(50));
        lim.vacuum();
        // After 50 ms with 1000 tokens/sec refill, every consumed bucket
        // has refilled (~50 tokens) and capped at 5 → all idle → all
        // dropped.
        assert_eq!(lim.tracked(), 0);
    }

    #[test]
    fn vacuum_keeps_busy_buckets() {
        let lim = RateLimiter::new(2.0, 0.001); // virtually no refill
        let ip_a = ip("198.51.100.50");
        assert!(lim.check(ip_a));
        assert!(lim.check(ip_a)); // bucket now at 0, busy
        assert_eq!(lim.tracked(), 1);
        lim.vacuum();
        assert_eq!(lim.tracked(), 1, "active bucket must be retained");
    }

    // ----- KeyedRateLimiter ([u8; 8] user-id bucket) -----

    #[test]
    fn keyed_per_user_independent_buckets() {
        let lim: KeyedRateLimiter<[u8; 8]> = KeyedRateLimiter::new(2.0, 0.001, 1024);
        let alice = *b"alice001";
        let bob = *b"bob00001";
        assert!(lim.check(&alice));
        assert!(lim.check(&alice));
        assert!(!lim.check(&alice));
        // Bob has his own budget — CGNAT users behind alice's IP are
        // not penalized.
        assert!(lim.check(&bob));
        assert!(lim.check(&bob));
        assert!(!lim.check(&bob));
        assert_eq!(lim.rejection_count(), 2);
    }

    #[test]
    fn keyed_global_single_bucket_via_unit_key() {
        // Global handshake budget — one shared bucket.
        let lim: KeyedRateLimiter<()> = KeyedRateLimiter::new(3.0, 0.001, 1);
        for _ in 0..3 {
            assert!(lim.check(&()));
        }
        assert!(!lim.check(&()));
        assert_eq!(lim.tracked(), 1);
        assert_eq!(lim.rejection_count(), 1);
    }

    #[test]
    fn keyed_max_buckets_cap_blocks_new_keys_when_full() {
        let lim: KeyedRateLimiter<u32> = KeyedRateLimiter::new(2.0, 0.001, 2);
        assert!(lim.check(&1));
        assert!(lim.check(&2));
        // Both buckets busy (haven't refilled). A 3rd key must fail.
        // First consume both so they're below capacity.
        assert!(lim.check(&1));
        assert!(lim.check(&2));
        assert!(!lim.check(&3), "third distinct key must be denied at cap");
        assert_eq!(lim.tracked(), 2);
    }

    #[test]
    fn keyed_rejection_counter_tracks_only_denies() {
        let lim: KeyedRateLimiter<u8> = KeyedRateLimiter::new(1.0, 0.001, 16);
        assert!(lim.check(&7));
        assert!(!lim.check(&7));
        assert!(!lim.check(&7));
        assert_eq!(lim.rejection_count(), 2);
    }

    #[test]
    fn keyed_refills_over_time() {
        let lim: KeyedRateLimiter<u8> = KeyedRateLimiter::new(2.0, 100.0, 16);
        let k = 42u8;
        assert!(lim.check(&k));
        assert!(lim.check(&k));
        assert!(!lim.check(&k));
        thread::sleep(Duration::from_millis(50));
        assert!(lim.check(&k));
    }
}
