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
use std::net::IpAddr;
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
}
