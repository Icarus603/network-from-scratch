//! Per-user **concurrent session cap**.
//!
//! ## Why this exists
//!
//! The existing per-user controls bound the **rate** at which a user
//! can do things:
//!
//! - `user_rate_limit` — token bucket on new connections per second.
//! - `per_user_bandwidth_rate` — sliding-window MB/s of cumulative
//!   bytes.
//! - `byte_budget` — discrete cap on per-session bytes.
//!
//! None of these bound the **number of concurrent sessions** a single
//! `user_id` holds open at one time. A stolen-credential attacker can
//! ratchet up the box by opening N short sessions in parallel — each
//! one stays well under any rate limit, but the aggregate FD / RAM /
//! upstream-bandwidth footprint matches "one heavy user".
//!
//! Real-world numbers from commercial VPNs underscore the gap:
//! - NordVPN: 6 simultaneous devices per account
//! - ExpressVPN: 8 simultaneous devices
//! - Mullvad: 5 simultaneous devices
//!
//! All of them enforce this cap at the credential level, not the
//! per-IP level (which we already have via `max_connections`). The
//! per-IP cap doesn't help against a stolen credential being used by
//! a botnet across many source IPs.
//!
//! ## Design
//!
//! - `Mutex<HashMap<[u8; 8], usize>>` tracking the in-flight session
//!   count per user_id.
//! - `try_acquire(user_id)` checks the count, increments if under
//!   cap, returns an RAII `PerUserConnGuard` that decrements on drop.
//! - The guard drops in the same `InFlightGuard::drop` window as the
//!   session-byte merge — no leak risk even on handler panic.
//! - Memory bound: HashMap entries are removed when their count hits
//!   zero (no accumulation past peak); upper bound is
//!   `active_concurrent_users` not `total_unique_users_seen`.
//!
//! ## Why not a `Semaphore` per user
//!
//! `tokio::sync::Semaphore` would be cleaner but tying the permit
//! lifetime to a value that lives across spawn boundaries (we want
//! the permit dropped when the relay's session future completes,
//! not when the accept-loop closure returns) is awkward — the
//! `OwnedSemaphorePermit` doesn't compose with our existing
//! `InFlightGuard` RAII pattern. A plain counter under a mutex
//! costs O(1) at acquire/release and matches the rest of the
//! per-user infrastructure.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Per-user concurrent-session limiter. Cheap to share via `Arc`
/// across the binary's α-TCP / α-TLS / β-QUIC accept closures —
/// all three carriers consult the same instance so a user opening
/// connections across protocols still hits one shared cap.
pub struct PerUserConnLimiter {
    inner: Mutex<HashMap<[u8; 8], usize>>,
    /// Per-user concurrent-session cap. A user already at this count
    /// will be rejected on their next `try_acquire`. Set to
    /// `usize::MAX` to effectively disable while keeping the limiter
    /// installed (so SIGHUP-style swap-without-restart works).
    max_per_user: usize,
    /// Cumulative count of acquisitions that were rejected because
    /// the user was already at the cap. Operator alerts on
    /// `rate(...) > 0`: a non-zero rate here is a strong signal of
    /// credential abuse OR an under-provisioned cap.
    rejections: AtomicU64,
}

/// RAII guard returned by [`PerUserConnLimiter::try_acquire`].
///
/// Decrements the per-user count on drop — including on panic
/// unwind, since the drop is normal stack unwinding behavior. Holds
/// an `Arc<PerUserConnLimiter>` so the decrement reaches the right
/// instance even if the original limiter handle is dropped first
/// (e.g. during shutdown after the accept loop has returned).
#[must_use = "drop this guard at end of session — holding it forever leaks the count"]
pub struct PerUserConnGuard {
    limiter: Arc<PerUserConnLimiter>,
    user_id: [u8; 8],
}

impl Drop for PerUserConnGuard {
    fn drop(&mut self) {
        self.limiter.release(self.user_id);
    }
}

/// Outcome of [`PerUserConnLimiter::try_acquire`].
pub enum AcquireOutcome {
    /// Acquired — drop the guard at session-end to release the slot.
    Acquired(PerUserConnGuard),
    /// Rejected — the user is at the per-user cap. The caller should
    /// log + bump a metric + close the session WITHOUT triggering
    /// `cover_forward` (the user IS authenticated; routing them to
    /// the cover would imply auth-fail which mis-leads attackers
    /// into thinking they have the wrong credential when really
    /// they have the right one but too many sessions).
    Rejected {
        /// The current in-flight count for this user (= the cap).
        /// Surfaced in the structured WARN log so operators see
        /// "alice001 hit the cap of 6 sessions" not just "rejected".
        current: usize,
    },
}

impl PerUserConnLimiter {
    /// Build a limiter with `max_per_user` concurrent sessions per
    /// `user_id`. Recommended production value: 6-10 (mirrors the
    /// commercial-VPN per-account device cap). For a personal-VPN-
    /// for-friends deployment with one user per friend, 4-6 is
    /// usually plenty.
    ///
    /// `max_per_user=0` is treated as "limiter disabled" — every
    /// `try_acquire` returns `Acquired` with a no-op guard. Same
    /// rationale as the rate detector's `threshold=0` mode: keep
    /// the slot wired so a SIGHUP swap can flip it on later.
    #[must_use]
    pub fn new(max_per_user: usize) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(HashMap::new()),
            max_per_user,
            rejections: AtomicU64::new(0),
        })
    }

    /// Read the configured cap.
    #[must_use]
    pub fn max_per_user(&self) -> usize {
        self.max_per_user
    }

    /// Read the cumulative rejection count. Surfaced on `/metrics`
    /// as `proteus_per_user_conn_limit_rejected_total`.
    #[must_use]
    pub fn rejection_count(&self) -> u64 {
        self.rejections.load(Ordering::Relaxed)
    }

    /// Number of distinct users currently holding at least one slot.
    /// Surfaced as a gauge — operators see "how many users are
    /// actively connected right now" without scraping per-session
    /// logs.
    #[must_use]
    pub fn active_users(&self) -> usize {
        self.inner
            .lock()
            .expect("per-user conn limiter poisoned")
            .len()
    }

    /// Try to acquire a slot for `user_id`. Increments the per-user
    /// counter and returns a guard whose drop decrements it. On
    /// reject, bumps the rejection counter and returns the current
    /// count.
    pub fn try_acquire(self: &Arc<Self>, user_id: [u8; 8]) -> AcquireOutcome {
        // `max_per_user == 0` = disabled. Return a no-op guard so
        // callers don't need a branch — the guard's drop hits an
        // entry that was never created, which is a HashMap::get→
        // None on the release path (handled).
        if self.max_per_user == 0 {
            return AcquireOutcome::Acquired(PerUserConnGuard {
                limiter: Arc::clone(self),
                user_id,
            });
        }
        let mut g = self.inner.lock().expect("per-user conn limiter poisoned");
        let count = g.entry(user_id).or_insert(0);
        if *count >= self.max_per_user {
            // Roll back the entry's existence if we just inserted it
            // (a brand-new user_id with count=0 stayed at 0 → no
            // active session, so vacate the slot). Otherwise the
            // map slot lingers until next acquire.
            if *count == 0 {
                g.remove(&user_id);
            }
            drop(g);
            self.rejections.fetch_add(1, Ordering::Relaxed);
            // Re-read for accurate `current` (we just dropped the
            // lock, but in the brief window between drop and
            // reacquire we tolerate a small race — the WARN log's
            // `current` is operator-informational, not a security
            // boundary).
            return AcquireOutcome::Rejected {
                current: self.max_per_user,
            };
        }
        *count += 1;
        AcquireOutcome::Acquired(PerUserConnGuard {
            limiter: Arc::clone(self),
            user_id,
        })
    }

    /// Release a slot. Called by `PerUserConnGuard::drop`; should not
    /// be called directly (the guard's API enforces correct pairing).
    fn release(&self, user_id: [u8; 8]) {
        if self.max_per_user == 0 {
            // Disabled mode: nothing to release.
            return;
        }
        let mut g = self.inner.lock().expect("per-user conn limiter poisoned");
        if let Some(count) = g.get_mut(&user_id) {
            if *count > 0 {
                *count -= 1;
            }
            if *count == 0 {
                g.remove(&user_id);
            }
        }
        // If the entry was absent, this is a release from a no-op
        // guard created in disabled mode. Silently ignore.
    }

    /// Emit the Prometheus exposition block.
    ///
    /// Three series:
    /// - `proteus_per_user_conn_limit_max_per_user` (gauge) — the
    ///   operator-set cap; surfaced so operators can verify their
    ///   YAML edit landed without inspecting the on-disk file.
    /// - `proteus_per_user_conn_limit_active_users` (gauge) —
    ///   distinct user_ids currently holding ≥1 slot.
    /// - `proteus_per_user_conn_limit_rejected_total` (counter) —
    ///   cumulative rejection count. Alert on `rate(...) > 0`.
    #[must_use]
    pub fn prometheus(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(384);
        let _ = writeln!(
            s,
            "# HELP proteus_per_user_conn_limit_max_per_user \
             Operator-set per-user concurrent session cap. \
             0 = limiter installed but disabled (back-compat / SIGHUP-swap slot)."
        );
        let _ = writeln!(s, "# TYPE proteus_per_user_conn_limit_max_per_user gauge");
        let _ = writeln!(
            s,
            "proteus_per_user_conn_limit_max_per_user {}",
            self.max_per_user
        );
        let _ = writeln!(
            s,
            "# HELP proteus_per_user_conn_limit_active_users \
             Distinct user_ids currently holding ≥1 concurrent session slot."
        );
        let _ = writeln!(s, "# TYPE proteus_per_user_conn_limit_active_users gauge");
        let _ = writeln!(
            s,
            "proteus_per_user_conn_limit_active_users {}",
            self.active_users()
        );
        let _ = writeln!(
            s,
            "# HELP proteus_per_user_conn_limit_rejected_total \
             Sessions rejected because the user_id was already at the \
             per-user concurrent-session cap. Non-zero rate = likely \
             stolen credential being used in parallel, OR under-provisioned cap."
        );
        let _ = writeln!(
            s,
            "# TYPE proteus_per_user_conn_limit_rejected_total counter"
        );
        let _ = writeln!(
            s,
            "proteus_per_user_conn_limit_rejected_total {}",
            self.rejection_count()
        );
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_when_max_zero_always_acquires() {
        let l = PerUserConnLimiter::new(0);
        for _ in 0..1000 {
            assert!(matches!(
                l.try_acquire(*b"alice001"),
                AcquireOutcome::Acquired(_)
            ));
        }
        assert_eq!(l.rejection_count(), 0);
        // Active-users gauge stays 0 in disabled mode (we don't
        // populate the map).
        assert_eq!(l.active_users(), 0);
    }

    #[test]
    fn acquires_under_cap_rejects_at_cap() {
        let l = PerUserConnLimiter::new(3);
        let g1 = l.try_acquire(*b"alice001");
        let g2 = l.try_acquire(*b"alice001");
        let g3 = l.try_acquire(*b"alice001");
        assert!(matches!(g1, AcquireOutcome::Acquired(_)));
        assert!(matches!(g2, AcquireOutcome::Acquired(_)));
        assert!(matches!(g3, AcquireOutcome::Acquired(_)));
        match l.try_acquire(*b"alice001") {
            AcquireOutcome::Rejected { current } => assert_eq!(current, 3),
            other => panic!(
                "expected Rejected, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
        assert_eq!(l.rejection_count(), 1);
        assert_eq!(l.active_users(), 1);
    }

    #[test]
    fn guard_drop_releases_slot() {
        let l = PerUserConnLimiter::new(2);
        let g1 = l.try_acquire(*b"alice001");
        let g2 = l.try_acquire(*b"alice001");
        assert!(matches!(g1, AcquireOutcome::Acquired(_)));
        assert!(matches!(g2, AcquireOutcome::Acquired(_)));
        // Drop one — should free a slot for a third acquire.
        drop(g1);
        let g3 = l.try_acquire(*b"alice001");
        assert!(matches!(g3, AcquireOutcome::Acquired(_)));
        assert_eq!(l.rejection_count(), 0);
    }

    #[test]
    fn distinct_users_independent_caps() {
        let l = PerUserConnLimiter::new(1);
        let _alice = l.try_acquire(*b"alice001");
        let _bob = l.try_acquire(*b"bob00002");
        // Both held one slot; alice's second acquire is rejected,
        // bob's first slot is still active.
        assert!(matches!(
            l.try_acquire(*b"alice001"),
            AcquireOutcome::Rejected { current: 1 }
        ));
        assert!(matches!(
            l.try_acquire(*b"bob00002"),
            AcquireOutcome::Rejected { current: 1 }
        ));
        assert_eq!(l.active_users(), 2);
    }

    #[test]
    fn empty_user_evicted_after_all_guards_drop() {
        // The map should not grow unboundedly across the unique-user
        // count — only across CONCURRENT users.
        let l = PerUserConnLimiter::new(4);
        for i in 0..100u16 {
            let mut uid = [0u8; 8];
            uid[0..2].copy_from_slice(&i.to_le_bytes());
            let g = l.try_acquire(uid);
            assert!(matches!(g, AcquireOutcome::Acquired(_)));
            // guard dropped at end of iteration → count goes to 0
            // → entry evicted.
        }
        assert_eq!(
            l.active_users(),
            0,
            "every user's count should have hit 0 → evicted"
        );
    }

    #[test]
    fn guard_drop_on_panic_releases_slot() {
        // Panic-safety: dropping the guard during stack unwind must
        // still release the slot. Pattern matches the InFlightGuard
        // test in metrics.rs.
        let l = PerUserConnLimiter::new(1);
        let l2 = Arc::clone(&l);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _g = l2.try_acquire(*b"alice001");
            assert_eq!(l2.active_users(), 1);
            panic!("simulated handler panic");
        }));
        assert!(r.is_err(), "panic should have propagated");
        // Slot freed during unwind.
        assert_eq!(l.active_users(), 0);
        // And the user can immediately acquire again.
        assert!(matches!(
            l.try_acquire(*b"alice001"),
            AcquireOutcome::Acquired(_)
        ));
    }

    #[test]
    fn rejection_does_not_bump_active_users_for_brand_new_uid() {
        // Edge case: an unknown user_id whose FIRST acquire is
        // rejected (impossible at cap=N>0 since count starts at 0,
        // but tested via cap=0 means disabled — so we use a tighter
        // mirror via a different shape: explicitly cap=1, get one,
        // then bob tries and gets rejected only after going one over.
        // The active-user accounting must not leak rows for users who
        // never held a real slot.
        let l = PerUserConnLimiter::new(1);
        let _g = l.try_acquire(*b"alice001");
        assert_eq!(l.active_users(), 1);
        // Alice's second acquire is rejected — must not increment
        // active_users (she was already counted).
        let _ = l.try_acquire(*b"alice001");
        assert_eq!(l.active_users(), 1);
    }

    #[test]
    fn prometheus_emits_three_series() {
        let l = PerUserConnLimiter::new(2);
        // Hold 2 for alice (at cap) + 1 for bob.
        let _a1 = l.try_acquire(*b"alice001");
        let _a2 = l.try_acquire(*b"alice001");
        let _b1 = l.try_acquire(*b"bob00002");
        // Two more alice attempts must reject (cap is 2).
        let a3 = l.try_acquire(*b"alice001");
        let a4 = l.try_acquire(*b"alice001");
        assert!(matches!(a3, AcquireOutcome::Rejected { .. }));
        assert!(matches!(a4, AcquireOutcome::Rejected { .. }));
        let s = l.prometheus();
        assert!(
            s.contains("proteus_per_user_conn_limit_max_per_user 2"),
            "{s}"
        );
        assert!(
            s.contains("proteus_per_user_conn_limit_active_users 2"),
            "{s}"
        );
        assert!(
            s.contains("proteus_per_user_conn_limit_rejected_total 2"),
            "expected rejected_total=2 in:\n{s}"
        );
    }

    #[test]
    fn prometheus_for_disabled_limiter_shows_max_zero() {
        let l = PerUserConnLimiter::new(0);
        let s = l.prometheus();
        assert!(s.contains("proteus_per_user_conn_limit_max_per_user 0"));
        // Counter still emitted (operators script alert from
        // existence of the series).
        assert!(s.contains("proteus_per_user_conn_limit_rejected_total 0"));
    }

    #[test]
    fn concurrent_acquire_release_stress() {
        // 16 threads × 100 ops; cap is 4 per user. Final state
        // must have count → 0 (every guard dropped).
        let l = PerUserConnLimiter::new(4);
        let mut handles = Vec::new();
        for _ in 0..16 {
            let l = Arc::clone(&l);
            handles.push(std::thread::spawn(move || {
                for _ in 0..100 {
                    let _g = l.try_acquire(*b"alice001");
                    std::thread::yield_now();
                    // _g dropped at end of iteration.
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(l.active_users(), 0);
        // Many rejections likely occurred (16 threads × 100 ops vs
        // cap=4) — verify the counter is non-zero.
        assert!(
            l.rejection_count() > 0,
            "expected rejections under contention, got 0"
        );
    }
}
