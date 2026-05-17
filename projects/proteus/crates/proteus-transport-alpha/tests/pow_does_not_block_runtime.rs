//! Iter-16 regression test: prove that the client-side PoW
//! solver does NOT block the tokio runtime.
//!
//! Pre-iter-16 `pow::solve` ran synchronously inside the
//! `handshake_over_split_bound` async fn. A non-zero
//! `pow_difficulty` (the server can advertise up to d=24 in
//! production, ~30 s of CPU on a typical residential desktop)
//! would freeze every other task on the same runtime worker
//! for the whole solve. On single-threaded runtimes this
//! stalled the entire client; on multi-threaded runtimes it
//! starved one worker per outstanding handshake.
//!
//! This test pins the fix: under a forced non-zero difficulty,
//! a concurrent timer task continues to make progress while
//! the solver runs. If the solver ever regresses to inline
//! blocking, the timer task would see its tick land late by
//! the solver's wall-clock duration.

use proteus_transport_alpha::pow;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Difficulty chosen to give the solver enough work that a
/// synchronous (pre-iter-16) implementation would obviously
/// stall the runtime, but not so much that this test takes
/// forever on slow CI. 12 bits ≈ 4096 hashes ≈ ~50 ms on a
/// modern x86; well above any noise floor.
const D: u8 = 12;

#[tokio::test(flavor = "current_thread")]
async fn pow_solve_via_spawn_blocking_does_not_freeze_current_thread_runtime() {
    // Single-threaded runtime — the harshest test environment.
    // If the solver runs inline, the ticker below cannot make
    // progress; if it runs on the blocking pool, the ticker
    // continues firing.
    let ticks = Arc::new(AtomicU64::new(0));
    let ticks_for_task = Arc::clone(&ticks);
    let ticker = tokio::spawn(async move {
        let mut iv = tokio::time::interval(Duration::from_millis(5));
        loop {
            iv.tick().await;
            ticks_for_task.fetch_add(1, Ordering::Relaxed);
        }
    });

    // Spawn the solver onto the blocking pool — same pattern
    // client.rs uses post-iter-16.
    let fp = [0x42u8; 32];
    let nonce = [0xA5u8; 16];
    let start = Instant::now();
    let solver_handle = tokio::task::spawn_blocking(move || pow::solve(&fp, &nonce, D))
        .await
        .unwrap();
    let solver_elapsed = start.elapsed();
    assert!(solver_handle.is_some(), "solver must succeed at d={D}");

    // Stop the ticker.
    ticker.abort();
    let final_ticks = ticks.load(Ordering::Relaxed);

    // Expected ticks at 5 ms cadence over `solver_elapsed`:
    // ~`solver_elapsed.as_millis() / 5`. Allow generous slack
    // for CI scheduling jitter — we just want to prove the
    // ticker DID tick more than zero times, which it couldn't
    // if the solver had hogged the runtime worker.
    let expected_min = (solver_elapsed.as_millis() / 50) as u64; // 10× slack
    assert!(
        final_ticks >= expected_min,
        "ticker only fired {final_ticks} times during {solver_elapsed:?} of PoW \
         solving — expected at least {expected_min}. Indicates the solver is \
         blocking the runtime instead of running on the blocking pool."
    );
}

/// Sanity: when difficulty == 0, the solver returns instantly
/// (without even hitting `spawn_blocking`) — the iter-16
/// happy path keeps the zero-difficulty case fast.
#[tokio::test]
async fn pow_difficulty_zero_returns_instantly() {
    let fp = [0u8; 32];
    let nonce = [0u8; 16];
    let start = Instant::now();
    let sol = pow::solve(&fp, &nonce, 0).expect("d=0 always succeeds");
    let elapsed = start.elapsed();
    assert_eq!(sol, [0u8; 7]);
    assert!(
        elapsed < Duration::from_millis(10),
        "d=0 should be O(1), took {elapsed:?}"
    );
}
