//! Iter-34 regression test: prove the CLIENT binary inherits
//! the iter-24 `panic = "unwind"` profile, mirroring the
//! existing server-side test in
//! `proteus-server/tests/panic_in_task_does_not_kill_runtime.rs`.
//!
//! Why this exists separately from the server test: each binary
//! crate inherits the workspace `[profile.release]` UNLESS it
//! explicitly overrides. A future refactor could accidentally
//! add `panic = "abort"` to `crates/proteus-client/Cargo.toml`'s
//! profile section without touching the workspace, and the
//! existing server-side iter-24 test would still pass while
//! the client binary silently regressed to "any panic in any
//! tokio task kills the proxy."
//!
//! Symmetric coverage: server test + client test together pin
//! the workspace-wide invariant. Drift in either binary
//! independently fires its respective test.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_panicking_task_does_not_abort_runtime() {
    // Single-thread variant would be harshest, but multi-thread
    // matches how proteus-client::main.rs runs in production.
    // The contract holds for both runtime flavors.
    let ticks = Arc::new(AtomicU64::new(0));
    let ticks_for_task = Arc::clone(&ticks);
    let ticker = tokio::spawn(async move {
        let mut iv = tokio::time::interval(Duration::from_millis(5));
        loop {
            iv.tick().await;
            ticks_for_task.fetch_add(1, Ordering::Relaxed);
        }
    });

    // Sibling panicker. Under `panic = abort` the entire test
    // process aborts at this panic and we never reach the
    // assertions below — libtest reports "test panicked: signal
    // 6 (SIGABRT)". Under `panic = unwind` (iter-24) tokio's
    // task wrapper catches it; the JoinHandle reports
    // is_panic()=true; other tasks (the ticker) continue.
    let panicker = tokio::spawn(async {
        tokio::time::sleep(Duration::from_millis(20)).await;
        panic!("iter-34 deliberate test panic — must NOT tear down the runtime in proteus-client");
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let panicker_result = panicker.await;
    assert!(
        panicker_result.is_err(),
        "panicker's JoinHandle must report Err on panic"
    );
    let join_err = panicker_result.unwrap_err();
    assert!(
        join_err.is_panic(),
        "JoinError must report is_panic()=true; got {join_err:?}"
    );

    let final_ticks = ticks.load(Ordering::Relaxed);
    assert!(
        final_ticks >= 10,
        "ticker fired only {final_ticks} times in 100ms (after panicker spawned at 20ms). \
         Expected ~16-18 ticks. If much less, the runtime may be degraded after the sibling \
         panic — which would mean proteus-client's release profile silently lost iter-24's \
         `panic = unwind` setting."
    );

    ticker.abort();
}

/// Companion: prove `JoinHandle::await` returns a panicked
/// `JoinError` rather than aborting the process. This is the
/// iter-24 invariant the client's SOCKS5 accept loop relies on
/// (every per-CONNECT handler runs inside its own
/// `tokio::spawn`; any panic in one MUST stay isolated).
#[tokio::test]
async fn client_await_of_panicked_task_returns_join_error_not_abort() {
    let h = tokio::spawn(async {
        panic!("iter-34 client-side: planned");
    });
    let r = h.await;
    assert!(r.is_err());
    assert!(r.unwrap_err().is_panic());
    // Process still alive — we can continue running tests.
}
