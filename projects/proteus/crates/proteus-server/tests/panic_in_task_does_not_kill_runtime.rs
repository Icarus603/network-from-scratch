//! Iter-24 regression test: prove that a panic in a single
//! `tokio::spawn`-ed task does NOT tear down the whole
//! process (i.e., release-profile `panic = "unwind"` is in
//! effect, not `panic = "abort"`).
//!
//! Pre-iter-24 the release profile had `panic = "abort"` —
//! any panic in any per-connection task aborted the entire
//! binary, making the iter-18/19/20/21 EMFILE-survival
//! hardening moot (a single malformed connection's logic bug
//! would kill every other in-flight session + the metrics
//! endpoint + the periodic self-test).
//!
//! Why this test lives in `proteus-server`: this is a binary-
//! crate-level contract. The release-profile `panic` mode is
//! a workspace-Cargo.toml decision; this test pins the
//! observable behavior at the test-binary level. If someone
//! flips it back to `abort`, the test fails because
//! `JoinHandle::await` returns a panicked task error AND the
//! ticker survives in this binary's process but it would NOT
//! in the production binary under abort.
//!
//! Technically the test runs under the `test` profile, not
//! `release`. But the workspace Cargo.toml sets the same
//! `panic = "unwind"` (test profile inherits from dev by
//! default, and dev doesn't override). The test is therefore
//! a SHAPE proof — it shows that tokio's task isolation
//! works as expected, which is the production guarantee the
//! iter-24 profile flip relies on. A separate manual check
//! (`cargo build --release && nm | grep _Unwind_Resume`)
//! confirms the release binary has unwinding tables.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn panicking_task_does_not_abort_runtime() {
    // A ticker task that increments a counter every 5 ms.
    // If the runtime survives the sibling task's panic,
    // this ticker keeps incrementing.
    let ticks = Arc::new(AtomicU64::new(0));
    let ticks_for_task = Arc::clone(&ticks);
    let ticker = tokio::spawn(async move {
        let mut iv = tokio::time::interval(Duration::from_millis(5));
        loop {
            iv.tick().await;
            ticks_for_task.fetch_add(1, Ordering::Relaxed);
        }
    });

    // Sibling task that PANICS. The JoinHandle's await returns
    // an `Err(JoinError { is_panic: true })` when this fires
    // — tokio's task wrapper catches the unwind, marks the
    // task as panicked, but does NOT propagate to other tasks
    // OR to the runtime.
    let panicker = tokio::spawn(async {
        // Brief await so the ticker has time to start.
        tokio::time::sleep(Duration::from_millis(20)).await;
        panic!("deliberate test panic — must NOT tear down the runtime");
    });

    // Let the ticker accumulate, the panicker fire, then
    // give the ticker more time AFTER the panic to prove
    // it kept running.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify the panicker actually panicked.
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

    // CRITICAL: ticker must have ticked BOTH before AND
    // after the panic. If `panic = abort` were in effect the
    // process would have died at the panic point and the
    // test wouldn't have reached this assertion at all —
    // libtest would report "test panicked: signal 6 (SIGABRT)"
    // instead of running the assertion. So reaching here is
    // itself a partial proof, and the tick-count sanity-
    // checks the runtime stayed responsive.
    let final_ticks = ticks.load(Ordering::Relaxed);
    assert!(
        final_ticks >= 10,
        "ticker fired only {final_ticks} times in 100ms; runtime should have produced ~20 ticks. \
         If this is much less than expected, the runtime may be degraded after the sibling panic."
    );

    ticker.abort();
}

/// Sanity: an `await` chain that hits a sub-spawned panicked
/// task surfaces the panic AS the JoinError, not as a process
/// abort. This proves the post-iter-24 expected behavior of
/// proteus-server's accept loops: when a handshake task
/// panics, the accept-loop's per-task `tokio::spawn` catches
/// it and the loop's NEXT accept proceeds normally.
#[tokio::test]
async fn await_of_panicked_task_returns_join_error_not_abort() {
    let h = tokio::spawn(async {
        panic!("planned");
    });
    let r = h.await;
    assert!(r.is_err());
    assert!(r.unwrap_err().is_panic());
    // Process still alive — we can continue running tests.
}

/// Iter-34: read the workspace Cargo.toml and pin
/// `[profile.release] panic = "unwind"` literally. The
/// runtime-behavior tests above (iter-24) prove tokio task
/// isolation works UNDER the dev/test profile (which inherits
/// `panic = unwind` from the same workspace config); this test
/// pins the RELEASE PROFILE setting directly so a future
/// refactor flipping it back to "abort" fires immediately
/// without needing a separate release-mode test harness.
///
/// Both proteus-server and proteus-client inherit this setting
/// (verified by `nm target/release/proteus-{server,client} |
/// grep _Unwind_` in the iter-24/iter-34 commit messages).
/// Per-crate `[profile.release]` overrides are a separate
/// failure mode caught by the corresponding crate's
/// `panic_in_task_does_not_kill_runtime` test.
#[test]
fn workspace_release_profile_pins_panic_unwind() {
    use std::path::Path;
    let workspace_toml = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("Cargo.toml");
    let body = std::fs::read_to_string(&workspace_toml)
        .unwrap_or_else(|e| panic!("read {}: {e}", workspace_toml.display()));

    // Find the [profile.release] section and confirm it
    // contains `panic = "unwind"` (NOT `panic = "abort"`).
    let release_section = body
        .split("[profile.")
        .find(|s| s.starts_with("release]"))
        .expect("[profile.release] section must exist in workspace Cargo.toml");
    // Bound the search to the section (next [profile.* or EOF).
    let release_section = release_section
        .split_once("\n[profile.")
        .map(|(head, _)| head)
        .unwrap_or(release_section);
    assert!(
        release_section.contains(r#"panic = "unwind""#),
        "workspace Cargo.toml [profile.release] MUST set `panic = \"unwind\"` (iter-24 contract). \
         Section body:\n{release_section}"
    );
    assert!(
        !release_section.contains(r#"panic = "abort""#),
        "workspace Cargo.toml [profile.release] MUST NOT set `panic = \"abort\"` — that's the \
         pre-iter-24 silent-failure mode where any tokio task panic abort the whole process. \
         Section body:\n{release_section}"
    );
}
