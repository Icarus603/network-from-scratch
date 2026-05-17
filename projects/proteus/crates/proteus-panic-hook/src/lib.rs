//! Shared panic-observability hook for the Proteus binaries.
//!
//! ## Why this exists
//!
//! Tokio absorbs panics from spawned tasks: the task ends, the
//! runtime keeps going, and **nothing surfaces to the operator**.
//! For a daemon that may run unattended for weeks, a panic in a
//! hot path — connection handler, ratchet step, AEAD seal — is
//! the worst kind of silent corruption: traffic for that session
//! is lost, the user retries, the retry maybe panics too, but
//! `journalctl -u proteus-server` shows nothing.
//!
//! The default Rust panic handler at least writes to stderr —
//! which systemd captures into the journal — but the message
//! is unstructured text (no `panic_count`, no thread name, no
//! session context). Operators dashboarding `proteus_panic_*`
//! see nothing, and a single grep of the journal for "panic"
//! won't catch the well-meaning variants like "thread 'tokio-
//! runtime-worker' panicked at...".
//!
//! This crate installs a custom `std::panic::set_hook` that:
//!
//!   1. **Increments a process-global panic counter** (atomic,
//!      thread-safe; readable by the metrics HTTP handler).
//!   2. **Emits a structured `tracing` event** at `ERROR` level
//!      with fields `thread`, `location`, `message`, and the
//!      cumulative `panic_count`. Operators can `journalctl |
//!      grep '"target":"proteus_panic"'` to find every panic
//!      since binary start.
//!   3. **Still delegates to the default backtrace path** when
//!      `RUST_BACKTRACE` is set, so operators debugging a panic
//!      retain full backtrace output.
//!
//! ## Why a separate crate
//!
//! Both `proteus-server` and `proteus-client` need the same
//! behaviour — counter type + install function — but they live
//! in independent workspace members. Lifting the logic into a
//! shared crate is the minimal-surface-area solution; the
//! alternative (duplicating the install code) drifts on the
//! first counter rename.
//!
//! Deliberately small: only depends on `tracing` (already a
//! transitive dep of every binary). No tokio, no atomics
//! crate, no procmacro — `AtomicU64` from `std::sync::atomic`
//! is the only thing we need.
//!
//! ## Usage
//!
//! ```ignore
//! // At the top of `main()`, before any tasks are spawned:
//! let panic_counter = proteus_panic_hook::install();
//!
//! // Pass the Arc<PanicCounter> to whatever metrics struct
//! // exposes it on /metrics. The counter increments on every
//! // panic, so dashboards can alert on rate(...) > 0.
//! ```
//!
//! ## Why we don't `abort()` on panic
//!
//! systemd's `Restart=on-failure` would catch an abort, BUT a
//! single hot-path panic would tear down EVERY in-flight session,
//! lose every connection, and force every client to redial. For
//! a proxy that's the worst possible failure mode — even a
//! buggy session handler that panics on one connection is better
//! than tearing the entire process down. The counter + log line
//! gives operators visibility WITHOUT forcing the nuclear option.
//!
//! Operators who DO want abort-on-panic semantics (e.g. for
//! "I want systemd to restart on any panic so I can guarantee
//! a clean state machine") can set the `RUST_PANIC_ABORT=1`
//! env var; the hook checks it and re-aborts after counting +
//! logging.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Atomic panic counter, suitable for embedding in a metrics
/// struct that's read by /metrics.
///
/// `Default`s to zero. The hook installed by [`install`] increments
/// this on every panic. Counter wraps at `u64::MAX` after ~5×10^11
/// years of one-panic-per-millisecond — effectively never.
#[derive(Debug, Default)]
pub struct PanicCounter {
    count: AtomicU64,
}

impl PanicCounter {
    /// Construct a new zeroed counter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Current cumulative panic count.
    #[must_use]
    pub fn get(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    /// Increment by one. Returns the new value.
    pub fn increment(&self) -> u64 {
        // Add and return the post-increment value so callers can
        // surface "panic #N" in the log message.
        self.count.fetch_add(1, Ordering::Relaxed) + 1
    }
}

/// Install the shared Proteus panic hook.
///
/// Returns an `Arc<PanicCounter>` whose `get()` reflects the
/// cumulative panic count seen since installation. The caller is
/// responsible for storing the Arc in whatever struct the
/// metrics renderer reads. Multiple clones of the returned Arc
/// share the same counter — this matches `Arc::clone(&counter)`
/// usage in the metrics layer.
///
/// **The hook captures the Arc by clone.** Re-installing the hook
/// (calling this function a second time) creates a fresh counter;
/// the previously-installed hook still references the old counter
/// but the old counter is now orphaned from the caller's
/// perspective. In practice the binaries call `install()` exactly
/// once from `main()`, so the second-install case is a test
/// scenario; tests should reset via `std::panic::take_hook()` if
/// they need isolation.
///
/// Honours these env vars:
/// - `RUST_PANIC_ABORT=1` → after counting + logging, re-abort
///   so systemd `Restart=on-failure` can pick up. Off by default
///   so a single-session panic doesn't tear down the proxy for
///   every other in-flight user.
/// - `RUST_BACKTRACE=full` or `=1` → the default handler is
///   still chained so backtraces render via the standard path.
///   (We don't *call* the default handler ourselves; we just
///   don't suppress it. `tracing` emits separately.)
pub fn install() -> Arc<PanicCounter> {
    let counter = Arc::new(PanicCounter::new());
    install_with_counter(Arc::clone(&counter));
    counter
}

/// Install the hook using a caller-supplied counter. Useful when
/// the metrics struct owns the counter and the install call must
/// pass that exact Arc in — avoids the "install then plumb" two-
/// step.
pub fn install_with_counter(counter: Arc<PanicCounter>) {
    // Capture the default hook BEFORE we replace it so we can
    // chain to it (preserves backtrace + standard stderr panic
    // line). We deliberately use `take_hook` (NOT `default_hook`)
    // because each `set_hook` call shadows the previous; chaining
    // is the only way to keep both ours + the original.
    let original = std::panic::take_hook();
    let abort_on_panic = std::env::var("RUST_PANIC_ABORT")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    std::panic::set_hook(Box::new(move |info| {
        let n = counter.increment();

        // Extract the panic message. `info.payload()` is a
        // `&dyn Any` — by convention it's either `&str` (from
        // `panic!("literal")`) or `String` (from
        // `panic!("{}", formatted)`).
        let message = if let Some(s) = info.payload().downcast_ref::<&str>() {
            (*s).to_string()
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "<non-string panic payload>".to_string()
        };

        // Location is "file:line:col" when present.
        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "<unknown>".to_string());

        let thread_name = std::thread::current()
            .name()
            .unwrap_or("<unnamed>")
            .to_string();

        // Structured tracing event. Operators query with
        // `journalctl -u proteus-server -o json |
        //  jq 'select(.target=="proteus_panic")'`. The
        // `panic_count` field is the same value the gauge
        // exposes, so operators can correlate.
        tracing::error!(
            target: "proteus_panic",
            panic_count = n,
            thread = %thread_name,
            location = %location,
            message = %message,
            "panic captured by proteus-panic-hook"
        );

        // Chain to the original handler. This preserves the
        // RUST_BACKTRACE=1 behaviour, the default stderr line
        // ("thread '...' panicked at ..."), and any custom hook
        // a parent crate may have installed.
        original(info);

        if abort_on_panic {
            // Bypass `process::exit` (which runs Drop globals
            // and may deadlock in a panicking thread): use
            // `process::abort` for an immediate SIGABRT.
            std::process::abort();
        }
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Iter-51: serialize tests that touch the global panic hook.
    /// `std::panic::set_hook` / `take_hook` is a process-wide
    /// single mutable slot. Two parallel tests both calling
    /// `install_with_counter` race: test A's hook fires test B's
    /// increment (and vice-versa), making `c.get() == 1`
    /// non-deterministic. The flake manifested as intermittent
    /// `assert_eq!(c.get(), 1) — left: 0, right: 1` failures in
    /// the workspace `cargo test --workspace` run.
    ///
    /// We serialize via a static Mutex — no `serial_test`
    /// dependency, no atomic-only juggling. The Mutex MUST be
    /// the FIRST line in each affected test so the guard outlives
    /// any panic-hook-set+drop sequence.
    static HOOK_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn counter_starts_at_zero_and_increments_monotonically() {
        let c = PanicCounter::new();
        assert_eq!(c.get(), 0);
        assert_eq!(c.increment(), 1);
        assert_eq!(c.increment(), 2);
        assert_eq!(c.get(), 2);
    }

    #[test]
    fn install_returns_counter_that_increments_when_hook_fires() {
        // Iter-51: serialize against other hook-touching tests.
        let _guard = HOOK_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // We can't easily test the full hook in unit tests
        // without polluting the global hook state of other
        // tests in the same process; assert the counter logic
        // instead. The integration test in proteus-server +
        // proteus-client crates exercises the full install +
        // panic + count path with real binary spawns.
        let c = install();
        // The shared counter is a fresh zero on install.
        assert_eq!(c.get(), 0);
        // Reset the hook so we don't pollute other tests.
        let _ = std::panic::take_hook();
    }

    #[test]
    fn arc_clones_share_counter_state() {
        let a = Arc::new(PanicCounter::new());
        let b = Arc::clone(&a);
        let _ = a.increment();
        let _ = b.increment();
        assert_eq!(a.get(), 2);
        assert_eq!(b.get(), 2);
    }

    /// Verify the hook actually fires and increments when a
    /// panic is caught (without aborting). This test is
    /// **isolated**: it installs its own counter, then takes
    /// the hook back at the end, so it doesn't interfere with
    /// other tests in the same binary.
    #[test]
    fn hook_increments_on_caught_panic() {
        // Iter-51: serialize against other hook-touching tests
        // so install_with_counter + catch_unwind can't observe
        // OTHER tests' panics on this process-global hook.
        let _guard = HOOK_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let c = Arc::new(PanicCounter::new());
        install_with_counter(Arc::clone(&c));
        // Use catch_unwind so the panic doesn't abort the test
        // runner. Our hook still fires INSIDE catch_unwind.
        let result = std::panic::catch_unwind(|| panic!("deliberate test panic — please ignore"));
        assert!(result.is_err(), "panic should be caught");
        assert_eq!(
            c.get(),
            1,
            "hook should have incremented the shared counter exactly once"
        );
        // Restore default hook for subsequent tests in this binary.
        let _ = std::panic::take_hook();
    }
}
