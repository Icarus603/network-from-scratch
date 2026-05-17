//! Process-global handle to the [`proteus_panic_hook::PanicCounter`].
//!
//! ## Why a global
//!
//! The panic hook needs to be installed in `main()` BEFORE the
//! metrics struct is constructed (otherwise a panic during config
//! load isn't counted). The metrics struct on the other hand is
//! built deeper inside [`run`] after YAML parse. Threading the
//! `Arc<PanicCounter>` through every intermediate constructor is
//! noisy; a single `OnceLock` keeps the wiring at the two call
//! sites that actually need it (the hook install + the metrics
//! render).
//!
//! `OnceLock` (stable since 1.70) gives us:
//!   * one-time set: the second `set()` is a no-op, so a re-entry
//!     of `main()` (which doesn't happen in practice but is theory-
//!     possible in tests) doesn't silently swap the counter
//!     mid-run;
//!   * lock-free `get()`: zero-cost on the hot path the metrics
//!     handler calls every scrape.
//!
//! Tests that need an isolated counter construct one directly via
//! `proteus_panic_hook::PanicCounter::new()` and skip this module;
//! the global is only used by the binary entry point.

use std::sync::Arc;
use std::sync::OnceLock;

use proteus_panic_hook::PanicCounter;

static GLOBAL_PANIC_COUNTER: OnceLock<Arc<PanicCounter>> = OnceLock::new();

/// Publish the process-wide panic counter. Called once from
/// `main()` after [`proteus_panic_hook::install`]. Subsequent
/// calls are no-ops (logged at `warn` so tests notice if they
/// accidentally try to swap a live counter).
pub fn set(counter: Arc<PanicCounter>) {
    if GLOBAL_PANIC_COUNTER.set(counter).is_err() {
        // OnceLock::set returns Err with the input back; we
        // discard it. Already-set means main() ran twice — the
        // metrics layer keeps reading the first counter.
        tracing::warn!(
            target: "proteus_server::process_panic_counter",
            "panic counter already set — ignoring second install"
        );
    }
}

/// Read the global counter as cumulative `u64`. Returns 0 when
/// the hook hasn't been installed (e.g. unit tests that don't
/// run `main()`). This means the gauge is **always present** on
/// /metrics scrapes — operators alerting on `rate(... > 0)` get
/// a deterministic baseline.
#[must_use]
pub fn get_count() -> u64 {
    GLOBAL_PANIC_COUNTER.get().map(|c| c.get()).unwrap_or(0)
}

/// Render the Prometheus exposition block for the panic counter.
/// Stable name: `proteus_panics_total`. Append-only (no labels
/// today, room to add `thread="..."` later if useful).
#[must_use]
pub fn prometheus() -> String {
    format!(
        "# HELP proteus_panics_total Cumulative process-wide panic count since binary start. \
         Captured by proteus-panic-hook before tokio absorbs spawned-task panics. Alert on \
         rate(proteus_panics_total[5m]) > 0.\n\
         # TYPE proteus_panics_total counter\n\
         proteus_panics_total {n}\n",
        n = get_count()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_count_is_zero_when_unset() {
        // We can't easily test the post-set path without polluting
        // the OnceLock for sibling tests in the same binary.
        // Coverage of the set→get round-trip lives in
        // proteus-panic-hook's own tests + an integration test
        // that spawns the binary.
        // This test just confirms the unset baseline is 0.
        if GLOBAL_PANIC_COUNTER.get().is_none() {
            assert_eq!(get_count(), 0);
        }
    }

    #[test]
    fn prometheus_block_contains_canonical_metric_name() {
        let body = prometheus();
        assert!(body.contains("proteus_panics_total"));
        assert!(body.contains("# TYPE proteus_panics_total counter"));
    }
}
