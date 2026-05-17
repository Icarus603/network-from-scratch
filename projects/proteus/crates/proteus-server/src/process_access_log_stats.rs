//! Process-global handle to the
//! [`proteus_transport_alpha::access_log::AccessLoggerStats`].
//!
//! ## Why a global
//!
//! The /metrics live_blocks vec is built BEFORE the access-log
//! task spawns (the metrics endpoint must bind before the rest of
//! the deployment surface comes up). Plumbing the stats Arc
//! through every intermediate constructor would be noisy; a
//! single OnceLock keeps the wiring at the two call sites that
//! actually need it (the access-log spawn + the metrics render
//! closure).
//!
//! Same pattern as `process_panic_counter`:
//!   * `OnceLock::set()` is one-shot — re-entry of main() (theory-
//!     possible in tests) doesn't silently swap mid-run.
//!   * `OnceLock::get()` is lock-free — zero cost on the metrics
//!     scrape path.
//!   * `prometheus()` returns the empty string when unset, so the
//!     /metrics body gains no spurious lines for operators who
//!     haven't configured `access_log:`.

use std::sync::Arc;
use std::sync::OnceLock;

use proteus_transport_alpha::access_log::AccessLoggerStats;

static GLOBAL: OnceLock<Arc<AccessLoggerStats>> = OnceLock::new();

/// Publish the process-wide access-log stats. Called once from
/// `main()` after the AccessLogger has been spawned. Subsequent
/// calls are no-ops (logged at `warn` so tests notice
/// accidental re-installs).
pub fn set(stats: Arc<AccessLoggerStats>) {
    if GLOBAL.set(stats).is_err() {
        tracing::warn!(
            target: "proteus_server::process_access_log_stats",
            "access-log stats already set — ignoring second install"
        );
    }
}

/// Render the Prometheus block. Returns the empty string when
/// the stats haven't been set (operator didn't configure
/// `access_log:`) so the /metrics body stays clean.
#[must_use]
pub fn prometheus() -> String {
    match GLOBAL.get() {
        Some(stats) => stats.prometheus(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prometheus_is_empty_when_unset() {
        // The global is shared across tests in the same binary;
        // we just assert that IF unset, prometheus is empty.
        // (The set→prometheus round-trip is covered by the
        // integration tests in proteus-server/tests.)
        if GLOBAL.get().is_none() {
            assert!(prometheus().is_empty());
        }
    }
}
