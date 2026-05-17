//! Process-global handle to the [`proteus_panic_hook::PanicCounter`]
//! for the client binary.
//!
//! Symmetric with `proteus-server::process_panic_counter` — same
//! `set` / `get_count` / `prometheus` surface. The client's admin
//! `/metrics` endpoint embeds the `proteus_panics_total` series
//! produced here so dashboards using a single Prometheus instance
//! can scrape BOTH ends and alert on
//! `rate(proteus_panics_total{job=~"proteus-.*"}[5m]) > 0`.
//!
//! Same `OnceLock` semantics as the server side: one-time-set,
//! lock-free read, zero-cost when unset (returns `0`).

use std::sync::Arc;
use std::sync::OnceLock;

use proteus_panic_hook::PanicCounter;

static GLOBAL_PANIC_COUNTER: OnceLock<Arc<PanicCounter>> = OnceLock::new();

/// Publish the process-wide panic counter. Called once from
/// `main()`. Subsequent calls are no-ops.
pub fn set(counter: Arc<PanicCounter>) {
    if GLOBAL_PANIC_COUNTER.set(counter).is_err() {
        tracing::warn!(
            target: "proteus_client::process_panic_counter",
            "panic counter already set — ignoring second install"
        );
    }
}

/// Read the global counter. Returns 0 when unset so /metrics always
/// emits a deterministic baseline.
#[must_use]
pub fn get_count() -> u64 {
    GLOBAL_PANIC_COUNTER.get().map(|c| c.get()).unwrap_or(0)
}

/// Render the Prometheus exposition block. Series name is
/// `proteus_panics_total` (same as server side) — operators
/// distinguish the source by Prometheus job label, not by metric
/// name.
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
