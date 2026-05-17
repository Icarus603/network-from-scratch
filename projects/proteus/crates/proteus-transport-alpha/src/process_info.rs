//! Process-lifecycle metrics — start time, uptime, build version.
//!
//! Operators currently can't answer common deployment questions from
//! `/metrics` alone:
//!
//! - **"Is this the new binary I just deployed?"** No version metric
//!   ⇒ operator must `ssh` + `proteus-server --version` to verify.
//! - **"Did the process actually restart after my systemd unit
//!   edit?"** No start-time metric ⇒ operator infers from
//!   `journalctl` timestamps and hopes the clocks agree.
//! - **"How long has this been up?"** Implicit in start-time but
//!   exposing the uptime directly saves the PromQL author one
//!   subtraction.
//!
//! This module provides a small `ProcessInfo` snapshot type that
//! renders the standard three series:
//!
//! ```text
//! # HELP proteus_process_start_unix_seconds Process start time as Unix seconds.
//! # TYPE proteus_process_start_unix_seconds gauge
//! proteus_process_start_unix_seconds 1747526400
//! # HELP proteus_process_uptime_seconds Seconds since process start.
//! # TYPE proteus_process_uptime_seconds gauge
//! proteus_process_uptime_seconds 3725
//! # HELP proteus_build_info Build metadata (version + rustc target triple). Always 1.
//! # TYPE proteus_build_info gauge
//! proteus_build_info{version="0.1.0",rustc="1.85.0",target="aarch64-apple-darwin"} 1
//! ```
//!
//! Both server and client emit this block with the SAME metric names
//! (no `_server` / `_client` discriminator) — the discriminator lives
//! in the `target` label of `proteus_build_info` so a single
//! Prometheus instance scraping both sees them as distinct time
//! series by Prometheus's standard `instance` + `job` labels.
//!
//! The "always 1" gauge with label-carried metadata is the
//! Prometheus-canonical pattern for build-info exposure (same shape
//! as Go's `go_info`, Rust's `process_*` from the `metrics` crate's
//! defaults, etc.). Operators query
//! `proteus_build_info{version!="0.2.0"}` to find unupgraded
//! instances in a fleet.

use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Process-lifecycle snapshot. Cheap to clone (the `Arc<str>`s are
/// shared and the `Instant` / `i64` are Copy).
#[derive(Clone)]
pub struct ProcessInfo {
    /// Wall-clock start time, captured once at construction.
    /// Surfaced as `proteus_process_start_unix_seconds`. Falls back
    /// to 0 only if the system clock is somehow before the Unix
    /// epoch (impossible on a sane system; defense-in-depth so the
    /// metric is never garbage).
    start_unix_seconds: i64,
    /// Monotonic counterpart used to compute uptime. Insulated from
    /// wall-clock drift — `proteus_process_uptime_seconds` derives
    /// from `Instant::elapsed()`, not from
    /// `SystemTime::now() - start_unix_seconds`. An operator who
    /// `date -s` a stretch backwards still gets a non-decreasing
    /// uptime gauge.
    start_instant: Instant,
    /// `CARGO_PKG_VERSION` of the binary. The build script doesn't
    /// know which binary built it, so operators pass this explicitly.
    pub version: Arc<str>,
    /// Rust compiler version (e.g. `"1.85.0"`). Captured at compile
    /// time via the `rustc-version-runtime` env var pattern, or
    /// supplied by the operator if they don't want a build-script
    /// dependency. Empty string when unavailable.
    pub rustc: Arc<str>,
    /// Target triple (e.g. `"aarch64-apple-darwin"`). Same
    /// provenance as `rustc`. Used in `proteus_build_info` label so
    /// a single Prometheus can disambiguate a Linux fleet's server
    /// instances from a macOS developer's client without inspecting
    /// `instance` labels.
    pub target: Arc<str>,
}

impl ProcessInfo {
    /// Build with the supplied build metadata; capture start time
    /// from `SystemTime::now()` + `Instant::now()`.
    #[must_use]
    pub fn capture(version: &str, rustc: &str, target: &str) -> Self {
        let start_unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        Self {
            start_unix_seconds,
            start_instant: Instant::now(),
            version: Arc::from(version),
            rustc: Arc::from(rustc),
            target: Arc::from(target),
        }
    }

    /// Test/manual constructor — sets every field explicitly. Used
    /// by unit tests to assert against a known start_unix value.
    #[must_use]
    pub fn from_parts(
        start_unix_seconds: i64,
        start_instant: Instant,
        version: &str,
        rustc: &str,
        target: &str,
    ) -> Self {
        Self {
            start_unix_seconds,
            start_instant,
            version: Arc::from(version),
            rustc: Arc::from(rustc),
            target: Arc::from(target),
        }
    }

    /// Read the recorded start time as Unix seconds.
    #[must_use]
    pub fn start_unix_seconds(&self) -> i64 {
        self.start_unix_seconds
    }

    /// Current uptime in whole seconds, computed monotonically from
    /// the captured `start_instant`. Always non-decreasing.
    #[must_use]
    pub fn uptime_seconds(&self) -> u64 {
        self.start_instant.elapsed().as_secs()
    }

    /// Emit the three-metric Prometheus block under a custom
    /// `metric_prefix`. The server uses `"proteus"` (yielding
    /// `proteus_process_start_unix_seconds` etc.); the client uses
    /// `"proteus_client"` (yielding `proteus_client_process_*`)
    /// so a single Prometheus scraping both ends doesn't get
    /// label collisions.
    ///
    /// Same field rendering + escape rules as the unparameterized
    /// `prometheus()` — that method now forwards here with the
    /// `"proteus"` prefix for back-compat.
    #[must_use]
    pub fn prometheus_with_prefix(&self, metric_prefix: &str) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(512);
        let _ = writeln!(
            s,
            "# HELP {metric_prefix}_process_start_unix_seconds Process start time as Unix seconds."
        );
        let _ = writeln!(s, "# TYPE {metric_prefix}_process_start_unix_seconds gauge");
        let _ = writeln!(
            s,
            "{metric_prefix}_process_start_unix_seconds {}",
            self.start_unix_seconds
        );
        let _ = writeln!(
            s,
            "# HELP {metric_prefix}_process_uptime_seconds Seconds since process start (monotonic)."
        );
        let _ = writeln!(s, "# TYPE {metric_prefix}_process_uptime_seconds gauge");
        let _ = writeln!(
            s,
            "{metric_prefix}_process_uptime_seconds {}",
            self.uptime_seconds()
        );
        let _ = writeln!(
            s,
            "# HELP {metric_prefix}_build_info Build metadata (version + rustc + target). Always 1."
        );
        let _ = writeln!(s, "# TYPE {metric_prefix}_build_info gauge");
        let _ = writeln!(
            s,
            r#"{metric_prefix}_build_info{{version="{}",rustc="{}",target="{}"}} 1"#,
            escape_label(&self.version),
            escape_label(&self.rustc),
            escape_label(&self.target),
        );
        s
    }

    /// Emit the three-metric Prometheus block. Always emits all
    /// three families — even `proteus_build_info` when fields are
    /// empty (label values become `""`, valid per Prometheus 0.0.4).
    /// Equivalent to `prometheus_with_prefix("proteus")` — kept for
    /// the existing server-side call site without forcing a churn.
    #[must_use]
    pub fn prometheus(&self) -> String {
        self.prometheus_with_prefix("proteus")
    }
}

impl std::fmt::Debug for ProcessInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProcessInfo")
            .field("start_unix_seconds", &self.start_unix_seconds)
            .field("uptime_seconds", &self.uptime_seconds())
            .field("version", &self.version.as_ref())
            .field("rustc", &self.rustc.as_ref())
            .field("target", &self.target.as_ref())
            .finish()
    }
}

/// Prometheus 0.0.4 label-value escape: `\` → `\\`, `"` → `\"`,
/// `\n` → `\n` (literal two chars). Identical to the helper in
/// `proteus-client/src/admin.rs::escape_label`; duplicated here so
/// the server doesn't have to depend on a client-side module.
fn escape_label(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '\\' => out.push_str(r"\\"),
            '"' => out.push_str(r#"\""#),
            '\n' => out.push_str(r"\n"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn sample() -> ProcessInfo {
        ProcessInfo::from_parts(
            1_747_526_400,
            Instant::now(),
            "0.1.0",
            "1.85.0",
            "aarch64-apple-darwin",
        )
    }

    #[test]
    fn capture_sets_start_unix_to_a_recent_timestamp() {
        let p = ProcessInfo::capture("0.1.0", "1.85.0", "x86_64-unknown-linux-gnu");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        // capture and now() must agree to within a second.
        assert!(
            (p.start_unix_seconds() - now).abs() <= 1,
            "start_unix={} vs now={}",
            p.start_unix_seconds(),
            now
        );
    }

    #[test]
    fn uptime_is_non_decreasing() {
        let p = sample();
        let a = p.uptime_seconds();
        std::thread::sleep(Duration::from_millis(50));
        let b = p.uptime_seconds();
        assert!(b >= a, "uptime regressed: {a} → {b}");
    }

    #[test]
    #[allow(non_snake_case)]
    fn prometheus_emits_three_families_with_correct_HELP_TYPE() {
        let p = sample();
        let s = p.prometheus();
        for name in [
            "proteus_process_start_unix_seconds",
            "proteus_process_uptime_seconds",
            "proteus_build_info",
        ] {
            assert!(
                s.contains(&format!("# HELP {name} ")),
                "missing HELP for {name}: {s}"
            );
            assert!(
                s.contains(&format!("# TYPE {name} gauge")),
                "missing TYPE for {name}: {s}"
            );
        }
    }

    #[test]
    fn prometheus_reflects_explicit_start_unix_seconds() {
        let p = sample();
        let s = p.prometheus();
        assert!(
            s.contains("proteus_process_start_unix_seconds 1747526400\n"),
            "{s}"
        );
    }

    #[test]
    fn prometheus_emits_build_info_with_all_labels() {
        let p = sample();
        let s = p.prometheus();
        assert!(
            s.contains(
                r#"proteus_build_info{version="0.1.0",rustc="1.85.0",target="aarch64-apple-darwin"} 1"#
            ),
            "{s}"
        );
    }

    #[test]
    fn prometheus_build_info_with_empty_fields_emits_empty_labels() {
        let p = ProcessInfo::from_parts(0, Instant::now(), "", "", "");
        let s = p.prometheus();
        assert!(
            s.contains(r#"proteus_build_info{version="",rustc="",target=""} 1"#),
            "{s}"
        );
    }

    #[test]
    fn prometheus_escapes_quotes_and_backslashes_in_labels() {
        let p = ProcessInfo::from_parts(0, Instant::now(), r#"weird"v"#, r"win\os", "x");
        let s = p.prometheus();
        // The two escapes must appear in the labels.
        assert!(s.contains(r#"version="weird\"v""#), "{s}");
        assert!(s.contains(r#"rustc="win\\os""#), "{s}");
    }

    /// `prometheus_with_prefix("proteus_client")` yields series
    /// under the client prefix — the path the client admin uses to
    /// avoid label collisions with the server scrape.
    #[test]
    fn prometheus_with_prefix_renders_under_custom_prefix() {
        let p = sample();
        let s = p.prometheus_with_prefix("proteus_client");
        assert!(
            s.contains("proteus_client_process_start_unix_seconds 1747526400"),
            "{s}"
        );
        assert!(s.contains("proteus_client_process_uptime_seconds "), "{s}");
        assert!(s.contains("proteus_client_build_info{"), "{s}");
        // Must NOT leak the default "proteus_" prefix.
        assert!(
            !s.contains("\nproteus_process_start_unix_seconds"),
            "should not double-emit under default prefix: {s}"
        );
    }

    /// Default `prometheus()` is exactly equivalent to
    /// `prometheus_with_prefix("proteus")`. Guarantees no
    /// behavioral drift between the two emission paths.
    #[test]
    fn prometheus_default_equals_prefix_proteus() {
        // Two snapshots constructed with the same start_unix; uptime
        // computed at different micro-instants in the test will
        // differ by at most 1s, so we compare HEAD lines.
        let a = ProcessInfo::from_parts(123, Instant::now(), "v", "r", "t");
        let s1 = a.prometheus();
        let s2 = a.prometheus_with_prefix("proteus");
        // Strip the uptime line from each (its value can race
        // between the two calls).
        let strip_uptime = |s: &str| -> String {
            s.lines()
                .filter(|l| !l.starts_with("proteus_process_uptime_seconds "))
                .collect::<Vec<_>>()
                .join("\n")
        };
        assert_eq!(strip_uptime(&s1), strip_uptime(&s2));
    }

    #[test]
    fn debug_impl_does_not_panic_and_contains_version() {
        let p = sample();
        let d = format!("{p:?}");
        assert!(d.contains("0.1.0"));
        assert!(d.contains("aarch64-apple-darwin"));
    }
}
